#include    <time.h>
#include    <stdio.h> 
#include    <stdlib.h>
#include    <fcntl.h>
#include    <unistd.h>
#include    <string.h>
#include    <sys/time.h>
#include    "packet.h"
#include    "default.h"
#include    "common.h"
#include    "structure.h"
#include    "statistic.h"
#include    "runlog.h"
#include    "storage.h"
#include    "socket.h"
#include    "auth.h"

/* cPacketBuf structure */
static _pcaphdr*    pPcapHdr;
static _pkthdr*     pPktHdr;
static _machdr*     pMacHdr;
static _arphdr*     pArpHdr;
static _vlanhdr*    pVlanHdr;
static _ip4hdr*     pIp4Hdr;
static _ip6hdr*     pIp6Hdr;
static _udphdr*     pUdpHdr;
static _tcphdr*     pTcpHdr;
static _icmphdr*    pIcmpHdr;

static int  iFdRead = 0;
static int  iCursor = 0;
static char cPacketBuf[2000];

void PcapHdrInspection()
{
    char cPcapHdrBuf[PCAPHDRLEN];
    pPcapHdr = (_pcaphdr*) cPcapHdrBuf;
    
    if (read(iFdRead, cPcapHdrBuf, sizeof(cPcapHdrBuf)) < 0) {
        LOGRECORD(ERROR, "Pcap header read failed");
    }

    if (htonl(pPcapHdr->magic) != 0xd4c3b2a1) {
        LOGRECORD(ERROR, "File format not supported");
    }
}

int PktHdrInspection()
{
    char cPktHdrBuf[PKTHDRLEN];
    pPktHdr = (_pkthdr*) cPktHdrBuf;
    if (read(iFdRead, cPktHdrBuf, sizeof(cPktHdrBuf)) < 1) {
        LOGRECORD(DEBUG, "Packet Inspection finished");
        return -1;
    }

    return pPktHdr->len;
}

U16 L2HdrInspection()
{
    pMacHdr = (_machdr *) (cPacketBuf + iCursor);
    iCursor += MACHDRLEN;
    return htons(pMacHdr->pro2);
}

U8 L3HdrInspection(U16 pro)
{
    U8 iPro = 0;
    char * pL3Hdr =  cPacketBuf + iCursor;

    if (pro == IPv4) {
        iCursor += IP4HDRLEN;
        _ip4hdr* pIp4Hdr = (_ip4hdr *) pL3Hdr;
        iPro = pIp4Hdr->protocol;
        RecordStatisticsInfo(EMPRO_IPv4);
    } else if (pro == VLAN) {
        iCursor += VLANLEN;
        pVlanHdr = (_vlanhdr *) pL3Hdr;
        iPro = L3HdrInspection(htons(pVlanHdr->type));
        RecordStatisticsInfo(EMPRO_VLAN);
        if (iPro == VLAN) {
            RecordStatisticsInfo(EMPRO_QinQ);
        }
    } else if (pro == ARP) {
        //_arphdr* pArpHdr = (_arphdr *) pL3Hdr;
        RecordStatisticsInfo(EMPRO_ARP);
    } else if (pro == IPv6) {
        iCursor += IP6HDRLEN;
        _ip6hdr* pIp6Hdr = (_ip6hdr *) pL3Hdr;
        iPro = pIp6Hdr->protocol;
        RecordStatisticsInfo(EMPRO_IPv6);
    } else {
        RecordStatisticsInfo(EMPRO_L3OTHER);
    }

    return iPro;
}

void L4HdrInspection(U8 pro)
{
    char * pL4Hdr =  cPacketBuf + iCursor;

    if (pro == TCP) {
        iCursor += TCPHDRLEN;
        _tcphdr* pTcpHdr = (_tcphdr *) pL4Hdr;
        // TCP stream check
        if(GetiValue("flow") == 1) {
            char iFiveTupleSum[32];
            sprintf(iFiveTupleSum, "%d", pIp4Hdr->srcip + pIp4Hdr->dstip
            + pTcpHdr->sport + pTcpHdr->dport + pIp4Hdr->protocol);
            StoreStreamInfo(MD5Digest(iFiveTupleSum));
        }

        RecordStatisticsInfo(EMPRO_TCP);
        StatisticUpperTcp(htons(pTcpHdr->sport), htons(pTcpHdr->dport));
    } else if (pro == UDP) {
        iCursor += UDPHDRLEN;
        _udphdr* pUdpHdr = (_udphdr *) pL4Hdr;
        RecordStatisticsInfo(EMPRO_UDP);
        StatisticUpperUdp(htons(pUdpHdr->sport), htons(pUdpHdr->dport));  
    } else if (pro == ICMPv4) {
        //_icmphdr* pIcmpHdr = (_icmphdr *) pL4Hdr;
        RecordStatisticsInfo(EMPRO_ICMPv4);
    } else if (pro == ICMPv6) {
        //_icmphdr* pIcmpHdr = (_icmphdr *) pL4Hdr;
    } else {
        RecordStatisticsInfo(EMPRO_L4OTHER);
    }
}

void DeepPacketInspection()
{
    LOGRECORD(DEBUG, "Deep packet inspection start...");

    // turn on flow assoition
    if(GetiValue("flow") == 1) {
        CreateStreamStorage();
    }

    if ((iFdRead = open(GetcValue("readfile"), O_RDWR)) < 0) {
        LOGRECORD(ERROR, "Open %s file error", GetcValue("readfile"));
    }

    PcapHdrInspection();

    int iPktLen = 0;
    while ((iPktLen = PktHdrInspection()) > 0) {
        if (read(iFdRead, cPacketBuf, iPktLen) < 0) {
            LOGRECORD(ERROR, "read packethdr error");
        }
        U16 iL3Pro = L2HdrInspection();
        U32 iL4Pro = L3HdrInspection(iL3Pro);
        L4HdrInspection(iL4Pro);
        iCursor = 0;
    } // end of while

    DisplayStatisticsResults();

    LOGRECORD(DEBUG, "Deep packet inspection finished...");

    close(iFdRead);
}

