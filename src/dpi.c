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

/* packet structure */
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
static char cPcapHdrBuf[PCAPHDRLEN];
static char cPktHdrBuf[PKTHDRLEN];

void ExtractMessage(char*, int );
void PacketProcessing();

/* pcap file header parsing */
char* PcapHdrInspection()
{
    pPcapHdr = (_pcaphdr*) cPcapHdrBuf;
    
    if (read(iFdRead, cPcapHdrBuf, sizeof(cPcapHdrBuf)) < 0) {
        LOGRECORD(ERROR, "Pcap header read failed");
    }

    if (htonl(pPcapHdr->magic) != 0xd4c3b2a1) {
        LOGRECORD(ERROR, "File format not supported");
    }
    //ExtractMessage(cPcapHdrBuf, PCAPHDRLEN);
    return cPcapHdrBuf;
}

/* message header information analysis */
int PktHdrInspection()
{
    pPktHdr = (_pkthdr*) cPktHdrBuf;
    if (read(iFdRead, cPktHdrBuf, sizeof(cPktHdrBuf)) < 1) {
        LOGRECORD(DEBUG, "Packet Inspection finished");
        return -1;
    }

    return pPktHdr->len;
}

/* layer four protocol analysis */
void L4HdrInspection(U8 pro)
{
    char * pL4Hdr =  cPacketBuf + iCursor;

    if (pro == TCP) {
        iCursor += TCPHDRLEN;
        pTcpHdr = (_tcphdr *) pL4Hdr;
        // TCP stream check
        if(GetiValue("flow") == 1) {
            char iFiveTupleSum[32];
            sprintf(iFiveTupleSum, "%d", pIp4Hdr->srcip + pIp4Hdr->dstip
                + pTcpHdr->sport + pTcpHdr->dport + pIp4Hdr->protocol);
            StoreStreamInfo(MD5Digest(iFiveTupleSum));
        }
        //PacketProcessing();

        RecordStatisticsInfo(EMPRO_TCP);
        StatisticUpperTcp(htons(pTcpHdr->sport), htons(pTcpHdr->dport));
    } else if (pro == UDP) {
        iCursor += UDPHDRLEN;
        pUdpHdr = (_udphdr *) pL4Hdr;
        RecordStatisticsInfo(EMPRO_UDP);
        StatisticUpperUdp(htons(pUdpHdr->sport), htons(pUdpHdr->dport));  
    } else if (pro == ICMPv4) {
        pIcmpHdr = (_icmphdr *) pL4Hdr;
        RecordStatisticsInfo(EMPRO_ICMPv4);
    } else if (pro == ICMPv6) {
        pIcmpHdr = (_icmphdr *) pL4Hdr;
    } else {
        RecordStatisticsInfo(EMPRO_L4OTHER);
    }
}

/* layer three protocol analysis */
U8 L3HdrInspection(U16 pro)
{
    U8 iPro = 0;
    char * pL3Hdr =  cPacketBuf + iCursor;

    if (pro == IPv4) {
        iCursor += IP4HDRLEN;
        pIp4Hdr = (_ip4hdr *) pL3Hdr;
        iPro = pIp4Hdr->protocol;
        RecordStatisticsInfo(EMPRO_IPv4);
        L4HdrInspection(iPro);
    } else if (pro == VLAN) {
        iCursor += VLANLEN;
        pVlanHdr = (_vlanhdr *) pL3Hdr;
        iPro = L3HdrInspection(htons(pVlanHdr->type));
        RecordStatisticsInfo(EMPRO_VLAN);
        if (iPro == VLAN) {
            RecordStatisticsInfo(EMPRO_QinQ);
        }
    } else if (pro == ARP) {
        pArpHdr = (_arphdr *) pL3Hdr;
        RecordStatisticsInfo(EMPRO_ARP);
    } else if (pro == IPv6) {
        iCursor += IP6HDRLEN;
        pIp6Hdr = (_ip6hdr *) pL3Hdr;
        iPro = pIp6Hdr->protocol;
        RecordStatisticsInfo(EMPRO_IPv6);
        L4HdrInspection(iPro);
    } else {
        RecordStatisticsInfo(EMPRO_L3OTHER);
    }

    return iPro;
}

/* layer two protocol analysis */
void L2HdrInspection()
{
    pMacHdr = (_machdr *) (cPacketBuf + iCursor);
    iCursor += MACHDRLEN;
    L3HdrInspection(htons(pMacHdr->pro2));
}

/* data content resolution portal */
void PacketPrase()
{
    L2HdrInspection();
    if (GetcValue("savefile") != NULL) {
        PacketProcessing();
    }
}

/* extracting data message */
void PacketProcessing()
{
    static int iNum = 1;
    if (iNum == 1) {
        ExtractMessage(cPcapHdrBuf, PCAPHDRLEN);
        iNum++;
    }
    ExtractMessage(cPktHdrBuf, PKTHDRLEN);
    ExtractMessage(cPacketBuf, pPktHdr->len);
}

/* deep packet inspection portal */
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
        
        PacketPrase();
        iCursor = 0;
    } // end of while

    DisplayStatisticsResults();
    if(GetiValue("flow") == 1) {
        DisplayAllStreamMD5();
    }

    LOGRECORD(DEBUG, "Deep packet inspection finished...");

    close(iFdRead);
}

