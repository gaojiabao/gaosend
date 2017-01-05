#include    <time.h>
#include    <stdio.h> 
#include    <stdlib.h>
#include    <fcntl.h>
#include    <unistd.h>
#include    <string.h>
#include    <sys/time.h>
#include    "auth.h"
#include    "packet.h"
#include    "default.h"
#include    "common.h"
#include    "structure.h"
#include    "statistic.h"
#include    "runlog.h"
#include    "socket.h"
#include    "storage.h"

extern _pcaphdr* pPcapHdr;
extern _pkthdr*  pPktHdr;
extern _machdr*  pMacHdr;
extern _vlanhdr* pVlanHdr1;
extern _vlanhdr* pVlanHdr2;
extern _arphdr*  pArpHdr;
extern _ip4hdr*  pIp4Hdr;
extern _udphdr*  pUdpHdr;
extern _tcphdr*  pTcpHdr;
extern _ip6hdr*  pIp6Hdr;

char  cPacketBuf[PACKETLEN];

void PktStrucInit(int iVlanCount)
{
    pPcapHdr = (_pcaphdr*) cPacketBuf;
    pPktHdr = (_pkthdr*) cPacketBuf;
    pMacHdr = (_machdr *) (cPacketBuf + MACOFFSET);
    pVlanHdr1 = (_vlanhdr *)(cPacketBuf + VLAN1OFFSET);
    pVlanHdr2 = (_vlanhdr *)(cPacketBuf + VLAN2OFFSET);
    pArpHdr = (_arphdr *) (cPacketBuf + ARPOFFSET(iVlanCount));
    pIp4Hdr = (_ip4hdr *) (cPacketBuf + IP4OFFSET(iVlanCount));
    pUdpHdr = (_udphdr *) (cPacketBuf + UDPOFFSET(iVlanCount));
    pTcpHdr = (_tcphdr *) (cPacketBuf + TCPOFFSET(iVlanCount));
    pIp6Hdr = (_ip6hdr *) (cPacketBuf + IP4OFFSET(iVlanCount));
}

void StatisticUpperUdp(int iIpVersion)
{
    if (htons(pUdpHdr->sport) == 53 || htons(pUdpHdr->dport) == 53) {
        RecordStatisticsInfo(iIpVersion ? EMPRO_DNS : EMPRO_DNS);
    }
}

void StatisticUpperTcp(int iIpVersion)
{
    // iIpVersion v4:1 v6:0
    if (htons(pTcpHdr->dport) == 25) {
        RecordStatisticsInfo(iIpVersion ? EMPRO_SMTP : EMPRO_SMTP);
    } else if (htons(pTcpHdr->sport) == 80 || htons(pTcpHdr->dport) == 80 
            || htons(pTcpHdr->sport) == 8080 || htons(pTcpHdr->dport) == 8080) {
        RecordStatisticsInfo(iIpVersion ? EMPRO_HTTP : EMPRO_FTP);
    } else if (htons(pTcpHdr->dport) == 110) {
        RecordStatisticsInfo(iIpVersion ? EMPRO_POP3 : EMPRO_POP3);
    } else if (htons(pTcpHdr->sport) == 143 || htons(pTcpHdr->dport) == 143) {
        RecordStatisticsInfo(iIpVersion ? EMPRO_IMAP : EMPRO_IMAP);
    } else if (htons(pTcpHdr->sport) == 139 || htons(pTcpHdr->dport) == 139 
            || htons(pTcpHdr->sport) == 445 || htons(pTcpHdr->dport) == 445) {
        RecordStatisticsInfo(iIpVersion ? EMPRO_SMB : EMPRO_SMB);
    } else if (htons(pTcpHdr->sport) == 20 || htons(pTcpHdr->dport) == 20 
            || htons(pTcpHdr->sport) == 21 || htons(pTcpHdr->dport) == 21) {
        RecordStatisticsInfo(iIpVersion ? EMPRO_FTP : EMPRO_FTP);
    }
}

void AnalysePacket()
{
    int iFd;
    int iVlanCount = GetiValue("vlannum");
    char* pFileName = GetcValue("readfile");

    LOGRECORD(DEBUG, "Analyse cPacketBuf start...");

    PktStrucInit(iVlanCount);
    memset(cPacketBuf, 0, sizeof(cPacketBuf));

    // turn on flow assoition
    if(GetiValue("flow") == 1) {
        CreateStreamStorage();
    }

    if ((iFd = open(pFileName, O_RDWR)) < 0) {
        LOGRECORD(ERROR, "open pcap file error");
    }
    if (read(iFd, cPacketBuf, PCAPHDRLEN) < 0) {
        LOGRECORD(ERROR, "read pcaphdr error");
    }
    if (htonl(pPcapHdr->magic) != 0xd4c3b2a1) {
        LOGRECORD(ERROR, "fileName paratarn error");
    }

    while(read(iFd, cPacketBuf, PKTHDRLEN) > 1) {
        if (read(iFd, cPacketBuf+PKTHDRLEN, pPktHdr->len) < 0) {
            LOGRECORD(ERROR, "read packethdr error");
            exit(0);
        }
        RefreshParameter();

        if (htons(pMacHdr->pro2) == VLAN) {
            RecordStatisticsInfo(EMPRO_VLAN);
            PktStrucInit(1);
            if (htons(pVlanHdr1->type) == VLAN) {
                RecordStatisticsInfo(EMPRO_QinQ);
                PktStrucInit(2);
            }
        }

        if (htons(pMacHdr->pro2) == ARP) {
            RecordStatisticsInfo(EMPRO_ARP);
        } else if (htons(pMacHdr->pro2) == IPv4 || htons(pVlanHdr1->type) == IPv4 \
                || htons(pVlanHdr2->type) == IPv4) { // Layer 3
            RecordStatisticsInfo(EMPRO_IPv4);
            if (pIp4Hdr->protocol == UDP) { // Layer 4
                RecordStatisticsInfo(EMPRO_UDP);
                StatisticUpperUdp(V4);
            } else if (pIp4Hdr->protocol == TCP) { // Layer 4
                // TCP stream check
                char iFiveTupleSum[32];
                sprintf(iFiveTupleSum, "%d", pIp4Hdr->srcip + pIp4Hdr->dstip
                    + pTcpHdr->sport + pTcpHdr->dport + pIp4Hdr->protocol);
                if(GetiValue("flow") == 1) {
                    StoreStreamInfo(MD5Digest(iFiveTupleSum));
                }

                RecordStatisticsInfo(EMPRO_TCP);
                StatisticUpperTcp(V4);
            } else if (pIp4Hdr->protocol == ICMPv4) { // Layer 4
                RecordStatisticsInfo(EMPRO_ICMPv4);
            } else {
                RecordStatisticsInfo(EMPRO_L4OTHER);
            }
        } else if (htons(pMacHdr->pro2) == IPv6 || htons(pVlanHdr1->type) == IPv6 \
                || htons(pVlanHdr2->type) == IPv6) { // Layer 3
            RecordStatisticsInfo(EMPRO_IPv6);
            if (pIp6Hdr->protocol == ICMPv6) { // Layer 4
                RecordStatisticsInfo(EMPRO_ICMPv6);
            } else if (pIp6Hdr->protocol == TCP) { // Layer 4
                RecordStatisticsInfo(EMPRO_TCP6);
            } else if (pIp6Hdr->protocol == UDP) { // Layer 4
                RecordStatisticsInfo(EMPRO_UDP6);
            } else {
                RecordStatisticsInfo(EMPRO_L4OTHER6);
            }
        } else {
            //DisplayPacketData(cPacketBuf, sizeof(cPacketBuf) );
            RecordStatisticsInfo(EMPRO_L3OTHER);
        }
    }// end of while

    close(iFd);
    DisplayStatisticsResults();
    if(GetiValue("flow") == 1) {
        DisplayAllStreamMD5();
    }
    LOGRECORD(DEBUG, "Analyse cPacketBuf finished...");
}
    
