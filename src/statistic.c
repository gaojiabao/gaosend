/*******************************************************
 *
 *  Author        : Mr.Gao
 *  Email         : 729272771@qq.com
 *  Filename      : statistic.c
 *  Last modified : 2018-01-29 14:25
 *  Description   : Protocol data statistics
 *
 * *****************************************************/


#include    "func.h"
#include    "flow.h"
#include    "stdio.h"
#include    "common.h"
#include    "runlog.h"
#include    "storage.h"
#include    "statistic.h"

unsigned int iProTag;

/* Expressed as a percentage */
float PercentCalc(int iCount, int iSum)
{
    return ((iCount * 100.0) / iSum);
}

/* Get statistics output format */
char* GetFormat(int iLevel)
{
    char* pPattern = NULL;
    switch (iLevel) {
        case 0  :
            pPattern = "-----------------------[statistic]-----------------------";
            break;
        case 1  :
            pPattern = "---------------------------------------------------------";
            break;
        case 3  :
            pPattern = "    |---%-20s:    |---%d(%.2f%%)";
            break;
        case 4  :
            pPattern = "      |----%-17s:      |----%d(%.2f%%)";
            break;
        case 7  :
            pPattern = "        |-----%-14s:        |-----%d(%.2f%%)";
            break;
        case 9  :
            pPattern = "    %-24s: %lld";
            break;
        default :
            LOGRECORD(ERROR, "Get statistics output format failed");
            break;
    }

    return pPattern;
}

void DisplayStatisticsResults()
{    
    LOGRECORD(INFO, GetFormat(0));
    LOGRECORD(INFO, GetFormat(3), "VLAN", iPRO_VLAN[0], PercentCalc(iPRO_VLAN[0], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(4), "QinQ", iPRO_VLAN[1], PercentCalc(iPRO_VLAN[1], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(1));
    LOGRECORD(INFO, GetFormat(3), "ARP",  iPRO_ARP, PercentCalc(iPRO_ARP, iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(3), "IPv4", iPRO_IP[V4], PercentCalc(iPRO_IP[V4], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(4), "ICMP4", iPRO_ICMP[V4], PercentCalc(iPRO_ICMP[V4], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(4), "UDP", iPRO_UDP[V4], PercentCalc(iPRO_UDP[V4], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(7), "DNS", iPRO_DNS[V4], PercentCalc(iPRO_DNS[V4], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(4), "TCP", iPRO_TCP[V4], PercentCalc(iPRO_TCP[V4], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(7), "SMB", iPRO_SMB[V4], PercentCalc(iPRO_SMB[V4], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(7), "FTP", iPRO_FTP[V4], PercentCalc(iPRO_FTP[V4], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(7), "HTTP", iPRO_HTTP[V4], PercentCalc(iPRO_HTTP[V4], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(7), "SMTP", iPRO_SMTP[V4], PercentCalc(iPRO_SMTP[V4], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(7), "POP3", iPRO_POP3[V4], PercentCalc(iPRO_POP3[V4], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(7), "IMAP", iPRO_IMAP[V4], PercentCalc(iPRO_IMAP[V4], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(7), "Other", iPRO_L7OR[V4], PercentCalc(iPRO_L7OR[V4], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(4), "Other", iPRO_L4OR[V4], PercentCalc(iPRO_L4OR[V4], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(3), "IPv6", iPRO_IP[V6], PercentCalc(iPRO_IP[V6], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(4), "ICMP6", iPRO_ICMP[V6], PercentCalc(iPRO_ICMP[V6], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(4), "UDP", iPRO_UDP[V6], PercentCalc(iPRO_UDP[V6], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(7), "DNS", iPRO_DNS[V6], PercentCalc(iPRO_DNS[V6], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(4), "TCP", iPRO_TCP[V6], PercentCalc(iPRO_TCP[V6], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(7), "SMB", iPRO_SMB[V6], PercentCalc(iPRO_SMB[V6], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(7), "FTP", iPRO_FTP[V6], PercentCalc(iPRO_FTP[V6], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(7), "HTTP", iPRO_HTTP[V6], PercentCalc(iPRO_HTTP[V6], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(7), "SMTP", iPRO_SMTP[V6], PercentCalc(iPRO_SMTP[V6], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(7), "POP3", iPRO_POP3[V6], PercentCalc(iPRO_POP3[V6], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(7), "IMAP", iPRO_IMAP[V6], PercentCalc(iPRO_IMAP[V6], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(7), "Other", iPRO_L7OR[V6], PercentCalc(iPRO_L7OR[V6], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(4), "Other", iPRO_L4OR[V6], PercentCalc(iPRO_L4OR[V6], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(3), "Unknown", iPRO_L3OR, PercentCalc(iPRO_L3OR, iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(1));
    LOGRECORD(INFO, GetFormat(9), "Totle", iPRO_TOTLE);
    LOGRECORD(INFO, GetFormat(9), "Avg ALL Len", iPKT_LEN / iPRO_TOTLE);
    LOGRECORD(INFO, GetFormat(9), "Avg TCP Len", 
        iPKT_TCP_LEN > 0 ? iPKT_TCP_LEN / (iPRO_TCP[V4] + iPRO_TCP[V6]) : iPKT_TCP_LEN);
    LOGRECORD(INFO, GetFormat(9), "Avg UDP Len", 
        iPKT_UDP_LEN > 0 ? iPKT_UDP_LEN / (iPRO_UDP[V4] + iPRO_UDP[V6]) : iPKT_UDP_LEN);
    LOGRECORD(INFO, GetFormat(1));
}

/* Layer seven protocol analysis statistics */
void L7Statistic(int iSport, int iDport, int iPos)
{
    if (iSport == 53 || iDport == 53) { // UDP
        iPRO_DNS[iPos] ++;
    } else if (iDport == 25) { // TCP
        iPRO_SMTP[iPos] ++;
    } else if (iSport == 80 || iDport == 80 
            || iSport == 8080 || iDport == 8080) {
        iPRO_HTTP[iPos] ++;
    } else if (iDport == 110) {
        iPRO_POP3[iPos] ++;
    } else if (iSport == 143 || iDport == 143) {
        iPRO_IMAP[iPos] ++;
    } else if (iSport == 139 || iDport == 139 
            || iSport == 445 || iDport == 445) {
        iPRO_SMB[iPos] ++;
    } else if (iSport == 20 || iDport == 20 
            || iSport == 21 || iDport == 21) {
        iPRO_FTP[iPos] ++;
    } else {
        iPRO_L7OR[iPos] ++;
    }
}

/* Layer four protocol analysis statistics */
void L4Statistic(_udphdr* pUdpHdr, _tcphdr* pTcpHdr,
    _icmp4hdr* pIcmp4Hdr, _icmp6hdr* pIcmp6Hdr)
{
    int iPos = -1;
    if (iProTag == IPv4) {
        iPos = 0;
    } else if (iProTag == IPv6) {
        iPos = 1;
    } else {
        return ;
    }

    if (pTcpHdr != NULL) {
        iPRO_TCP[iPos] ++;
        L7Statistic(htons(pTcpHdr->sport), htons(pTcpHdr->dport), iPos);
    } else if (pUdpHdr != NULL) {
        iPRO_UDP[iPos] ++;
        L7Statistic(htons(pUdpHdr->sport), htons(pUdpHdr->dport), iPos);
    } else if (pIcmp4Hdr != NULL) {
        iPRO_ICMP[iPos] ++;
    } else if (pIcmp6Hdr != NULL) {
        iPRO_ICMP[iPos] ++;
    } else {
        iPRO_L4OR[iPos] ++;
    }
}

/* Layer three protocol analysis statistics */
void L3Statistic(_arphdr* pArpHdr, _ip4hdr* pIp4Hdr, _ip6hdr* pIp6Hdr)
{
    if (iProTag == IPv4 && pIp4Hdr != NULL) {
        iPRO_IP[V4] ++;
    } else if (iProTag == IPv6 && pIp6Hdr != NULL) {
        iPRO_IP[V6] ++;
    } else if (iProTag == ARP && pArpHdr != NULL) {
        iPRO_ARP ++;
    } else {
        iPRO_L3OR ++;
    }
}

/* Layer vlan protocol analysis statistics */
void VLANStatistic(_vlanhdr* pVlanHdr, _vlanhdr* pQinQHdr)
{
    if (iProTag == VLAN) {
        if (pVlanHdr != NULL) {
            iPRO_VLAN[0] ++;
            iProTag = htons(pVlanHdr->pro);
        } 
        if (pQinQHdr != NULL) {
            iPRO_VLAN[1] ++;
            iProTag = htons(pQinQHdr->pro);
        }
    }
}

/* Layer two protocol analysis statistics */
void L2Statistic(_etherhdr* pEtherHdr)
{
    if (pEtherHdr != NULL) {
        iPRO_TOTLE += 1;
        iProTag = htons(pEtherHdr->pro);
    } else {
        LOGRECORD(WARNING, "Not Ethernet packet");
    }
}

void PKTStatistic(_pkthdr* pPktHdr, _tcphdr* pTcpHdr, _udphdr* pUdpHdr)
{
    if (pPktHdr != NULL) {
        iPKT_LEN += pPktHdr->len;
    } else {
        LOGRECORD(WARNING, "Unidentified packet");
    }

    if (pTcpHdr != NULL) {
        iPKT_TCP_LEN += pPktHdr->len;
    } else if (pUdpHdr != NULL) {
        iPKT_UDP_LEN += pPktHdr->len;
    }
}

/* Packet protocol analysis statistics */
void StatisticPacket()
{
    int iFlowSwitch = GetNum("flow");
    while (DeepPacketInspection() > 0) {
        if (iFlowSwitch) {
            BuildFMT(GetPktStrc());
        }
        stPktStrc stPkt = GetPktStrc();
        PKTStatistic(stPkt.pPktHdr, stPkt.pTcpHdr, stPkt.pUdpHdr);
        L2Statistic(stPkt.pEtherHdr);
        VLANStatistic(stPkt.pVlanHdr, stPkt.pQinQHdr);
        L3Statistic(stPkt.pArpHdr, stPkt.pIp4Hdr, stPkt.pIp6Hdr);
        L4Statistic(stPkt.pUdpHdr, 
            stPkt.pTcpHdr, stPkt.pIcmp4Hdr, stPkt.pIcmp6Hdr);
    }

    DisplayStreamStorage();
    DisplayStatisticsResults();
}

