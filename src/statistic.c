/*******************************************************
 *
 *  Author        : Mr.Gao
 *  Email         : 729272771@qq.com
 *  Filename      : statistic.c
 *  Last modified : 2017-04-25 14:14
 *  Description   : Protocol data statistics
 *
 * *****************************************************/


#include    "func.h"
#include    "flow.h"
#include    "runlog.h"
#include    "storage.h"
#include    "statistic.h"


/* Layer three protocol analysis statistics */
void L3Statistic(int iCode)
{
    switch (iCode) {
        case EMPRO_L3_ARP   : iPRO_ARP ++; break;
        case EMPRO_L3_IPv4  : iPRO_IP[V4] ++; break;
        case EMPRO_L3_IPv6  : iPRO_IP[V6] ++; break;
        case EMPRO_L3_OTHER : iPRO_L3OR ++; break;
    }
}

/* Layer vlan protocol analysis statistics */
void VLStatistic(int iCode)
{
    if (iCode == 1) {
        iPRO_VLAN[0] ++;
    } else if (iCode == 3) {
        iPRO_VLAN[0] ++;
        iPRO_VLAN[1] ++;
    }
}

/* Layer four protocol analysis statistics */
void L4Statistic(int iL3Code, int iCode)
{
    int iPos = ((iL3Code == 2) ? V4 : V6);
    switch (iCode) {
        case EMPRO_L4_UDP   : iPRO_UDP[iPos] ++; break;
        case EMPRO_L4_TCP   : iPRO_TCP[iPos] ++; break;
        case EMPRO_L4_ICMP4 : iPRO_ICMP[iPos] ++; break;
        case EMPRO_L4_ICMP6 : iPRO_ICMP[iPos] ++; break;
        case EMPRO_L4_OTHER : iPRO_L4OR[iPos] ++; break;
    }
}

/* Layer seven protocol analysis statistics */
void L7Statistic(int iL3Code, int iCode)
{
    int iPos = ((iL3Code == 2) ? V4 : V6);
    switch (iCode) {
        case EMPRO_L7_DNS   : iPRO_DNS[iPos] ++; break;
        case EMPRO_L7_SMB   : iPRO_SMB[iPos] ++; break;
        case EMPRO_L7_FTP   : iPRO_FTP[iPos] ++; break;
        case EMPRO_L7_HTTP  : iPRO_HTTP[iPos] ++; break;
        case EMPRO_L7_SMTP  : iPRO_SMTP[iPos] ++; break;
        case EMPRO_L7_POP3  : iPRO_POP3[iPos] ++; break;
        case EMPRO_L7_IMAP  : iPRO_IMAP[iPos] ++; break;
        case EMPRO_L7_OTHER : iPRO_L7OR[iPos] ++; break;
    }
}

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
            pPattern = "    %-24s: %d";
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
    LOGRECORD(INFO, GetFormat(4), "Other", iPRO_L4OR[V6], PercentCalc(iPRO_L4OR[V6], iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(3), "Unknown", iPRO_L3OR, PercentCalc(iPRO_L3OR, iPRO_TOTLE));
    LOGRECORD(INFO, GetFormat(1));
    LOGRECORD(INFO, GetFormat(9), "Totle", iPRO_TOTLE);
    LOGRECORD(INFO, GetFormat(1));
}

/* Packet protocol analysis statistics */
void StatisticPacket()
{
    // Turn on flow assoition
    if(GetNum("flow") > 0) {
        StreamStorageInit();
    }

    while (DeepPacketInspection() > 0) {
        iPRO_TOTLE ++;
        int iCode = GetStatisticCode();
        int iL3Code = (iCode / 10000);
        L3Statistic(iL3Code);
        VLStatistic(iCode / 1000 % 10);
        L4Statistic(iL3Code, (iCode / 100 % 10));
        L7Statistic(iL3Code, (iCode % 100));
    }

    if (GetNum("flow") > 0) {
        DisplayStreamStorage();
    }

    DisplayStatisticsResults();
}

