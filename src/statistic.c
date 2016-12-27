#include    <stdio.h>
#include    <string.h>
#include    "default.h"
#include    "packet.h"
#include    "runlog.h"
#include    "statistic.h"

static  int iTotleNum       = 0;
static  int iArpNum         = 0;
static  int iVlanNum        = 0;
static  int iQinQNum        = 0;
static  int iIpv4Num        = 0;         
static  int iIpv6Num        = 0;         
static  int iIcmpv4Num      = 0;         
static  int iIcmpv6Num      = 0;         
static  int iUdpNum         = 0;         
static  int iTcpNum         = 0;         
static  int iUdp6Num        = 0;         
static  int iTcp6Num        = 0;         
static  int iHttpNum        = 0;         
static  int iDnsNum         = 0; 
static  int iSmbNum         = 0; 
static  int iFtpNum         = 0; 
static  int iSmtpNum        = 0;
static  int iPop3Num        = 0;
static  int iImapNum        = 0;
static  int iL3OtherNum     = 0; 
static  int iL4OtherNum     = 0; 
static  int iL4Other6Num    = 0; 

void RecordStatisticsInfo(int iEmProNum)
{
    switch(iEmProNum) {
        case EMPRO_ARP      : iArpNum++;
                              iTotleNum++;   break;
        case EMPRO_VLAN     : iVlanNum++;    break;
        case EMPRO_QinQ     : iQinQNum++;    break;
        case EMPRO_IPv4     : iIpv4Num++;    break;
        case EMPRO_IPv6     : iIpv6Num++; 
                              iTotleNum++;   break;
        case EMPRO_ICMPv4   : iIcmpv4Num++;  
                              iTotleNum++;   break;
        case EMPRO_ICMPv6   : iIcmpv6Num++;  break;
                              //iTotleNum++;   break;
        case EMPRO_UDP      : iUdpNum++;     
                              iTotleNum++;   break;
        case EMPRO_TCP      : iTcpNum++;
                              iTotleNum++;   break;
        case EMPRO_UDP6      : iUdp6Num++;    break; 
                              //iTotleNum++;   break;
        case EMPRO_TCP6      : iTcp6Num++;   break;
                              //iTotleNum++;   break;
        case EMPRO_HTTP     : iHttpNum++;    break;
        case EMPRO_DNS      : iDnsNum++;     break;
        case EMPRO_SMB      : iSmbNum++;     break;
        case EMPRO_FTP      : iFtpNum++;     break;
        case EMPRO_SMTP     : iSmtpNum++;    break;
        case EMPRO_POP3     : iPop3Num++;    break;
        case EMPRO_IMAP     : iImapNum++;    break;
        case EMPRO_L4OTHER  : iL4OtherNum++;    
                              iTotleNum++;   break;
        case EMPRO_L4OTHER6 : iL4Other6Num++;break;   
        case EMPRO_L3OTHER  : iL3OtherNum++;     
                              iTotleNum++;   break;
    }
}

float PercentCalc(int a, int b)
{
    return ((a * 100.0)/b);
}

void DisplayStatisticsResults()
{    
    LOGRECORD(INFO, "--------------[statistic]--------------------");
    LOGRECORD(INFO, " |---VLAN          : |---%d(%.2f%%)", iVlanNum, PercentCalc(iVlanNum, iTotleNum));
    LOGRECORD(INFO, "   |----QinQ       :   |----%d(%.2f%%)", iQinQNum, PercentCalc(iQinQNum, iTotleNum));
    LOGRECORD(INFO, "---------------------------------------------");
    LOGRECORD(INFO, " |---ARP           : |---%d(%.2f%%)", iArpNum, PercentCalc(iArpNum, iTotleNum));
    LOGRECORD(INFO, " |---IPv4          : |---%d(%.2f%%)", iIpv4Num, PercentCalc(iIpv4Num, iTotleNum));
    LOGRECORD(INFO, "   |----ICMPv4     :   |----%d(%.2f%%)", iIcmpv4Num, PercentCalc(iIcmpv4Num, iTotleNum));
    LOGRECORD(INFO, "   |----UDP        :   |----%d(%.2f%%)", iUdpNum, PercentCalc(iUdpNum, iTotleNum));
    LOGRECORD(INFO, "     |-----DNS     :     |-----%d(%.2f%%)", iDnsNum, PercentCalc(iDnsNum, iTotleNum));
    LOGRECORD(INFO, "   |----TCP        :   |----%d(%.2f%%)", iTcpNum, PercentCalc(iTcpNum, iTotleNum));
    LOGRECORD(INFO, "     |-----SMB     :     |-----%d(%.2f%%)", iSmbNum, PercentCalc(iSmbNum, iTotleNum));
    LOGRECORD(INFO, "     |-----FTP     :     |-----%d(%.2f%%)", iFtpNum, PercentCalc(iFtpNum, iTotleNum));
    LOGRECORD(INFO, "     |-----HTTP    :     |-----%d(%.2f%%)", iHttpNum, PercentCalc(iHttpNum, iTotleNum));
    LOGRECORD(INFO, "     |-----SMTP    :     |-----%d(%.2f%%)", iSmtpNum, PercentCalc(iSmtpNum, iTotleNum));
    LOGRECORD(INFO, "     |-----POP3    :     |-----%d(%.2f%%)", iPop3Num, PercentCalc(iPop3Num, iTotleNum));
    LOGRECORD(INFO, "     |-----IMAP    :     |-----%d(%.2f%%)", iImapNum, PercentCalc(iImapNum, iTotleNum));
    LOGRECORD(INFO, "   |----L4_Other   :   |----%d(%.2f%%)", iL4OtherNum, PercentCalc(iL4OtherNum, iTotleNum));
    LOGRECORD(INFO, " |---IPv6          : |---%d(%.2f%%)", iIpv6Num, PercentCalc(iIpv6Num, iTotleNum));
    LOGRECORD(INFO, "   |----ICMPv6     :   |----%d(%.2f%%)", iIcmpv6Num, PercentCalc(iIcmpv6Num, iTotleNum));
    LOGRECORD(INFO, "   |----UDP        :   |----%d(%.2f%%)", iUdp6Num, PercentCalc(iUdp6Num, iTotleNum));
    LOGRECORD(INFO, "   |----TCP        :   |----%d(%.2f%%)", iTcp6Num, PercentCalc(iTcp6Num, iTotleNum));
    LOGRECORD(INFO, "   |----L4_Other   :   |----%d(%.2f%%)", iL4Other6Num, PercentCalc(iL4Other6Num, iTotleNum));
    LOGRECORD(INFO, " |---L3_Other      : |---%d(%.2f%%)", iL3OtherNum, PercentCalc(iL3OtherNum, iTotleNum));
    LOGRECORD(INFO, " Totle             : %d", iTotleNum);
    LOGRECORD(INFO, "---------------------------------------------");
}

