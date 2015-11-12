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
static  int iHttpNum        = 0;         
static  int iDnsNum         = 0; 
static  int iOtherNum       = 0; 

void RecordStatisticsInfo(int iEmProNum)
{
	switch(iEmProNum) {
		case EMPRO_ARP      : iArpNum++;
							  iTotleNum++;  break;
		case EMPRO_VLAN     : iVlanNum++;	break;
		case EMPRO_QinQ     : iQinQNum++;	break;
		case EMPRO_IPv4     : iIpv4Num++;	break;
		case EMPRO_IPv6     : iIpv6Num++;	break;
		case EMPRO_ICMPv4   : iIcmpv4Num++; 
							  iTotleNum++;  break;
		case EMPRO_ICMPv6   : iIcmpv6Num++; 
							  iTotleNum++;  break;
		case EMPRO_UDP      : iUdpNum++;	
							  iTotleNum++;  break;
		case EMPRO_TCP      : iTcpNum++;
							  iTotleNum++;  break;
		case EMPRO_HTTP     : iHttpNum++;	break;
		case EMPRO_DNS      : iDnsNum++;	break;
		default             : iOtherNum++;	break;
	}
}

void DisplayStatisticsResults()
{    
	LOGRECORD(INFO, "--------[statistic]---------");
	LOGRECORD(INFO, "  ARP       :    %d", iArpNum);
	LOGRECORD(INFO, "  VLAN      :    %d", iVlanNum);
	LOGRECORD(INFO, "  QinQ      :    %d", iQinQNum);
	LOGRECORD(INFO, "  IPv4      :    %d", iIpv4Num);
	LOGRECORD(INFO, "  IPv6      :    %d", iIpv6Num);
	LOGRECORD(INFO, "  TCP       :    %d", iTcpNum);
	LOGRECORD(INFO, "  UDP       :    %d", iUdpNum);
	LOGRECORD(INFO, "  ICMPv4    :    %d", iIcmpv4Num);
	LOGRECORD(INFO, "  ICMPv6    :    %d", iIcmpv6Num);
	LOGRECORD(INFO, "  Other     :    %d", iOtherNum);
	LOGRECORD(INFO, "  Totle     :    %d", iTotleNum);
	LOGRECORD(INFO, "----------------------------");
}

