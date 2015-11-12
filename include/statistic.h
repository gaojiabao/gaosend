#ifndef __STATISTIC_H__
#define __STATISTIC_H__

enum 
{
	EMPRO_ARP,
	EMPRO_VLAN,
	EMPRO_QinQ,
	EMPRO_IPv4,
	EMPRO_IPv6,
	EMPRO_ICMPv4,
	EMPRO_ICMPv6,
	EMPRO_UDP,
	EMPRO_TCP,
	EMPRO_HTTP,
	EMPRO_DNS,
	EMPRO_OTHER,
};

void RecordStatisticsInfo(int );
void DisplayStatisticsResults();

#endif
