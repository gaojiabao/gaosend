#ifndef __STATISTIC_H__
#define __STATISTIC_H__

enum 
{
    EMPRO_ARP,
    EMPRO_VLAN,
    EMPRO_QinQ,
    EMPRO_IPv4,
    EMPRO_IPv6,
    EMPRO_ICMP4,
    EMPRO_ICMP6,
    EMPRO_UDP,
    EMPRO_TCP,
    EMPRO_UDP6,
    EMPRO_TCP6,
    EMPRO_HTTP,
    EMPRO_DNS,
    EMPRO_SMB,
    EMPRO_FTP,
    EMPRO_SMTP,
    EMPRO_POP3,
    EMPRO_IMAP,
    EMPRO_L3OTHER,
    EMPRO_L4OTHER,
    EMPRO_L4OTHER6,
};

#define V4 1
#define V6 0

void RecordStatisticsInfo(int );
void DisplayStatisticsResults();
void StatisticUpperUdp(int, int);
void StatisticUpperTcp(int, int);

#endif

