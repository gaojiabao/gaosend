#ifndef __STATISTIC_H__
#define __STATISTIC_H__

#define V4 0
#define V6 1

enum {
    EMPRO_L3_ARP = 1,
    EMPRO_L3_IPv4,
    EMPRO_L3_IPv6,
    EMPRO_L3_OTHER
};

enum {
    EMPRO_L3_VLAN = 1,
    EMPRO_L3_QinQ
}; 

enum {
    EMPRO_L4_UDP = 1,
    EMPRO_L4_TCP,
    EMPRO_L4_ICMP4,
    EMPRO_L4_ICMP6,
    EMPRO_L4_OTHER
};

enum {
    EMPRO_L7_DNS = 1,
    EMPRO_L7_SMB,
    EMPRO_L7_FTP,
    EMPRO_L7_HTTP,
    EMPRO_L7_SMTP,
    EMPRO_L7_POP3,
    EMPRO_L7_IMAP,
    EMPRO_L7_OTHER
};

long long int iPRO_TOTLE;
long long int iPRO_VLAN[2];

long long int iPRO_ARP;
long long int iPRO_IP[2];
long long int iPRO_L3OR;

long long int iPRO_TCP[2];
long long int iPRO_UDP[2];
long long int iPRO_ICMP[2];
long long int iPRO_L4OR[2];

long long int iPRO_DNS[2];
long long int iPRO_SMB[2];
long long int iPRO_FTP[2];
long long int iPRO_HTTP[2];
long long int iPRO_SMTP[2];
long long int iPRO_POP3[2];
long long int iPRO_IMAP[2];
long long int iPRO_L7OR[2];

long long int iPKT_LEN;
long long int iPKT_TCP_LEN;
long long int iPKT_UDP_LEN;

stPktStrc GetPktStrc();

#endif

