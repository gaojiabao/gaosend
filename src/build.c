/*
 *  author   : Mr. Gao
 *
 *  function : This file will deal with command args which get from terminal, 
 *             then make a specifed packet and send it.
 */

#include    <time.h>
#include    <stdio.h> 
#include    <fcntl.h>
#include    <stdlib.h>
#include    <unistd.h>
#include    <getopt.h>
#include    <string.h>
#include    <sys/time.h>
#include    "devide.h"
#include    "socket.h"
#include    "packet.h"
#include    "default.h"
#include    "function.h"
#include    "structure.h"
#include    "statistic.h"
#include    "runlog.h"
#include	"auth.h"
#include	"list_single.h"


void UseTimesFunction(int);
void chgip6();
void duplication(char*, int);
void merge(char*);
void SuperMan();
void PcapFileAnalyse(char*);


void ModifyPacketParameters(char* file);

/* debug flag */
int iDebugFlag = 0;

/* packet */
char    packet[PACKETLEN];
char    chksum[PACKETLEN];

/* packet structure */
_machdr*    mac_hdr    = NULL;
_vlanhdr*   vlan_hdr1  = NULL;
_vlanhdr*   vlan_hdr2  = NULL;
_arphdr*    arp_hdr    = NULL;
_ip4hdr*    ip4_hdr    = NULL;
_icmphdr*   icmp_hdr   = NULL;
_udphdr*    udp_hdr    = NULL;
_tcphdr*    tcp_hdr    = NULL;
_dnshdr*    dns_hdr    = NULL;
_pcaphdr*   pcap_hdr   = NULL;
_pkthdr*    pkt_hdr    = NULL;
_pseudohdr* pseudo_hdr = NULL;
char*       virtual    = NULL;
char*       data       = NULL;

/* really varible */
char*        sip       = SIP;
char*        dip       = DIP;
char*       smac       = SMAC;
char*       dmac       = DMAC;
int         vlan_num   = 0;
int         sport      = SPORT;
int         dport      = DPORT;
int         interval   = INTERVAL;
int         pkt_len    = PKTLEN;
int         offset     = OFFSET;
int         str_len    = STRLEN;
int         counter    = COUNTER;
int         vlan1      = VLANID;
int         vlan2      = VLANID;
char*       host;
char*       uri;
char*       interface  = INTERFACE;
char*       l2_pro     = L2PRO;
int         l3_pro     = IPv4;
char*       pcapfile;
int         l2_tag     = 1;
int         pay_len    = 0;
uint8_t     l4_pro     = UDP;

/* input varible tag */
char*       smac_tag   = NULL;
char*       dmac_tag   = NULL;
char*       sip_tag    = NULL;
char*       dip_tag    = NULL;
char*       sport_tag  = NULL;
char*       dport_tag  = NULL;
char*       pktlen_tag = NULL;
char*       vlan1_tag  = NULL;
char*       vlan2_tag  = NULL;
char*       str_tag    = "random";
char*       url_tag    = NULL;
char*       l3_pro_tag = NULL;
char*       l4_pro_tag = NULL;
char*       l7_pro_tag = NULL;
char*       rule_tag   = "other";
int         rule_str_len = 0;
int         iWriteMode = 0;


/* to make wireshark recognise *.pcap file */
void BuildPcapHeader()
{
    pcap_hdr->magic = htonl(0xd4c3b2a1);
    pcap_hdr->major = 2;
    pcap_hdr->minor = 4;
    pcap_hdr->thiszone = 0;
    pcap_hdr->sigflags = 0;
    pcap_hdr->snaplen = 1518;
    pcap_hdr->linktype = 1;
}

/* to make wireshark recognise every packet in *.pcap file */
void BuildPacketHeader()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    pkt_hdr->htimestamp = tp.tv_sec;
    pkt_hdr->ltimestamp = tp.tv_usec;
    pkt_hdr->caplen = pkt_len;
    pkt_hdr->len = pkt_len;
}

/* pseudo head struct for calculate checksum*/
void BuildPseudoHeader(uint32_t sip, uint32_t dip,uint8_t protocol, int len)
{
    pseudo_hdr->srcip = sip;
    pseudo_hdr->dstip = dip;
    pseudo_hdr->flag = 0;
    pseudo_hdr->protocol = protocol;
    pseudo_hdr->len = htons(len);
}

/* to make virtual packet for calculate checksum */
uint16_t BuildPseduoPacket(void* header, uint8_t protocol, int len)
{
    BuildPseudoHeader(inet_addr(sip), inet_addr(dip), protocol, len);
    memcpy(virtual, header, len);
    return GetCheckSum((uint16_t*)chksum, (len + 12));
}

/* ethernet layer two protocol struct */
void BuildMacHeader(char *smac, char *dmac, uint16_t type)
{
    mac_type_change(dmac, (char*)&mac_hdr->dmac);
    mac_type_change(smac, (char*)&mac_hdr->smac);
    mac_hdr->pro2 = type;
}

/* ethernet vlan protocol struct */
void BuildVlanField(_vlanhdr* vlan_hdr, uint16_t vlan_id, uint16_t type)
{
    vlan_hdr->vlan_id=vlan_id;
    vlan_hdr->type = type;
}

void BuildArpHeader(char *smac, char *dmac, uint32_t sip, uint32_t dip)
{
    arp_hdr->hrd = 0x01;
    arp_hdr->pro = htons(0x0800);
    arp_hdr->len = 0x06;
    arp_hdr->plen = 0x04;
    arp_hdr->option = htons(2);
    mac_type_change(smac, (char*)&arp_hdr->smac);
    arp_hdr->sip = sip;
    mac_type_change(dmac, (char*)&arp_hdr->dmac);
    arp_hdr->dip = dip;
}

/* ip protocol struct */
void BuildIpv4Header (uint32_t sip, uint32_t dip, uint8_t pro, int pkt_len)
{
    ip4_hdr->ver_len = (4 << 4 | IP4HDRLEN / 4);
    ip4_hdr->tos = 0;
    ip4_hdr->total_len = htons (pkt_len - MACHDRLEN - vlan_num * VLANLEN);
    ip4_hdr->ident = 1;
    ip4_hdr->flag_offset = 0;
    ip4_hdr->ttl = 128;
    ip4_hdr->protocol = pro;
    ip4_hdr->checksum = 0;
    ip4_hdr->srcip = sip;
    ip4_hdr->dstip = dip;
    ip4_hdr->checksum = GetCheckSum((uint16_t *) ip4_hdr, IP4HDRLEN);
}

/* icmp protocol struct */
void BuildIcmpv4Header()
{
    icmp_hdr->type = 0;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = GetCheckSum((uint16_t *)icmp_hdr, 30);
    icmp_hdr->identifier = htons(getpid());
    icmp_hdr->seq = 256;
}

/* udp protocol struct */
void BuildUdpHeader (int sport, int dport, int pkt_len)
{
    int udp_length;
    udp_hdr->sport = htons (sport);
    udp_hdr->dport = htons (dport);
    udp_length = pkt_len - MACHDRLEN - IP4HDRLEN - vlan_num * VLANLEN;
    udp_hdr->len = htons (udp_length);
    udp_hdr->checksum = 0;
    BuildPseudoHeader(inet_addr(sip), inet_addr(dip),UDP, udp_length);
    udp_hdr->checksum = BuildPseduoPacket(udp_hdr, UDP, udp_length);
}

/* dns protocol struct */
void BuildDnsHeader()
{
    dns_hdr->tid   = htons(0x1234);
    dns_hdr->flag  = htons(0x0001);
    dns_hdr->que   = htons(0x0001);
    dns_hdr->anrrs = htons(0x0000);
    dns_hdr->aurrs = htons(0x0000);
    dns_hdr->adrrs = htons(0x0000);
}

/* tcp protocol struct */
void BuildTcpHeader (int sport, int dport, int pkt_len)
{
    int tcp_length;
    tcp_hdr->sport = htons (sport);
    tcp_hdr->dport = htons (dport); tcp_hdr->seq = 1; tcp_hdr->ack = 0;
    tcp_length = pkt_len - MACHDRLEN - IP4HDRLEN - vlan_num * VLANLEN;
    tcp_hdr->hdrlen = 0x5f;
    tcp_hdr->flag = 128; /*cwr|ecn|urg|ack|psh|rst|syn|fin*/
    tcp_hdr->win = htons(65535);
    tcp_hdr->checksum = 0;
    tcp_hdr->checksum = BuildPseduoPacket(tcp_hdr, TCP, tcp_length);
    tcp_hdr->urg = 0;
}

/* help infomation for user */
void UsageOfProgram () 
{
    printf(
        "Usage: gaosend [args ...]\n"
        "PACKET ARGS\n" 
        "\t--smac       -a   Source mac  [ fixed | random | increase ]\n"
        "\t--sip        -s   Source ip   [ fixed | random | increase ]\n"
        "\t--sport      -P   Source port [ fixed | random | increase ]\n"
        "\t--dmac       -b   Destation mac  [ fixed | random | increase ]\n"
        "\t--dip        -d   Destation ip   [ fixed | random | increase ]\n"
        "\t--dport      -Q   Destation port [ fixed | random | increase ]\n"
        "\t--l3pro      -q   Layer 3 protocol [ ip | arp ]\n"
        "\t--l4pro      -p   Layer 4 protocol [ udp | tcp | icmp | random ]\n"
        "\t--l7pro      -H   Layer 7 protocol [ HTTP-GET | HTTP-POST | DNS ]\n"
        "\t--vlan1      -V   Vlan1 value [ fixed | random | increase ]\n"
        "\t--vlan2      -W   Vlan2 value [ fixed | random | increase ]\n"
        "\t--offset     -O   String offset\n"
        "\t--url        -u   URL in Http GET or Http POST\n"
        "\t--length     -l   Packet len  [ fixed | increace | random ]\n"
        "\t--string     -S   String in data part\n"
        "\t--strlen     -y   String length of rule\n"
        "FUNCTION ARGS\n"
        "\t--duplicate  -D   Duplicate N times into original pcap-file < filename times >\n"
        "\t--devide     -C   Devide the pcap file to single pcap file < filename >\n"
        "\t--merge      -m   Merge the pcap files into frist pcap file < filename >\n"
        "\t--statistic  -A   Statistic informations < filename >\n"
        "\t--modify     -M   Modify packet < filename >\n"
        "OTHER ARGS\n"
        "\t--filename   -w   Save packet into a pcap file < filename >\n"
        "\t--ruletype   -Z   Rule type [ aclnmask | aclex | mac_table ]\n"
        "\t--interval   -i   Interval time\n"
        "\t--interface  -I   Interface number\n"
        "\t--count      -c   Packets number\n"
        "\t--version    -v   Program version\n"
        "\t--help       -h   Help informations\n"
    );
    LOGRECORD(DEBUG, "Query help information");
    PROGRAMEND();
}

/* software version */
void VersionOfProgram ()
{
    printf ("Author  : GaoJiabao\n" 
            "E-mail  : 729272771@qq.com\n"
			"Version : %s-%s-%s\n",
            __DATE__, __TIME__, VERSION);
    LOGRECORD(DEBUG, "Check the version information");
    PROGRAMEND();
}

void DebugModeEntrance()
{
    iDebugFlag = 1;
    LOGRECORD(DEBUG, "Enable debug iWriteMode");
}

/* deal with terminal args */
extern void TerminalParametersInitialization()
{
    //smac
    if (smac_tag != NULL) {
        if (strcmp(smac_tag, "random") == 0) {
            smac = GetRandomMacAddress(0);
        } else if (strcmp(smac_tag, "increase") == 0) {
            smac = GetIncreaseMacAddress(0);
        } else {
            smac = smac_tag;
        }
    }

    //dmac
    if (dmac_tag != NULL) {
        if (strcmp(dmac_tag, "random") == 0) {
            dmac = GetRandomMacAddress(1);
        } else if (strcmp(dmac_tag, "increase") == 0) {
            dmac = GetIncreaseMacAddress(1);
        } else {
            dmac = dmac_tag;
        }
    }

    //sip
    if (sip_tag != NULL) {
        if (strcmp(sip_tag, "random") == 0) {
            sip = GetRandomIpAddress(0);
        } else if (strcmp(sip_tag, "increase") == 0) {
            sip = GetIncreaseIpAddress(0);
        } else {
            sip = sip_tag;
        }
    }

    //dip
    if (dip_tag != NULL) {
        if (strcmp(dip_tag, "random") == 0) {
            dip = GetRandomIpAddress(1);
        } else if (strcmp(dip_tag, "increase") == 0) {
            dip = GetIncreaseIpAddress(1);
        } else {
            dip = dip_tag;
        }
    }

    //sport
    if (sport_tag != NULL) {
        if (strcmp(sport_tag, "random") == 0) {
            sport = GetRandomPort();
        } else if (strcmp(sport_tag, "increase") == 0) {
            sport = GetIncreasePort(0);
        } else {
            sport = atoi(sport_tag);
        }
    }

    //dport
    if (dport_tag != NULL) {
        if (strcmp(dport_tag, "random") == 0) {
            dport = GetRandomPort();
        } else if (strcmp(dport_tag, "increase") == 0) {
            dport = GetIncreasePort(1);
        } else {
            dport = atoi(dport_tag);
        }
    }

    //pkt_len
    if (pktlen_tag != NULL) {
        if (strcmp(pktlen_tag, "random") == 0) {
            pkt_len = GetRandomPacketLength();
        } else if (strcmp(pktlen_tag, "increase") == 0) {
            pkt_len = GetIncreasePacketLength();
        } else {
            pkt_len = atoi(pktlen_tag);
        }
    }

    //l7_pro
    if (l7_pro_tag != NULL) {
        if (strcmp(l7_pro_tag, "HTTP-GET")==0 \
            || strcmp(l7_pro_tag, "HTTP-POST")==0) {
            l4_pro_tag = "tcp";
            dport = 80;
            if (pkt_len < 360)
                pkt_len = 360;
            
        } else if (strcmp(l7_pro_tag, "DNS")==0) {
            l4_pro_tag = "udp";
            dport = 53;
            if (url_tag == NULL) {
                pkt_len = MACHDRLEN+IP4HDRLEN+UDPHDRLEN+DNSHDRLEN+13+6;
            } else {
                host= strtok(url_tag, "/");
                pkt_len = MACHDRLEN+IP4HDRLEN+UDPHDRLEN\
                          +DNSHDRLEN+strlen(url_tag)+6;
            }
        }
    }             

    //l4_pro      
    if (l4_pro_tag!= NULL) {
        if (strcmp(l4_pro_tag, "random") == 0) {
            l4_pro = GetRandomLayer4Pro();
        } else {
            l4_pro = ProtocolConversion(l4_pro_tag);
        }
    }

    //vlan1
    if (vlan1_tag != NULL) {
        if (strcmp(vlan1_tag, "random") == 0) {
            vlan1 = GetRandomVlan();
        } else if (strcmp(vlan1_tag, "increase") == 0) {
            vlan1 = GetIncreaseVlan(0);
        } else {
            vlan1 = atoi(vlan1_tag);
        }
        vlan_num = 1;
    }

    //vlan2
    if (vlan2_tag != NULL) {
        if (strcmp(vlan2_tag, "random") == 0) {
            vlan2 = GetRandomVlan();
        } else if (strcmp(vlan2_tag, "increase") == 0) {
            vlan2 = GetIncreaseVlan(1);
        } else {
            vlan2 = atoi(vlan2_tag);
        }
        vlan_num = 2;
    }


    //l3_pro
    if (l3_pro_tag !=NULL) {
        l3_pro = ProtocolConversion(l3_pro_tag);
    }

    //mend packet length
    if(str_tag){
        int pkt_len_tmp = 0;
        if(l4_pro == UDP) {
            pkt_len_tmp = MACHDRLEN + vlan_num * VLANLEN \
                          + IP4HDRLEN + UDPHDRLEN + strlen(str_tag);
        }else if(l4_pro == TCP){
            pkt_len_tmp = MACHDRLEN + vlan_num * VLANLEN \
                          + IP4HDRLEN + TCPHDRLEN + strlen(str_tag);
        }
        if(pkt_len_tmp > pkt_len) 
          pkt_len = pkt_len_tmp;
    }
}


void Storage(char* title, char* value)
{
	printf("****************10\n");
	printf("[%s:%s]\n", title, value);
	int flag;
	if(strcmp(value, "increase") == 0) {
	  flag = 1;
	} else if(strcmp(value, "random") == 0) {
		flag = 2;
	} else {
	  flag = 0;
	}
	printf("flag:%d\n", flag);
	printf("****************10\n");

	update(title, value, flag);
}


/* init packet struct */
void PacketStrcutureInitialization()
{
    pkt_hdr     = (_pkthdr*) packet;
    mac_hdr     = (_machdr *) (packet + MACOFFSET);
    vlan_hdr1   = (_vlanhdr *)(packet + VLAN1OFFSET);
    vlan_hdr2   = (_vlanhdr *)(packet + VLAN2OFFSET);
    arp_hdr     = (_arphdr *) (packet + ARPOFFSET(vlan_num));
    ip4_hdr     = (_ip4hdr *) (packet + IPOFFSET(vlan_num));
    pseudo_hdr  = (_pseudohdr*) chksum;
    virtual     = (char*)(chksum + PSEUDOHDRLEN);
    icmp_hdr    = (_icmphdr *)(packet + ICMPv4OFFSET(vlan_num));
    udp_hdr     = (_udphdr *) (packet + UDPOFFSET(vlan_num));
    tcp_hdr     = (_tcphdr *) (packet + TCPOFFSET(vlan_num));

    LOGRECORD(DEBUG, "Packet strcuture initialization finished");
}

int WriteModeInitialization()
{
    int iPcapFd;
    pcap_hdr = (_pcaphdr*)packet;
    BuildPcapHeader();
    if((iPcapFd =open(pcapfile, O_WRONLY|O_EXCL|O_CREAT, PERM)) < 0) {
        LOGRECORD(ERROR, "pcap file open error or exist");
    }
    if (write(iPcapFd, packet, PCAPHDRLEN) < 0 ) {
        LOGRECORD(ERROR, "save pcap file error");
    }
    if (iDebugFlag){
        DisplayPacketData(packet, PCAPHDRLEN);
    }

    return iPcapFd;
}

void BuildLayer2Header()
{
	int vlNum = atoi(GetValue("vlnum"));
	printf("vlNum:%d\n",vlNum);

	char* smac = GetValue("smac");
	char* dmac = GetValue("dmac");
	printf("hahah\n");
	uint16_t pro = GetHex(GetValue("l3pro"));

	printf("**************************start\n");
	switch(vlNum) {
		case 0: BuildMacHeader (smac, dmac, pro);
				break;
		case 1: BuildMacHeader (smac, dmac, VLAN);
				BuildVlanField (vlan_hdr1, htons(vlan1), pro);
				RecordStatisticsInfo(EMPRO_VLAN);
				break;
		case 2: BuildMacHeader (smac, dmac, VLAN);
				BuildVlanField (vlan_hdr1, htons(vlan1), VLAN);
				BuildVlanField (vlan_hdr2, htons(vlan2), pro);
				RecordStatisticsInfo(EMPRO_QinQ);
				break;
		default:LOGRECORD(ERROR, "VLAN number is wrong");
				break;
	}
	printf("**************************end\n");
	printf("out of BuildLayer2Header\n");
}

void BuildLayer3Header()
{
    if (GetHex(GetValue("l3pro")) == IPv4) {
        BuildIpv4Header (inet_addr (sip), inet_addr (dip), l4_pro, pkt_len);
    } else if(GetHex(GetValue("l3pro")) == ARP) {
        BuildArpHeader(GetValue("smac"), GetValue("dmac"), \
			inet_addr(GetValue("sip")), inet_addr(GetValue("dip")));
        RecordStatisticsInfo(EMPRO_ARP);
    }
}

void BuildLayer4Header()
{
	switch(GetHex(GetValue("l4pro"))) {
		case UDP:
			BuildUdpHeader ((uint16_t) sport, (uint16_t) dport, pkt_len);
			RecordStatisticsInfo(EMPRO_UDP);
			break;
		case TCP:
			BuildTcpHeader ((uint16_t) sport, (uint16_t) dport, pkt_len);
			RecordStatisticsInfo(EMPRO_TCP);
			break;
		case ICMPv4:
			BuildIcmpv4Header();
			RecordStatisticsInfo(EMPRO_ICMPv4);
			break;
		default:
			LOGRECORD(ERROR, "Layer 4 protocal is not found");
	}
}

void BuildDnsDataContext()
{
    char cDnsData[150];
    if (url_tag == NULL) {
        char* url_res = GetUrlString();
        host= strtok(url_res, "/");
    }
    memset(cDnsData, 0, 50);
    cDnsData[0]='.';
    strcat(cDnsData, host);
    strcat(cDnsData, ".");
    unsigned int i=0, pos=0, dnslen=0, dnum=0, slen=0;
    for(i=0;i<strlen(cDnsData);i++) {
        if (cDnsData[i+1]) {
            if (cDnsData[i] == '.') {
                if (++dnum > 1) {
                    cDnsData[pos] = (slen-1)&0xff;
                    slen = 0;
                    pos = i;
                } else {
                    pos = i;
                }
            }
            slen++;
        } else {
            cDnsData[pos] = (slen-1)&0xff;
            cDnsData[i] = 0x00;
        }
    }
    dnslen = strlen(cDnsData);
    cDnsData[++dnslen] = 0x00;
    cDnsData[++dnslen] = 0x01;
    cDnsData[++dnslen] = 0x00;
    cDnsData[++dnslen] = 0x01;
    memcpy(data, cDnsData, ++dnslen);
}

void BuildHttpDataContext()
{
    if (url_tag == NULL) {
        char*    url_res = GetUrlString();
        host = strtok(url_res, "/");
        uri = url_res + strlen(host) + 1;
    } else {
        uri = url_tag;
        host = "";
    }

    char Http[BUFSIZ];
    memset(Http, 0, BUFSIZ);

    if (strcmp(l7_pro_tag, "HTTP-GET") == 0) {
        strcat(Http, "GET /");  
    } else if (strcmp(l7_pro_tag, "HTTP-POST") == 0) {
        strcat(Http, "POST /");  
    }

    strcat(Http, uri);  
    strcat(Http, " HTTP/1.1\r\n");  
    strcat(Http, "Host: ");  
    strcat(Http, host);  
    strcat(Http, "\r\nConnection: Keep-Alive\r\n");  
    strcat(Http, "Accept: */*\r\n");  
    strcat(Http, "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0;"
                 "Windows NT 5.1; Trident/4.0;"
                 ".NET CLR 2.0.50727; .NET CLR 3.0.04506.648;"
                 " .NET CLR 3.5.21022; InfoPath.2)\r\n");  
    strcat(Http, "Accept-Encoding: gzip, deflate/r/n");  
    strcat(Http, "Accept-Language: zh-cn\r\n");  
    strcat(Http, "Cookie:");  
    strcat(Http, GetRandomCharactor(pay_len - strlen(Http) - 4));
    strcat(Http, "\r\n\r\n");  
    memcpy(data, Http, strlen(Http));
}

void BuildDataContexts()
{
    if (pay_len < offset) {
        LOGRECORD(ERROR, "offset grate than payload length");
    } 

    if (strcmp(str_tag, "random") == 0 && l7_pro_tag == NULL) {
        if(rule_str_len != 0 && rule_str_len < pay_len){
            pay_len = rule_str_len;
        }
        memcpy (data, GetRandomCharactor(pay_len), pay_len);
    } else if (str_tag[0] == '0' && str_tag[1] == 'x' && !l7_pro_tag) {
        char* stop;
        unsigned int i=2;
        int j = 0;
        while(i < strlen(str_tag)) {
            data[offset+j] = strtol(subs(str_tag, i, 2), &stop, 16);
            i += 2;
            j += 1;
        }
    } else if (!l7_pro_tag) {
        memcpy (data+offset, str_tag, strlen(str_tag));
    }
}

void BuildLayer7Header()
{
	// *data initialization
    if (l4_pro == UDP) {
        data = packet + UDPDATAOFFSET(vlan_num);
        if (l7_pro_tag) {
            dns_hdr = (_dnshdr *) (packet+DNSOFFSET(vlan_num));
            data = packet + DNSDATAOFFSET(vlan_num);
        } else {
            pay_len = UDPPAYLEN(pkt_len, vlan_num);
        }
    } else if (l4_pro == TCP) {
        data = packet + TCPDATAOFFSET(vlan_num);
        pay_len = TCPPAYLEN(pkt_len, vlan_num);
    } else if (l4_pro == ICMPv4) {
        data = packet + ICMPv4DATAOFFSET(vlan_num);
        pay_len = ICMPv4PAYLEN(pkt_len, vlan_num);
    }

    // deal with protocol
    if (l7_pro_tag != NULL 
			&& strcmp(l7_pro_tag, "DNS")==0) {
        BuildDnsHeader();
        BuildDnsDataContext();
    } else if (l7_pro_tag != NULL 
            && (strcmp(l7_pro_tag, "HTTP-GET")==0 
            ||  strcmp(l7_pro_tag, "HTTP-POST")==0)) {
        BuildHttpDataContext();
    } else {
        BuildDataContexts();
    }
}

int RuleModeInitialization()
{
    int fd = 0;
    if (strcmp(rule_tag, "aclnmask") == 0) {
        fd=open(ACLNMASKFILE, O_WRONLY|O_CREAT, PERM);
    } else if (strcmp(rule_tag, "aclex") == 0) {
        fd=open(ACLEXFILE, O_WRONLY|O_CREAT, PERM);
    } else if (strcmp(rule_tag, "mac_table") == 0) {
        fd=open(MACTABLEFILE, O_WRONLY|O_CREAT, PERM);
    }

    return fd;
}

void RulesGenerationEntrance(int fd, int iRuleNum)
{
    /* to print reletive ACL rules into file*/
    if (strcmp(rule_tag, "aclnmask") == 0) {
        if (dprintf(fd, "add ruleset test aclnmask %d "
                "action=drop, sip=%s, dip=%s, sport=%d, dport=%d, protocol=%s\n", 
                iRuleNum, sip, dip, sport, dport,
                ChangeLayer4HexToString(l4_pro)) < 0) {
            LOGRECORD(ERROR, "write aclmask rules error");
        }
    } else if (strcmp(rule_tag, "aclex") == 0) {
        if (dprintf(fd, "add ruleset test aclex %d "
                "action=drop, offset=%d, strkey=%s\n", 
                iRuleNum, offset, data+offset) < 0) {
            LOGRECORD(ERROR, "write aclex rules error");
        }
    } else if (strcmp(rule_tag, "mac_table") == 0) {
        if (dprintf(fd, "add mac_table %s "
                "action=forward, outgroup=1\n", smac) < 0) {
            LOGRECORD(ERROR, "write mac table rules error");
        }
    }
}

void CloseRuleMode(int fd)
{
    close(fd);
    LOGRECORD(DEBUG, "Write rules finished");
}

void CloseWriteMode(int fd)
{
    close(fd);
    LOGRECORD(DEBUG, "Write packets finished");
}

void PcapFileAnalyse(char* file)
{
    int fdin;
    int vlanNum = 0;
    pcap_hdr = (_pcaphdr*)packet;

    /*
    if(interface == NULL)
        SendModeInitialization(interface);
    else
        LOGRECORD(ERROR, "interface is null");
    */
    SendModeInitialization("eth1");

    UseTimesFunction(+1);
    PacketStrcutureInitialization();

    memset(packet,0,sizeof(packet));
    if ((fdin = open(file, O_RDWR)) < 0) {
        LOGRECORD(ERROR, "open pcap file error");
    }
    if (read(fdin, packet, PCAPHDRLEN) < 0) {
        LOGRECORD(ERROR, "read pcaphdr error");
    }
    if (htonl(pcap_hdr->magic) != 0xd4c3b2a1) {
        LOGRECORD(ERROR, "file paratarn error");
    }

    while (read(fdin, packet, PKTHDRLEN) > 1) {
        if (read(fdin, packet+PKTHDRLEN, pkt_hdr->len) < 0) {
            LOGRECORD(ERROR, "read packethdr error");
            exit(0);
        }
        TerminalParametersInitialization();

        if(smac) mac_type_change(smac, (char*)&mac_hdr->smac);
        if(dmac) mac_type_change(dmac, (char*)&mac_hdr->dmac);

        if (htons(mac_hdr->pro2) == VLAN) {
            vlanNum++;
            if(htons(vlan_hdr1->type) == VLAN){
                vlanNum++;
                if(vlan2_tag){
                    vlan_hdr2->vlan_id = htons(vlan2);
                }
            }
            if(vlan1_tag){
                vlan_hdr1->vlan_id = htons(vlan1);
            }
        }

        if (htons(mac_hdr->pro2) == ARP) {
			RecordStatisticsInfo(EMPRO_ARP);
        } else if (htons(mac_hdr->pro2) == IPv4) { // Layer 3
			RecordStatisticsInfo(EMPRO_IPv4);
            if (ip4_hdr->protocol == UDP) { // Layer 4
				RecordStatisticsInfo(EMPRO_UDP);
            } else if (ip4_hdr->protocol == TCP) { // Layer 4
				RecordStatisticsInfo(EMPRO_TCP);
            }else if (ip4_hdr->protocol == ICMPv4) { // Layer 4
				RecordStatisticsInfo(EMPRO_ICMPv4);
            }
        }
		SendPacketProcess(packet+PKTHDRLEN, pkt_hdr->len);
		/*
        else if (htons(mac_hdr->pro2) == IPv6) { // Layer 3
			RecordStatisticsInfo(EMPRO_IPv6);
            if (ip6_hdr->protocol == TCP) { // Layer 4
				RecordStatisticsInfo(EMPRO_TCP);
            }else if (ip6_hdr->protocol == UDP) { // Layer 4
				RecordStatisticsInfo(EMPRO_UDP);
            }else if (ip6_hdr->protocol == ICMPv6) { // Layer 4
				RecordStatisticsInfo(EMPRO_ICMPv6);
            } else {
				RecordStatisticsInfo(EMPRO_UNKNOWN);
            }
        } 
		*/
    }// end of while

    close(fdin);
	DisplayStatisticsResults();

    PROGRAMEND();

}
void RegularExpress()
{

}

void ModifyPacketParameters(char* file)
{
    int fdin;
    int fdout;
    int vlanNum = 0;
	int packetId = 0;
    pcap_hdr = (_pcaphdr*)packet;

    UseTimesFunction(+1);
    PacketStrcutureInitialization();

    memset(packet,0,sizeof(packet));
    if ((fdin = open(file, O_RDWR)) < 0) {
        LOGRECORD(ERROR, "open pcap file error");
    }
    if ((fdout = open("result.pcap", O_RDWR | O_CREAT, PERM)) < 0) {
        LOGRECORD(ERROR, "open result.pcap error");
    }
    if (read(fdin, packet, PCAPHDRLEN) < 0) {
        LOGRECORD(ERROR, "read pcaphdr error");
    }
    if (htonl(pcap_hdr->magic) != 0xd4c3b2a1) {
        LOGRECORD(ERROR, "file paratarn error");
    }

    if (write(fdout, packet, PCAPHDRLEN) < 0) {
        LOGRECORD(ERROR, "read pcaphdr error");
    }

    memset(packet,0,sizeof(packet));

    while (read(fdin, packet, PKTHDRLEN) > 1) {
        if (read(fdin, packet+PKTHDRLEN, pkt_hdr->len) < 0) {
            LOGRECORD(ERROR, "read packethdr error");
            exit(0);
        }
		packetId++;
		/*
		if(packetId == 4){
			DisplayPacketData(packet+PKTHDRLEN, pkt_hdr->len);
			printf("%s\n", );
		}
		*/
        TerminalParametersInitialization();

        if(smac) mac_type_change(smac, (char*)&mac_hdr->smac);
        if(dmac) mac_type_change(dmac, (char*)&mac_hdr->dmac);

		// add vlan
		/*
		BuildVlanField(vlan_hdr1, htons(100), htons(mac_hdr->pro2));
		mac_hdr->pro2 = htons(VLAN);
		DisplayPacketData(packet, pkt_hdr->len);
		memcpy(packet+PKTHDRLEN+MACHDRLEN, vlan_hdr1, 4);
		memcpy(packet+PKTHDRLEN+MACHDRLEN+4, packet+PKTHDRLEN+MACHDRLEN, pkt_hdr->len-MACHDRLEN);
		DisplayPacketData(packet, pkt_hdr->len+4);
		*/

        if (htons(mac_hdr->pro2) == VLAN) {
            vlanNum++;
            if(htons(vlan_hdr1->type) == VLAN){
                vlanNum++;
                if(vlan2_tag){
                    vlan_hdr2->vlan_id = htons(vlan2);
                }
            }
            if(vlan1_tag){
                vlan_hdr1->vlan_id = htons(vlan1);
            }
        }

        if (htons(mac_hdr->pro2) == ARP) {
            LOGRECORD(INFO, "ARP Nothing to perform");
        } else if (htons(mac_hdr->pro2) == IPv4) { // Layer 3
			/*
			if( ip4_hdr->srcip == inet_addr("10.10.10.4")){
				ip4_hdr->srcip = inet_addr("1.1.1.1");
				printf("%x\n",ip4_hdr->srcip);
			}
			*/
            if(sip_tag) ip4_hdr->srcip = inet_addr(sip);
            if(dip_tag) ip4_hdr->dstip = inet_addr(dip);
            if (ip4_hdr->protocol == UDP) { // Layer 4
                if(sport_tag) udp_hdr->sport = htons(sport);
                if(dport_tag) udp_hdr->dport = htons(dport);
            } else if (ip4_hdr->protocol == TCP || ip4_hdr->protocol == UDP) { // Layer 4
                if(sport_tag) tcp_hdr->sport = htons(sport);
                if(dport_tag) tcp_hdr->dport = htons(dport);
            }else if (ip4_hdr->protocol == ICMPv4) { // Layer 4
                LOGRECORD(INFO, "ICMP Nothing to perform");
            }
        } 
        /*
        else if (htons(mac_hdr->pro2) == IPv6) { // Layer 3
            unsigned char buf1[sizeof(struct in6_addr)];
            unsigned char buf2[sizeof(struct in6_addr)];
            if (sip_tag) {
                ip4_hdr->srcip = inet_pton(AF_INET6, sip, buf1);
                memPcpy(packetbuf, 32, buf1, sizeof(struct in6_addr));
            }
            if (dip_tag) {
                ip4_hdr->dstip = inet_pton(AF_INET6, dip, buf2);
                memPcpy(packetbuf, 48, buf2, sizeof(struct in6_addr));
            }
            if (ip6_hdr->protocol == TCP) { // Layer 4
                if (sport_tag) tcp_hdr->sport = htons(sport);
                if (dport_tag) tcp_hdr->dport = htons(dport);
            }else if (ip6_hdr->protocol == UDP) { // Layer 4
                if (sport_tag) udp_hdr->sport = htons(sport);
                if (dport_tag) udp_hdr->dport = htons(dport);
            }else if (ip6_hdr->protocol == ICMPv6) { // Layer 4
                printf("ICMPv6 Nothing to perform\n");
            } else {
                printf("ALL Nothing to perform\n");
            }
        } 
        */
		RegularExpress();

		//DisplayPacketData(packet, pkt_hdr->len+PKTHDRLEN);
        if (write(fdout, packet, pkt_hdr->len+PKTHDRLEN) < 0) {
            LOGRECORD(ERROR, "write packetbuf error");
        }
    }// end of while

    close(fdin);
    close(fdout);

    PROGRAMEND();

}

/* to build packets*/
extern void BuildPacketEnterance()
{
	printf("***********in BuildPacketEnterance*************\n");
    int iPcapFd = 0;
    int iLoopNum = 0;

    UseTimesFunction(+1);

	printf("%d\n", iWriteMode);
    /* how to deal with packets */
    (!iWriteMode) ? SendModeInitialization(interface) \
        : (iPcapFd = WriteModeInitialization());

    int fd = RuleModeInitialization();
    PacketStrcutureInitialization();

    /* build packet */
    while (!counter || iLoopNum<counter) {
        memset(packet, 0, PACKETLEN);

        TerminalParametersInitialization();

        if (iWriteMode){
            BuildPacketHeader();
        }

		printf("************1\n");
        BuildLayer2Header();
		printf("************2\n");
        BuildLayer3Header();
		printf("************3\n");

        BuildLayer4Header();
		printf("************4\n");
        BuildLayer7Header();
		printf("************7\n");

		printf("iWriteMode:%d\n", iWriteMode);
		DisplayPacketData(packet, pkt_len+PKTHDRLEN);
        if (iWriteMode) {
            /* write packet into a *.pcap file */
            if (write(iPcapFd, packet, pkt_len+PKTHDRLEN) < 0) {
                LOGRECORD(ERROR, "write packet to pacp file error");
            }
            /* display every packet for debug */
            if (iDebugFlag)
                DisplayPacketData(packet, pkt_len+PKTHDRLEN);
        } else {
            /* send packet to interface interface */
			printf("here1\n");
			printf("pkt_len:%d\n", pkt_len);
            SendPacketProcess(packet+PKTHDRLEN, pkt_len);
			printf("here2\n");
            /* display every packet for debug */
            if (iDebugFlag) {
                DisplayPacketData(packet + PKTHDRLEN, pkt_len);
            }
        }

        if(strcmp(rule_tag,"other") != 0) {
            RulesGenerationEntrance(fd, iLoopNum);
        }

        /* time interval */
        usleep(interval);

        /* display program process */
        ProgramProcessingSchedule(++iLoopNum, counter);
    }//end of while

    LOGRECORD(DEBUG, "Build packets finished,num:%d", iLoopNum);

    if (iDebugFlag) {
        DisplayStatisticsResults();
    }

    if (!iWriteMode) {
        LOGRECORD(INFO, "%d packets have been sent !", iLoopNum);
        CloseSendConnect();
    } else {
        CloseWriteMode(iPcapFd);
    }

    if(strcmp(rule_tag,"other") != 0) {
       CloseRuleMode(fd);
    }

	printf("*****************end of Build****************\n");
}//end of 

