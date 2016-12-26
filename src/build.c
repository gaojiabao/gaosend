/*
 *  author   : Mr. Gao
 *
 *  function : This file will deal with command args which get from terminal, 
 *             then make a specifed packet and send it.
 */

#include    <time.h>
#include    <stdio.h> 
#include    <stdlib.h>
#include    <fcntl.h>
#include    <unistd.h>
#include    <string.h>
#include    <sys/time.h>
#include    "packet.h"
#include    "default.h"
#include    "function.h"
#include    "structure.h"
#include    "statistic.h"
#include    "runlog.h"
#include    "socket.h"
#include    "storage.h"

/* packet */
char    packet[PACKETLEN];
char    chksum[PACKETLEN];

/* packet structure */
_machdr*    pMacHdr    = NULL;
_vlanhdr*   pVlanHdr1  = NULL;
_vlanhdr*   pVlanHdr2  = NULL;
_arphdr*    pArpHdr    = NULL;
_ip4hdr*    pIp4Hdr    = NULL;
_ip6hdr*    pIp6Hdr    = NULL;
_icmphdr*   pIcmpHdr   = NULL;
_udphdr*    pUdpHdr    = NULL;
_tcphdr*    pTcpHdr    = NULL;
_dnshdr*    pDnsHdr    = NULL;
_pcaphdr*   pPcapHdr   = NULL;
_pkthdr*    pPktHdr    = NULL;
_pseudohdr* pPseudoHdr = NULL;
char*       virtual    = NULL;
char*       data       = NULL;

/* really varible */
int         str_len    = STRLEN;
char*       host;
char*       uri;
uint8_t     l4_pro     = UDP;

/* input varible tag */
char*       url_tag    = NULL;
char*       rule_tag   = "other";
int         rule_str_len = 0;


/* to make wireshark recognise *.pcap file */
void BuildPcapHeader()
{
    pPcapHdr->magic = htonl(0xd4c3b2a1);
    pPcapHdr->major = 2;
    pPcapHdr->minor = 4;
    pPcapHdr->thiszone = 0;
    pPcapHdr->sigflags = 0;
    pPcapHdr->snaplen = 1518;
    pPcapHdr->linktype = 1;
}

/* to make wireshark recognise every packet in *.pcap file */
void BuildPacketHeader(int pktlen)
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    pPktHdr->htimestamp = tp.tv_sec;
    pPktHdr->ltimestamp = tp.tv_usec;
    pPktHdr->caplen = pktlen;
    pPktHdr->len = pktlen;
}

/* pseudo head struct for calculate checksum*/
void BuildPseudoHeader(uint32_t sip, uint32_t dip,uint8_t protocol, int len)
{
    pPseudoHdr->srcip = sip;
    pPseudoHdr->dstip = dip;
    pPseudoHdr->flag = 0;
    pPseudoHdr->protocol = protocol;
    pPseudoHdr->len = htons(len);
}

/* to make virtual packet for calculate checksum */
uint16_t BuildPseduoPacket(void* header, uint8_t protocol, int len)
{
    BuildPseudoHeader(inet_addr(GetcValue("sip")), inet_addr(GetcValue("dip")), protocol, len);
    memcpy(virtual, header, len);
    return GetCheckSum((uint16_t*)chksum, (len + 12));
}

/* ethernet layer two protocol struct */
void BuildMacHeader(char *smac, char *dmac, uint16_t pro)
{
    mac_type_change(dmac, (char*)&pMacHdr->dmac);
    mac_type_change(smac, (char*)&pMacHdr->smac);
    pMacHdr->pro2 = pro;
}

/* ethernet vlan protocol struct */
void BuildVlanField(_vlanhdr* vlan_hdr, uint16_t vlan_id, uint16_t type)
{
    vlan_hdr->vlan_id = vlan_id;
    vlan_hdr->type = type;
}

void BuildArpHeader(char *smac, char *dmac, uint32_t sip, uint32_t dip)
{
    pArpHdr->hrd = 0x01;
    pArpHdr->pro = htons(0x0800);
    pArpHdr->len = 0x06;
    pArpHdr->plen = 0x04;
    pArpHdr->option = htons(2);
    mac_type_change(smac, (char*)&pArpHdr->smac);
    pArpHdr->sip = sip;
    mac_type_change(dmac, (char*)&pArpHdr->dmac);
    pArpHdr->dip = dip;
}

/* ip protocol struct */
void BuildIpv4Header(uint32_t sip, uint32_t dip, uint8_t pro)
{
    int vlNum = GetiValue("vlannum");
    int pkt_len = GetiValue("pktlen");
    pIp4Hdr->ver_len = (4 << 4 | IP4HDRLEN / 4);
    pIp4Hdr->tos = 0;
    pIp4Hdr->total_len = htons (pkt_len - MACHDRLEN - vlNum * VLANLEN);
    pIp4Hdr->ident = 1;
    pIp4Hdr->flag_offset = 0;
    pIp4Hdr->ttl = 128;
    pIp4Hdr->protocol = pro;
    pIp4Hdr->checksum = 0;
    pIp4Hdr->srcip = sip;
    pIp4Hdr->dstip = dip;
    pIp4Hdr->checksum = GetCheckSum((uint16_t *) pIp4Hdr, IP4HDRLEN);
}

/* icmp protocol struct */
void BuildIcmpv4Header()
{
    pIcmpHdr->type = 0;
    pIcmpHdr->code = 0;
    pIcmpHdr->checksum = GetCheckSum((uint16_t *)pIcmpHdr, 30);
    pIcmpHdr->identifier = htons(getpid());
    pIcmpHdr->seq = 256;
}

/* udp protocol struct */
void BuildUdpHeader(int sport, int dport, int pkt_len)
{
    int udp_length;
    pUdpHdr->sport = htons (sport);
    pUdpHdr->dport = htons (dport);
    udp_length = pkt_len - MACHDRLEN - IP4HDRLEN - GetiValue("vlannum") * VLANLEN;
    pUdpHdr->len = htons (udp_length);
    pUdpHdr->checksum = 0;
    BuildPseudoHeader(inet_addr(GetcValue("sip")), inet_addr(GetcValue("dip")),UDP, udp_length);
    pUdpHdr->checksum = BuildPseduoPacket(pUdpHdr, UDP, udp_length);
}

/* dns protocol struct */
void BuildDnsHeader()
{
    pDnsHdr->tid   = htons(0x1234);
    pDnsHdr->flag  = htons(0x0001);
    pDnsHdr->que   = htons(0x0001);
    pDnsHdr->anrrs = htons(0x0000);
    pDnsHdr->aurrs = htons(0x0000);
    pDnsHdr->adrrs = htons(0x0000);
}

/* tcp protocol struct */
void BuildTcpHeader(int sport, int dport, int pktlen)
{
    int vlNum = GetiValue("vlannum");
    int tcplen = pktlen - MACHDRLEN - IP4HDRLEN - vlNum * VLANLEN;
    pTcpHdr->sport = htons(sport);
    pTcpHdr->dport = htons(dport); 
    pTcpHdr->seq = 1; 
    pTcpHdr->ack = 0;
    pTcpHdr->hdrlen = 0x5f;
    pTcpHdr->flag = 128; /*cwr|ecn|urg|ack|psh|rst|syn|fin*/
    pTcpHdr->win = htons(65535);
    pTcpHdr->checksum = BuildPseduoPacket(pTcpHdr, TCP, tcplen);
    pTcpHdr->urg = 0;
}

/* init packet struct */
void PacketStrcutureInitialization()
{
    int vlNum = GetiValue("vlannum");
    pPktHdr     = (_pkthdr*) packet;
    pMacHdr     = (_machdr *) (packet + MACOFFSET);
    pVlanHdr1   = (_vlanhdr *)(packet + VLAN1OFFSET);
    pVlanHdr2   = (_vlanhdr *)(packet + VLAN2OFFSET);
    pArpHdr     = (_arphdr *) (packet + ARPOFFSET(vlNum));
    pIp4Hdr     = (_ip4hdr *) (packet + IPOFFSET(vlNum));
    pPseudoHdr  = (_pseudohdr*) chksum;
    virtual     = (char*)(chksum + PSEUDOHDRLEN);
    pIcmpHdr    = (_icmphdr *)(packet + ICMPv4OFFSET(vlNum));
    pUdpHdr     = (_udphdr *) (packet + UDPOFFSET(vlNum));
    pTcpHdr     = (_tcphdr *) (packet + TCPOFFSET(vlNum));

    LOGRECORD(DEBUG, "Packet strcuture initialization finished");
}

int WriteModeInitialization()
{
    int iPcapFd;
    pPcapHdr = (_pcaphdr*)packet;
    BuildPcapHeader();
    if ((iPcapFd =open(GetcValue("savefile"), 
        O_WRONLY|O_EXCL|O_CREAT, PERM)) < 0) {
        LOGRECORD(ERROR, "pcap file open error or exist");
    }
    if (write(iPcapFd, packet, PCAPHDRLEN) < 0 ) {
        LOGRECORD(ERROR, "save pcap file error");
    }
    if (GetiValue("debug")) {
        DisplayPacketData(packet, PCAPHDRLEN);
    }

    return iPcapFd;
}

void BuildLayer2Header()
{
    int   vlan1, vlan2;
    int   vlNum = GetiValue("vlannum");
    char* smac = GetcValue("smac");
    char* dmac = GetcValue("dmac");
    uint16_t pro = GetL3Hex(GetcValue("l3pro"));

    switch(vlNum) {
        case 0: BuildMacHeader (smac, dmac, htons(pro));
                break;
        case 1: vlan1 = GetiValue("vlan1");
                BuildMacHeader(smac, dmac, htons(VLAN));
                BuildVlanField(pVlanHdr1, htons(vlan1), htons(pro));
                RecordStatisticsInfo(EMPRO_VLAN);
                break;
        case 2: vlan1 = GetiValue("vlan1");
                vlan2 = GetiValue("vlan2");
                BuildMacHeader(smac, dmac, htons(VLAN));
                BuildVlanField(pVlanHdr1, htons(vlan1), htons(VLAN));
                BuildVlanField(pVlanHdr2, htons(vlan2), htons(pro));
                RecordStatisticsInfo(EMPRO_QinQ);

                break;
        default:LOGRECORD(ERROR, "VLAN number is wrong");
                break;
    }
}

void BuildLayer3Header()
{
    if (GetL3Hex(GetcValue("l3pro")) == IPv4) {
        BuildIpv4Header(inet_addr(GetcValue("sip")), 
            inet_addr(GetcValue("dip")), GetL4Hex(GetcValue("l4pro")));
    } else if (GetL3Hex(GetcValue("l3pro")) == ARP) {
        BuildArpHeader(GetcValue("smac"), GetcValue("dmac"), 
            inet_addr(GetcValue("sip")), inet_addr(GetcValue("dip")));
        RecordStatisticsInfo(EMPRO_ARP);
    } else {
        LOGRECORD(ERROR, "Protocol analysis is wrong");
    }
}

void BuildLayer4Header()
{
    char *p = GetcValue("l4pro");
    if (strcmp(p, "UDP") == 0) {
        BuildUdpHeader(GetiValue("sport"), GetiValue("dport"), GetiValue("pktlen"));
        RecordStatisticsInfo(EMPRO_UDP);
    } else if (strcmp(p, "TCP") == 0) {
        BuildTcpHeader(GetiValue("sport"), GetiValue("dport"), GetiValue("pktlen"));
        RecordStatisticsInfo(EMPRO_TCP);
    } else if (strcmp(p, "ICMPv4") == 0) {
        BuildIcmpv4Header();
        RecordStatisticsInfo(EMPRO_ICMPv4);
    } else {
        LOGRECORD(ERROR, "Layer 4 protocol is not found");
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

void BuildHttpDataContext(int paylen)
{
    char* pro = GetcValue("l7pro");
    char* url = GetcValue("url");
    char* uri = NULL;
    char* host = "";

    if (url == NULL) {
        char* fullUrl = GetUrlString();
        host = strtok(fullUrl, "/");
        uri = fullUrl + strlen(host) + 1;
    } else {
        host = strtok(url, "/");
        uri = strtok(NULL, "/");
    }

    char Http[BUFSIZ];
    memset(Http, 0, BUFSIZ);

    if (strcmp(pro, "HTTP-GET") == 0) {
        strcat(Http, "GET /");  
    } else if (strcmp(pro, "HTTP-POST") == 0) {
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
    strcat(Http, GetRandomCharactor(paylen - strlen(Http) - 4));
    strcat(Http, "\r\n\r\n");  
    memcpy(data, Http, strlen(Http));
    strcat(Http, uri);  
}

void BuildDataContexts(int paylen)
{
    int offset = GetiValue("offset");
    int strFlag = GetFlag("string");

    if (paylen < offset) {
        LOGRECORD(ERROR, "offset grate than payload length");
    } 

    if (strFlag == FG_RANDOM) {
        /*
        if (rule_str_len != 0 && rule_str_len < paylen) {
            paylen = rule_str_len;
        }
        */
        memcpy(data, GetRandomCharactor(paylen), paylen);
    } else if (strFlag == FG_FIXDATA) {
        char* pString = GetcValue("string");
        int sLength = strlen(pString);
        if (pString[0] == '0' && pString[1] == 'x') {
            char* stop;
            int sPosition=2;
            int dPosition = 0;
            while(sPosition < sLength) {
                data[offset+dPosition] = strtol(subs(pString, sPosition, 2), &stop, 16);
                sPosition += 2;
                dPosition += 1;
            }
        } else {
            memcpy(data+offset, pString, sLength);
        }
    }
}

void BuildLayer7Header()
{
    int paylen = 0;
    int vlNum = GetiValue("vlannum");
    int pktlen = GetiValue("pktlen");
    uint8_t l4pro = GetL4Hex(GetcValue("l4pro"));
    int l7flag = 1;
    
    char *pro = GetcValue("l7pro");
    if (pro == NULL) {
        l7flag = 0;
    }

    // *data initialization
    if (l4pro == UDP) {
        data = packet + UDPDATAOFFSET(vlNum);
        if (l7flag == 1 && strcmp(pro, "DNS") == 0) {
            pDnsHdr = (_dnshdr *) (packet+DNSOFFSET(vlNum));
            data = packet + DNSDATAOFFSET(vlNum);
            BuildDnsHeader();
            BuildDnsDataContext();
        } else {
            paylen = UDPPAYLEN(pktlen, vlNum);
            BuildDataContexts(paylen);
        }
    } else if (l4pro == TCP) {
        data = packet + TCPDATAOFFSET(vlNum);
        paylen = TCPPAYLEN(pktlen, vlNum);
        if (l7flag == 1  \
            && (strcmp(pro, "HTTP-GET")==0 \
            || strcmp(pro, "HTTP-POST")==0)) {
            BuildHttpDataContext(paylen);
        } else {
            BuildDataContexts(paylen);
        }
    } else if (l4pro == ICMPv4) {
        data = packet + ICMPv4DATAOFFSET(vlNum);
        paylen = ICMPv4PAYLEN(pktlen, vlNum);
        BuildDataContexts(paylen);
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
                iRuleNum, GetcValue("sip"), GetcValue("dip"), GetiValue("sport"), GetiValue("dport"),
                ChangeLayer4HexToString(l4_pro)) < 0) {
            LOGRECORD(ERROR, "write aclmask rules error");
        }
    } else if (strcmp(rule_tag, "aclex") == 0) {
        int offset = GetiValue("offset");
        if (dprintf(fd, "add ruleset test aclex %d "
                "action=drop, offset=%d, strkey=%s\n", 
                iRuleNum, offset, data+offset) < 0) {
            LOGRECORD(ERROR, "write aclex rules error");
        }
    } else if (strcmp(rule_tag, "mac_table") == 0) {
        if (dprintf(fd, "add mac_table %s "
                "action=forward, outgroup=1\n", GetcValue("smac")) < 0) {
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

void BuildPacket()
{
    int pktlen = PKTLEN;
    int iPcapFd = 0;
    int iLoopNum = 0;
    int counter = GetiValue("count");
    int interval = GetiValue("interval");

    LOGRECORD(DEBUG, "Build Packet start...");

    /* how to deal with packets */
    if (GetiValue("exec") == 0) { //send
        SendModeInitialization(GetcValue("interface"));
    } else { //save
        iPcapFd = WriteModeInitialization();
    }

    int fd = RuleModeInitialization();
    PacketStrcutureInitialization();

    /* build packet */
    while(!counter || iLoopNum<counter)
    {
        RefreshParameter();
        pktlen = GetiValue("pktlen");
        memset(packet, 0, sizeof(packet));

        if (GetiValue("exec") == 1) {
            BuildPacketHeader(GetiValue("pktlen"));
        }

        BuildLayer2Header();
        BuildLayer3Header();
        if (GetcValue("l4pro") != NULL) {
            BuildLayer4Header();
            BuildLayer7Header();
        }

        if (GetiValue("exec") == 0) {
            /* send packet to interface interface */
            SendPacketProcess(packet+PKTHDRLEN, pktlen);
        } else {
            /* write packet into a *.pcap file */
            if (write(iPcapFd, packet, pktlen+PKTHDRLEN) < 0) {
                LOGRECORD(ERROR, "write packet to pacp file error");
            }
        }
        /* display every packet for debug */
        if (GetiValue("debug")) {
            ShowParameter();
            DisplayPacketData(packet, pktlen+PKTHDRLEN);
        }

        if (strcmp(rule_tag,"other") != 0) {
            RulesGenerationEntrance(fd, iLoopNum);
        }

        /* time interval */
        usleep(interval);

        /* display program process */
        ProgramProcessingSchedule(++iLoopNum, counter);
    }//end of while
    printf("\n");

    LOGRECORD(DEBUG, "Build packets finished,num:%d", iLoopNum);

    if (GetiValue("debug")) {
        DisplayStatisticsResults();
    }

    if (GetiValue("exec") == 0) {
        LOGRECORD(INFO, "%d packets have been sent !", iLoopNum);
        CloseSendConnect();
    } else {
        CloseWriteMode(iPcapFd);
    }

    if (strcmp(rule_tag,"other") != 0) {
       CloseRuleMode(fd);
    }

    LOGRECORD(DEBUG, "Build Packet finished...");
}//end of 

