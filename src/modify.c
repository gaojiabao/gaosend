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
#include    "storage.h"
#include    "socket.h"

/* packet structure */
extern _pcaphdr*    pPcapHdr;
extern _pkthdr*     pPktHdr;
extern _machdr*     pMacHdr;
extern _vlanhdr*    pVlanHdr1;
extern _vlanhdr*    pVlanHdr2;
extern _arphdr*     pArpHdr;
extern _ip4hdr*     pIp4Hdr;
extern _udphdr*     pUdpHdr;
extern _tcphdr*     pTcpHdr;
extern _icmphdr*    pIcmpHdr;

char packet[1518];
extern void BuildVlanField(_vlanhdr*, uint16_t, uint16_t);

#define SRC 0 
#define DST 1

/* init packet struct */
void PktStrcInit(int vlnum)
{
printf("vlan num:%d\n", vlnum);
    int iVlanCount    = vlnum;
    pPcapHdr    = (_pcaphdr*) packet;
    pPktHdr     = (_pkthdr*) packet;
    pMacHdr     = (_machdr *) (packet + MACOFFSET);
    pVlanHdr1   = (_vlanhdr *)(packet + VLAN1OFFSET);
    pVlanHdr2   = (_vlanhdr *)(packet + VLAN2OFFSET);
    pArpHdr     = (_arphdr *) (packet + ARPOFFSET(iVlanCount));
    pIp4Hdr     = (_ip4hdr *) (packet + IP4OFFSET(iVlanCount));
    pIcmpHdr  = (_icmphdr *)(packet + ICMP4OFFSET(iVlanCount));
    pUdpHdr     = (_udphdr *) (packet + UDPOFFSET(iVlanCount));
    pTcpHdr     = (_tcphdr *) (packet + TCPOFFSET(iVlanCount));

    LOGRECORD(DEBUG, "Packet strcuture initialization finished");
}

void RegularExpress(uint32_t a, uint32_t b)
{
    static uint32_t ip1;
    static uint32_t ip2;
    static int i = 0;
    if (i == 0) {
        ip1 = pIp4Hdr->srcip;
        ip2 = pIp4Hdr->dstip;
        i++;
    }
    if (pIp4Hdr->srcip == ip1 && pIp4Hdr->dstip == ip2) {
        pIp4Hdr->srcip = a;
        pIp4Hdr->dstip = b;
    } else {
        pIp4Hdr->srcip = b;
        pIp4Hdr->dstip = a;
    }
}

int IsNeedModify(char* title)
{    
    int iResNum = 0;
    if (GetFlag(title) > 1) { // need modify
        iResNum = 1;
    }

    return iResNum;
}

void ModifyMacAddress(char* title, int isSrcMac) //smac:0,dmac:1
{
    char* pMac = NULL;
    pMac = isSrcMac ? (char*)&pMacHdr->dmac : (char*)&pMacHdr->smac;

    switch(GetFlag(title)) {
        case FG_FIXDATA: mac_type_change(GetcValue(title), pMac); break;
        case FG_RANDOM : mac_type_change(GetRandomMacAddress(isSrcMac), pMac); break;
        case FG_INCR   : mac_type_change(GetIncreaseMacAddress(isSrcMac), pMac); break;
    }
}

void ModifyVlanNumber(char* title, int isFirstVlan) //vlan1:0,vlan2:1
{
    uint16_t vlanId = 0;

    switch(GetFlag(title)) {
        case FG_FIXDATA: vlanId = htons(GetiValue(title)); break;
        case FG_RANDOM : vlanId = htons(GetRandomVlan(isFirstVlan)); break;
        case FG_INCR   : vlanId = htons(GetIncreaseVlan(isFirstVlan)); break;
    }

    isFirstVlan ? (pVlanHdr2->vlan_id = vlanId) : (pVlanHdr1->vlan_id = vlanId);
}

void InsertVlanHeader()
{
    memcpy(packet+PKTHDRLEN+MACHDRLEN+VLANLEN, \
        packet+PKTHDRLEN+MACHDRLEN, pPktHdr->len-MACHDRLEN);
    BuildVlanField(pVlanHdr1, htons(100), pMacHdr->pro2);
    pMacHdr->pro2 = htons(VLAN);
    pPktHdr->len += VLANLEN;
    pPktHdr->caplen += VLANLEN;
}

void ModifyIpAddress(char* title, int isSrcIp) //sip:0,dip:1
{
    int iCheckRes = 0;
    char* pIp = NULL;
    uint32_t ipaddr = 0;
    switch(GetFlag(title)) {
        case FG_FIXDATA: pIp = GetcValue(title);
                         iCheckRes = CheckIpLegal(pIp);
                         if (iCheckRes == SUCCESS) ipaddr = inet_addr(pIp);
                         else if (iCheckRes == FALSE) LOGRECORD(ERROR, "Illegal IP Address !");
                         break;
        case FG_RANDOM : ipaddr = inet_addr(GetRandomIpAddress(isSrcIp)); break;
        case FG_INCR   : ipaddr = inet_addr(GetIncreaseIpAddress(isSrcIp)); break;
    }

    if (iCheckRes == 2) {
        char* pTmpSpace = malloc(strlen(pIp));
        memcpy(pTmpSpace, pIp, strlen(pIp));
        char *pOriginalIp = strtok(pTmpSpace, ":");
        char *pReplaceIp  = strtok(NULL, ":");

        if (isSrcIp) {
            if (pIp4Hdr->dstip == inet_addr(pOriginalIp))
                pIp4Hdr->dstip =  inet_addr(pReplaceIp); 
        } else {
            if (pIp4Hdr->srcip == inet_addr(pOriginalIp)) {
                pIp4Hdr->srcip =  inet_addr(pReplaceIp); 
            }
        } 
        free(pTmpSpace);
    } else if (iCheckRes == SUCCESS) {
        isSrcIp ? (pIp4Hdr->dstip = ipaddr) : (pIp4Hdr->srcip = ipaddr);
    }
}

void ModifyPortNumber(char* title, uint8_t pro, int isSrcPort) //sport:0,dport:1
{
    uint16_t port = 0;
    switch(GetFlag(title)) {
        case FG_FIXDATA: port = htons(GetiValue(title)); break;
        case FG_RANDOM : port = htons(GetRandomPort()); break;
        case FG_INCR   : port = htons(GetIncreasePort(isSrcPort)); break;
    }

    if (pro == UDP) {
        isSrcPort ? (pUdpHdr->dport = port) : (pUdpHdr->sport = port);
    } else if (pro == TCP) {
        isSrcPort ? (pTcpHdr->dport = port) : (pTcpHdr->sport = port);
    }
}

int GetVlanNum()
{
    int iVlanNum = 0;
    if (htons(pMacHdr->pro2) == VLAN) {
        iVlanNum++;
        if (htons(pVlanHdr1->type == VLAN)) {
            iVlanNum++;
        }
    }
    return iVlanNum;
}

void ModifyLayer2()
{
    int iVlanNum = GetVlanNum();
    if (IsNeedModify("smac")) ModifyMacAddress("smac", SRC);
    if (IsNeedModify("dmac")) ModifyMacAddress("dmac", DST);
    PktStrcInit(iVlanNum);

    if (IsNeedModify("vlan1")) {
        if (htons(pMacHdr->pro2) == VLAN) {
            ModifyVlanNumber("vlan1", 0);
        } else {
            InsertVlanHeader();
            PktStrcInit(1);
        }
    }

    if (IsNeedModify("vlan2")) {
        if (iVlanNum > 0) {
            if (htons(pVlanHdr1->type == VLAN)) {
                ModifyVlanNumber("vlan2", 0);
            } else {
                InsertVlanHeader();
            }
        } else {
            LOGRECORD(INFO, "QinQ has nothing to do");
        }
    }

}

void ModifyLayer3(uint16_t pro)
{
    if (pro == ARP) {
        LOGRECORD(INFO, "ARP Nothing to perform");
    } else if (pro == IPv4) { 
        if (IsNeedModify("sip")) ModifyIpAddress("sip", SRC);
        if (IsNeedModify("dip")) ModifyIpAddress("dip", DST);
    } else {
        LOGRECORD(INFO, "Layer3 Nothing to perform");
    } 
    /*
    else if (pro == IPv6) { // Layer 3
        unsigned char buf1[sizeof(struct in6_addr)];
        unsigned char buf2[sizeof(struct in6_addr)];
        if (sip_tag) {
            pIp4Hdr->srcip = inet_pton(AF_INET6, sip, buf1);
            BufferCopy(packetbuf, 32, buf1, sizeof(struct in6_addr));
        }
        if (dip_tag) {
            pIp4Hdr->dstip = inet_pton(AF_INET6, dip, buf2);
            BufferCopy(packetbuf, 48, buf2, sizeof(struct in6_addr));
        }
        if (ip6_hdr->protocol == TCP) { // Layer 4
            if (sport_tag) pTcpHdr->sport = htons(sport);
            if (dport_tag) pTcpHdr->dport = htons(dport);
        }else if (ip6_hdr->protocol == UDP) { // Layer 4
            if (sport_tag) pUdpHdr->sport = htons(sport);
            if (dport_tag) pUdpHdr->dport = htons(dport);
        }else if (ip6_hdr->protocol == ICMPv6) { // Layer 4
            printf("ICMPv6 Nothing to perform\n");
        } else {
            printf("ALL Nothing to perform\n");
        }
    } 
    */

}

void ModifyLayer4(uint8_t pro)
{
    if (pro == UDP || pro == TCP) { 
        if (IsNeedModify("sport")) ModifyPortNumber("sport", pro, SRC);
        if (IsNeedModify("dport")) ModifyPortNumber("dport", pro, DST);
    } else if (pro == ICMPv4) { 
        LOGRECORD(INFO, "ICMP Nothing to perform");
    }
}

uint16_t GetL3Protocol()
{
    uint16_t l3pro;
    if (htons(pMacHdr->pro2) == VLAN) {
        if (htons(pVlanHdr1->type == VLAN)) {
            l3pro = pVlanHdr2->type;
        } else {
            l3pro = pVlanHdr1->type;
        }
    } else {
        l3pro = pMacHdr->pro2;
    }

    return l3pro;
}

void ErrorHanding(int fdin, int fdout, char* filename)
{
    close(fdin);
    close(fdout);
    remove(filename);
    LOGRECORD(DEBUG, "ErrorHanding finished !");

}

void ModifyPacket()
{
    int iFdRead = 0; 
    int iFdSave = 0; 

    PktStrcInit(GetiValue("vlannum"));
    //PktStrcInit(1);
    if (GetiValue("debug")) {
        ShowParameter();
    }

    /* how to deal with packets */
    if (GetiValue("exec") == 0) { //send
        SendModeInitialization(GetcValue("interface"));
    } else { //save
        if ((iFdSave = open(GetcValue("savefile"), O_RDWR | O_CREAT, PERM)) < 0) {
            LOGRECORD(ERROR, "open result.pcap error");
        }
    }

    memset(packet, 0, sizeof(packet));

    if ((iFdRead = open(GetcValue("readfile"), O_RDWR)) < 0) {
        LOGRECORD(ERROR, "open pcap file error");
    }
    if (read(iFdRead, packet, PCAPHDRLEN) < 0) {
        LOGRECORD(ERROR, "read pcaphdr error");
    }
    if (htonl(pPcapHdr->magic) != 0xd4c3b2a1) {
        LOGRECORD(ERROR, "file paratarn error");
    }

    if (GetiValue("exec") == 1) { //save
        if (write(iFdSave, packet, PCAPHDRLEN) < 0) {
            LOGRECORD(ERROR, "read pcaphdr error");
        }
    }

    memset(packet, 0, sizeof(packet));

    LOGRECORD(DEBUG, "Modify packet start...");

    while(read(iFdRead, packet, PKTHDRLEN) > 1 ) 
    {
        if (read(iFdRead, packet+PKTHDRLEN, pPktHdr->len) < 0) {
            LOGRECORD(ERROR, "read packethdr error");
            exit(0);
        }

        RefreshParameter();

        ModifyLayer2();
        ModifyLayer3(htons(GetL3Protocol()));
        ModifyLayer4(pIp4Hdr->protocol);

        //////////////
        //RegularExpress(sipTmp, dipTmp);

        if (GetiValue("exec") == 0) { //send
            SendPacketProcess(packet+PKTHDRLEN, pPktHdr->len);
        } else {
            //DisplayPacketData(packet, pPktHdr->len+PKTHDRLEN);
            if (write(iFdSave, packet, pPktHdr->len+PKTHDRLEN) < 0) {
                LOGRECORD(ERROR, "write packetbuf error");
            }
        }
    }// end of while

    LOGRECORD(DEBUG, "Modify packet finished...");

    if (GetiValue("exec") == 0) { //send
        CloseSendConnect();
    } else {
        close(iFdSave);
    }

    close(iFdRead);
}

/* change ipv6 address */
/*
void chgip6(char* file)
{
    int fdin,fdout;
    char* result = "result.pcap";
    if ((fdin = open(file,O_RDWR)) < 0) {
        perror("open error");
        exit(0);
    }
    if ((fdout = open(result, O_RDWR | O_CREAT, PERM)) < 0) {
        perror("open error");
        exit(0);
    }
    char pcapbuf[24];
    if (read(fdin,pcapbuf,24) < 0) {
        perror("read pcaphdr error !");
        exit(0);
    }
    if (write(fdout,pcapbuf,24) < 0) {
        perror("write error !");
        exit(0);
    }

    int num = 0;
    char pktbuf[16];
    while(read(fdin,pktbuf,16)) {
        _pkthdr* pPktHdr = (_pkthdr*)pktbuf;
        if (write(fdout,pktbuf,16) < 0) {
            perror("write error !");
            exit(0);
        }

        char macbuf[14];
        if (read(fdin,macbuf,14) < 0) {
            perror("read pcaphdr error !");
            exit(0);
        }
        if (write(fdout,macbuf,14) < 0) {
            perror("write error !");
            exit(0);
        }

        unsigned char ipbuf[40];
        if (read(fdin,ipbuf,40) < 0) {
            perror("read pcaphdr error !");
            exit(0);
        }
        unsigned char buf1[sizeof(struct in6_addr)];
        unsigned char buf2[sizeof(struct in6_addr)];
        unsigned char buf1_temp[sizeof(struct in6_addr)];
//      unsigned char buf2_temp[sizeof(struct in6_addr)];

        inet_pton(AF_INET6,"2400:fe00:f000:0601::29",buf1);
        inet_pton(AF_INET6,"2100:fe00:f000:0601::30",buf2);
        unsigned int i;
        //copy
        if (num++ == 0) {
            for(i=0;i<sizeof(struct in6_addr);i++) {
                buf1_temp[i] = ipbuf[8+i];
            }
            /////////////////////////////////
            for(i=0;i<sizeof(struct in6_addr);i++) {
                buf2_temp[i] = temp4[24+i];
            }
            /////////////////////////////////
        }
        //_ip6hdr* ip6_hdr = (_ip6hdr*)ipbuf;
        //matching
        if (CompareIpv6Address(ipbuf,buf1_temp)) {
            //amend
            for(i=0;i<sizeof(struct in6_addr);i++) {
                ipbuf[8+i]=buf1[i];
            }
            for(i=0;i<sizeof(struct in6_addr);i++) {
                ipbuf[24+i]=buf2[i];
            }
        
        } else {
            //amend
            for(i=0;i<sizeof(struct in6_addr);i++) {
                ipbuf[8+i]=buf2[i];
            }
            for(i=0;i<sizeof(struct in6_addr);i++) {
                ipbuf[24+i]=buf1[i];
            }
        
        }

        if (write(fdout,ipbuf,40) < 0) {
            perror("write error !");
            exit(0);
        }
        int datalen =  pPktHdr->len - 14 - 40;
        char databuf[1518];
        if (read(fdin,databuf,datalen) < 0) {
            perror("read pcaphdr error !");
            exit(0);
        }
        if (write(fdout,databuf,datalen) < 0) {
            perror("write error !");
            exit(0);
        }
    }

    close(fdin);
    close(fdout);
    exit(0);
}
*/
