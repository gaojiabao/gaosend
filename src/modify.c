#include    <time.h>
#include    <stdio.h> 
#include    <stdlib.h>
#include	<fcntl.h>
#include	<unistd.h>
#include    <string.h>
#include	<sys/time.h>
#include    "packet.h"
#include    "default.h"
#include    "function.h"
#include    "structure.h"
#include    "statistic.h"
#include    "runlog.h"
#include	"list.h"
#include	"socket.h"

/* packet structure */
extern _machdr*  mac_hdr;
extern _vlanhdr* vlan_hdr1;
extern _vlanhdr* vlan_hdr2;
extern _arphdr*  arp_hdr;
extern _ip4hdr*  ip4_hdr;
extern _udphdr*  udp_hdr;
extern _tcphdr*  tcp_hdr;
extern _pcaphdr* pcap_hdr;
extern _pkthdr*  pkt_hdr;

char packet[1518];
extern void BuildVlanField(_vlanhdr*, uint16_t, uint16_t);

/* init packet struct */
void PktStrcInit(int num)
{
	int vlNum	= num;
	pcap_hdr	= (_pcaphdr*) packet;
	pkt_hdr     = (_pkthdr*) packet;
	mac_hdr     = (_machdr *) (packet + MACOFFSET);
	vlan_hdr1   = (_vlanhdr *)(packet + VLAN1OFFSET);
	vlan_hdr2   = (_vlanhdr *)(packet + VLAN2OFFSET);
	arp_hdr     = (_arphdr *) (packet + ARPOFFSET(vlNum));
	ip4_hdr     = (_ip4hdr *) (packet + IPOFFSET(vlNum));
	//icmp_hdr  = (_icmphdr *)(packet + ICMPv4OFFSET(vlNum));
	udp_hdr     = (_udphdr *) (packet + UDPOFFSET(vlNum));
	tcp_hdr     = (_tcphdr *) (packet + TCPOFFSET(vlNum));

	LOGRECORD(DEBUG, "Packet strcuture initialization finished");
}

void RegularExpress(uint32_t a, uint32_t b)
{
	static uint32_t ip1;
	static uint32_t ip2;
	static int i = 0;
	if(i == 0) {
		ip1 = ip4_hdr->srcip;
		ip2 = ip4_hdr->dstip;
		i++;
	}
	if(ip4_hdr->srcip == ip1 && ip4_hdr->dstip == ip2) {
		ip4_hdr->srcip = a;
		ip4_hdr->dstip = b;
	} else {
		ip4_hdr->srcip = b;
		ip4_hdr->dstip = a;
	}
}

int IsNeedModify(char* title)
{	
	int res = 0;
	if(GetFlag(title) >= 3) {
		res = 1;
	}

	return res;
}

void ModifyMacAddress(char* title, int flag)
{
	char* pMac = NULL;
	if(flag == 0) {
		pMac = (char*)&mac_hdr->smac;
	} else if(flag == 1) {
		pMac = (char*)&mac_hdr->dmac;
	}

	switch(GetFlag(title) % 3) {
		case 0: mac_type_change(GetcValue(title), pMac); break;
		case 1: mac_type_change(GetRandomMacAddress(flag), pMac); break;
		case 2: mac_type_change(GetIncreaseMacAddress(flag), pMac); break;
		default: LOGRECORD(ERROR, "Mac switch error!");
	}
}

void ModifyVlanNumber(char* title, int flag)
{
	uint16_t vlanId = 0;

	switch(GetFlag(title) % 3) {
		case 0: vlanId = htons(GetiValue(title)); break;
		case 1: vlanId = htons(GetRandomVlan(flag)); break;
		case 2: vlanId = htons(GetIncreaseVlan(flag)); break;
		default: LOGRECORD(ERROR, "Vlan Number switch error!");
	}

	if(flag == 0) {
		vlan_hdr1->vlan_id = vlanId;
	} else if(flag == 1) {
		vlan_hdr2->vlan_id = vlanId;
	}
}

void InsertVlanHeader()
{
	memcpy(packet+PKTHDRLEN+MACHDRLEN+VLANLEN, \
				packet+PKTHDRLEN+MACHDRLEN, pkt_hdr->len-MACHDRLEN);
	BuildVlanField(vlan_hdr1, htons(100), mac_hdr->pro2);
	mac_hdr->pro2 = htons(VLAN);
	pkt_hdr->len += VLANLEN;
	pkt_hdr->caplen += VLANLEN;
}

void ModifyIpAddress(char* title, int flag)
{
	uint32_t ipaddr = 0;
	switch(GetFlag(title) % 3) {
		case 0: ipaddr = inet_addr(GetcValue(title)); break;
		case 1: ipaddr = inet_addr(GetRandomIpAddress(flag)); break;
		case 2: ipaddr = inet_addr(GetIncreaseIpAddress(flag)); break;
		default: LOGRECORD(ERROR, "Ip switch error!");
	}

	if(flag == 0) {
		ip4_hdr->srcip = ipaddr;
	} else if(flag == 1) {
		ip4_hdr->dstip = ipaddr;
	}
}

void ModifyPortNumber(char* title, uint8_t pro, int flag)
{
	uint16_t port = 0;
	switch(GetFlag(title) % 3) {
		case 0: port = htons(GetiValue(title)); break;
		case 1: port = htons(GetRandomPort()); break;
		case 2: port = htons(GetIncreasePort(flag)); break;
		default: LOGRECORD(ERROR, "switch error!");
	}

	if(pro == UDP && flag == 0) {
		udp_hdr->sport = port;
	} else if(pro == UDP && flag == 1) {
		udp_hdr->dport = port;
	} else if(pro == TCP && flag == 0) {
		tcp_hdr->sport = port;
	} else if(pro == TCP && flag == 1) {
		tcp_hdr->dport = port;
	}
}

int GetVlanNum()
{
	int vlanNum = 0;
	if(htons(mac_hdr->pro2) == VLAN) {
		vlanNum++;
		if(htons(vlan_hdr1->type == VLAN)) {
			vlanNum++;
		}
	}
	return vlanNum;
}

void ModifyLayer2()
{
	int vlanNum = GetVlanNum();
	if(IsNeedModify("smac")) ModifyMacAddress("smac", 0);
	if(IsNeedModify("dmac")) ModifyMacAddress("dmac", 1);
	PktStrcInit(vlanNum);
	if(IsNeedModify("vlan1")) {
		if(htons(mac_hdr->pro2) == VLAN) {
			ModifyVlanNumber("vlan1", 0);
		} else {
			InsertVlanHeader();
			PktStrcInit(1);
		}
	}

	if(IsNeedModify("vlan2")) {
		if(vlanNum > 0) {
			if(htons(vlan_hdr1->type == VLAN)) {
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
	if(pro == ARP) {
		LOGRECORD(INFO, "ARP Nothing to perform");
	} else if(pro == IPv4) { 
		if(IsNeedModify("sip")) ModifyIpAddress("sip", 0);
		if(IsNeedModify("dip")) ModifyIpAddress("dip", 1);
	} else {
		LOGRECORD(INFO, "Layer3 Nothing to perform");
	} 
	/*
	   else if(pro == IPv6) { // Layer 3
	   unsigned char buf1[sizeof(struct in6_addr)];
	   unsigned char buf2[sizeof(struct in6_addr)];
	   if(sip_tag) {
	   ip4_hdr->srcip = inet_pton(AF_INET6, sip, buf1);
	   memPcpy(packetbuf, 32, buf1, sizeof(struct in6_addr));
	   }
	   if(dip_tag) {
	   ip4_hdr->dstip = inet_pton(AF_INET6, dip, buf2);
	   memPcpy(packetbuf, 48, buf2, sizeof(struct in6_addr));
	   }
	   if(ip6_hdr->protocol == TCP) { // Layer 4
	   if(sport_tag) tcp_hdr->sport = htons(sport);
	   if(dport_tag) tcp_hdr->dport = htons(dport);
	   }else if(ip6_hdr->protocol == UDP) { // Layer 4
	   if(sport_tag) udp_hdr->sport = htons(sport);
	   if(dport_tag) udp_hdr->dport = htons(dport);
	   }else if(ip6_hdr->protocol == ICMPv6) { // Layer 4
	   printf("ICMPv6 Nothing to perform\n");
	   } else {
	   printf("ALL Nothing to perform\n");
	   }
	   } 
	   */

}

void ModifyLayer4(uint8_t pro)
{
	if(pro == UDP || pro == TCP) { 
		if(IsNeedModify("sport")) ModifyPortNumber("sport", pro, 0);
		if(IsNeedModify("dport")) ModifyPortNumber("dport", pro, 1);
	} else if(pro == ICMPv4) { 
		LOGRECORD(INFO, "ICMP Nothing to perform");
	}
}

uint16_t GetL3Protocol()
{
	uint16_t l3pro;
	if(htons(mac_hdr->pro2) == VLAN) {
		if(htons(vlan_hdr1->type == VLAN)) {
			l3pro = vlan_hdr2->type;
		} else {
			l3pro = vlan_hdr1->type;
		}
	} else {
		l3pro = mac_hdr->pro2;
	}

	return l3pro;
}

void ModifyPacket()
{
	int fdin = 0; 
	int fdout = 0; 
	///////////////
	uint32_t sipTmp = inet_addr(GetRandomIpAddress(0));
	uint32_t dipTmp = inet_addr(GetRandomIpAddress(1));

	PktStrcInit(GetiValue("vlannum"));

	/* how to deal with packets */
	if(GetiValue("exec") == 0) { //send
		SendModeInitialization(GetcValue("interface"));
	} else { //save
		if((fdout = open(GetcValue("savefile"), O_RDWR | O_CREAT, PERM)) < 0) {
			LOGRECORD(ERROR, "open result.pcap error");
		}
	}

	memset(packet,0,sizeof(packet));

	if((fdin = open(GetcValue("readfile"), O_RDWR)) < 0) {
		LOGRECORD(ERROR, "open pcap file error");
	}
	if(read(fdin, packet, PCAPHDRLEN) < 0) {
		LOGRECORD(ERROR, "read pcaphdr error");
	}
	if(htonl(pcap_hdr->magic) != 0xd4c3b2a1) {
		LOGRECORD(ERROR, "file paratarn error");
	}

	if(GetiValue("exec") == 1) { //save
		if(write(fdout, packet, PCAPHDRLEN) < 0) {
			LOGRECORD(ERROR, "read pcaphdr error");
		}
	}

	memset(packet,0,sizeof(packet));

	while(read(fdin, packet, PKTHDRLEN) > 1) 
	{
		if(read(fdin, packet+PKTHDRLEN, pkt_hdr->len) < 0) {
			LOGRECORD(ERROR, "read packethdr error");
			exit(0);
		}
		//DisplayPacketData(packet, pkt_hdr->len+PKTHDRLEN);

		ParameterUpadte();

		ModifyLayer2();
		ModifyLayer3(htons(GetL3Protocol()));
		ModifyLayer4(ip4_hdr->protocol);

		//////////////
		RegularExpress(sipTmp, dipTmp);

		if(GetiValue("exec") == 0) { //send
			SendPacketProcess(packet+PKTHDRLEN, pkt_hdr->len);
		} else {
			//DisplayPacketData(packet, pkt_hdr->len+PKTHDRLEN);
			if(write(fdout, packet, pkt_hdr->len+PKTHDRLEN) < 0) {
				LOGRECORD(ERROR, "write packetbuf error");
			}
		}
	}// end of while

	if(GetiValue("exec") == 0) { //send
		CloseSendConnect();
	} else {
		close(fdout);
	}

	close(fdin);
}

/* change ipv6 address */
/*
   void chgip6(char* file)
   {
   int fdin,fdout;
   char* result = "result.pcap";
   if((fdin = open(file,O_RDWR)) < 0){
   perror("open error");
   exit(0);
   }
   if((fdout = open(result, O_RDWR | O_CREAT, PERM)) < 0){
   perror("open error");
   exit(0);
   }
   char pcapbuf[24];
   if(read(fdin,pcapbuf,24) < 0){
   perror("read pcaphdr error !");
   exit(0);
   }
   if(write(fdout,pcapbuf,24) < 0){
   perror("write error !");
   exit(0);
   }

   int num = 0;
   char pktbuf[16];
   while(read(fdin,pktbuf,16)){
   _pkthdr* pkt_hdr = (_pkthdr*)pktbuf;
   if(write(fdout,pktbuf,16) < 0){
   perror("write error !");
   exit(0);
   }

   char macbuf[14];
   if(read(fdin,macbuf,14) < 0){
   perror("read pcaphdr error !");
   exit(0);
   }
   if(write(fdout,macbuf,14) < 0){
   perror("write error !");
   exit(0);
   }

   unsigned char ipbuf[40];
   if(read(fdin,ipbuf,40) < 0){
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
if(num++ == 0){
for(i=0;i<sizeof(struct in6_addr);i++){
buf1_temp[i] = ipbuf[8+i];
}
/////////////////////////////////
for(i=0;i<sizeof(struct in6_addr);i++){
buf2_temp[i] = temp4[24+i];
}
/////////////////////////////////
}
//_ip6hdr* ip6_hdr = (_ip6hdr*)ipbuf;
//matching
if(compare(ipbuf,buf1_temp)){
//amend
for(i=0;i<sizeof(struct in6_addr);i++){
ipbuf[8+i]=buf1[i];
}
for(i=0;i<sizeof(struct in6_addr);i++){
	ipbuf[24+i]=buf2[i];
}

}else{
	//amend
	for(i=0;i<sizeof(struct in6_addr);i++){
		ipbuf[8+i]=buf2[i];
	}
	for(i=0;i<sizeof(struct in6_addr);i++){
		ipbuf[24+i]=buf1[i];
	}

}

if(write(fdout,ipbuf,40) < 0){
	perror("write error !");
	exit(0);
}
int datalen =  pkt_hdr->len - 14 - 40;
char databuf[1518];
if(read(fdin,databuf,datalen) < 0){
	perror("read pcaphdr error !");
	exit(0);
}
if(write(fdout,databuf,datalen) < 0){
	perror("write error !");
	exit(0);
}
}

close(fdin);
close(fdout);
exit(0);
}
*/
