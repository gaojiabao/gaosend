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
#include	"socket.h"
#include	"list.h"

extern _machdr*  mac_hdr;
extern _vlanhdr* vlan_hdr1;
extern _vlanhdr* vlan_hdr2;
extern _arphdr*  arp_hdr;
extern _ip4hdr*  ip4_hdr;
extern _udphdr*  udp_hdr;
extern _tcphdr*  tcp_hdr;
extern _pcaphdr* pcap_hdr;
extern _pkthdr*  pkt_hdr;

char  packet[PACKETLEN];

void PktStrucInit(int vlNum)
{
	pcap_hdr = (_pcaphdr*) packet;
	pkt_hdr = (_pkthdr*) packet;
	mac_hdr = (_machdr *) (packet + MACOFFSET);
	vlan_hdr1 = (_vlanhdr *)(packet + VLAN1OFFSET);
	vlan_hdr2 = (_vlanhdr *)(packet + VLAN2OFFSET);
	arp_hdr = (_arphdr *) (packet + ARPOFFSET(vlNum));
	ip4_hdr = (_ip4hdr *) (packet + IPOFFSET(vlNum));
	udp_hdr = (_udphdr *) (packet + UDPOFFSET(vlNum));
	tcp_hdr = (_tcphdr *) (packet + TCPOFFSET(vlNum));
}

void AnalysePacket()
{
	int fdin;
	int vlNum = GetiValue("vlannum");
	char* file = GetcValue("readfile");

	LOGRECORD(DEBUG, "Analyse Packet start...");

	PktStrucInit(vlNum);
	memset(packet,0,sizeof(packet));

	if((fdin = open(file, O_RDWR)) < 0) {
		LOGRECORD(ERROR, "open pcap file error");
	}
	if(read(fdin, packet, PCAPHDRLEN) < 0) {
		LOGRECORD(ERROR, "read pcaphdr error");
	}
	if(htonl(pcap_hdr->magic) != 0xd4c3b2a1) {
		LOGRECORD(ERROR, "file paratarn error");
	}

	while(read(fdin, packet, PKTHDRLEN) > 1) {
		if(read(fdin, packet+PKTHDRLEN, pkt_hdr->len) < 0) {
			LOGRECORD(ERROR, "read packethdr error");
			exit(0);
		}
		ParameterUpadte();

		if(htons(mac_hdr->pro2) == VLAN) {
			RecordStatisticsInfo(EMPRO_VLAN);
			PktStrucInit(1);
			if(htons(vlan_hdr1->type) == VLAN) {
				RecordStatisticsInfo(EMPRO_QinQ);
				PktStrucInit(2);
			}
		}

		if(htons(mac_hdr->pro2) == ARP) {
			RecordStatisticsInfo(EMPRO_ARP);
		} else if(htons(mac_hdr->pro2) == IPv4 || htons(vlan_hdr1->type) == IPv4 \
					|| htons(vlan_hdr2->type) == IPv4) { // Layer 3
			RecordStatisticsInfo(EMPRO_IPv4);
			if(ip4_hdr->protocol == UDP) { // Layer 4
				RecordStatisticsInfo(EMPRO_UDP);
			} else if(ip4_hdr->protocol == TCP) { // Layer 4
				RecordStatisticsInfo(EMPRO_TCP);
			} else if(ip4_hdr->protocol == ICMPv4) { // Layer 4
				RecordStatisticsInfo(EMPRO_ICMPv4);
			}
		}
		/*
		   else if(htons(mac_hdr->pro2) == IPv6) { // Layer 3
		   RecordStatisticsInfo(EMPRO_IPv6);
		   if(ip6_hdr->protocol == TCP) { // Layer 4
		   RecordStatisticsInfo(EMPRO_TCP);
		   } else if(ip6_hdr->protocol == UDP) { // Layer 4
		   RecordStatisticsInfo(EMPRO_UDP);
		   } else if(ip6_hdr->protocol == ICMPv6) { // Layer 4
		   RecordStatisticsInfo(EMPRO_ICMPv6);
		   } else {
		   RecordStatisticsInfo(EMPRO_UNKNOWN);
		   }
		   } 
		   */
	}// end of while

	close(fdin);
	DisplayStatisticsResults();
	LOGRECORD(DEBUG, "Analyse Packet finished...");
}

