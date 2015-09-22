/*
 *  author   : Mr. Gao
 *
 *  function : To define different layer packet header structure.
 */

#ifndef __PACKET_H__
#define __PACKET_H__

#include	<fcntl.h>
#include	<stdlib.h>
#include	<arpa/inet.h>
#include	<linux/if.h>

typedef struct pcaphdr
{
	uint32_t	magic;
    uint16_t	major;
    uint16_t	minor;
	uint32_t	thiszone;
    uint32_t	sigflags;
	uint32_t	snaplen;
    uint32_t	linktype;
}_pcaphdr;

typedef struct pkthdr
{
	uint32_t	htimestamp;
    uint32_t	ltimestamp;
	uint32_t	caplen;
    uint32_t	len;
}_pkthdr;

typedef struct pseudohdr{
    uint32_t	srcip;
    uint32_t	dstip;
    uint8_t		flag;
    uint8_t		protocol;
    uint16_t	len;
}_pseudohdr;


typedef struct machdr {
    unsigned char	dmac[6];
    unsigned char	smac[6];
    uint16_t		pro2;
}_machdr;

typedef struct vlanhdr {
    uint16_t	vlan_id;
    uint16_t	type;
}_vlanhdr;

typedef struct arphdr {
	uint16_t	hrd;
	uint16_t	pro;
	uint8_t		len;
	uint8_t		plen;
	uint16_t	option;
	unsigned char	smac[6];
	uint32_t	sip;
	unsigned char	dmac[6];
	uint32_t	dip;
}__attribute__((packed)) _arphdr;

typedef struct ip4hdr {
    uint8_t		ver_len;
    uint8_t		tos;
    uint16_t	total_len;
    uint16_t	ident;
    uint16_t	flag_offset;
    uint8_t		ttl;
    uint8_t		protocol;
    uint16_t	checksum;
    uint32_t	srcip;    
    uint32_t	dstip;
}_ip4hdr;

typedef struct ip6hdr {
	uint32_t	version:4,
				traffic:8,
				flowLabel:20;
	uint16_t	payload;
	uint8_t		protocol;
	uint8_t		nextHop;
	unsigned char	sip[sizeof(struct in6_addr)];
	unsigned char	dip[sizeof(struct in6_addr)];
}__attribute__((packed)) _ip6hdr;

typedef struct icmphdr {
    uint8_t		type;
    uint8_t		code;
    uint16_t	checksum;
    uint16_t	identifier;
    uint16_t	seq;
}_icmphdr;

typedef struct udphdr {
    uint16_t	sport;
    uint16_t	dport;
    uint16_t	len;
    uint16_t	checksum;
}_udphdr;

typedef struct tcphdr {
    uint16_t	sport;
    uint16_t	dport;
    uint32_t	seq;
    uint32_t	ack;
    uint8_t 	hdrlen;
    uint8_t 	flag;
    uint16_t	win;
    uint16_t	checksum;
    uint16_t	urg;
}_tcphdr;

typedef struct dns{
    uint16_t	tid;
    uint16_t	flag;
    uint16_t	que;
    uint16_t	anrrs;
    uint16_t	aurrs;
    uint16_t	adrrs;
}_dnshdr;

#endif

