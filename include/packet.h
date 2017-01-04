/*
 *  author   : Mr. Gao
 *
 *  function : To define different layer packet header structure.
 */

#ifndef __PACKET_H__
#define __PACKET_H__

#include    <fcntl.h>
#include    <stdlib.h>
#include    <arpa/inet.h>
#include    <linux/if.h>

typedef uint32_t U32;
typedef uint16_t U16;
typedef uint8_t  U8;

typedef struct pcaphdr
{
    U32    magic;
    U16    major;
    U16    minor;
    U32    thiszone;
    U32    sigflags;
    U32    snaplen;
    U32    linktype;
}_pcaphdr;

typedef struct pkthdr
{
    U32    htimestamp;
    U32    ltimestamp;
    U32    caplen;
    U32    len;
}_pkthdr;

typedef struct pseudohdr{
    U32    srcip;
    U32    dstip;
    U8     flag;
    U8     protocol;
    U16    len;
}_pseudohdr;

typedef struct machdr {
    U8     dmac[6];
    U8     smac[6];
    U16    pro2;
}_machdr;

typedef struct vlanhdr {
    U16    vlan_id;
    U16    type;
}_vlanhdr;

typedef struct arphdr {
    U16    hrd;
    U16    pro;
    U8     len;
    U8     plen;
    U16    option;
    U8     smac[6];
    U32    sip;
    U8     dmac[6];
    U32    dip;
}__attribute__((packed)) _arphdr;

typedef struct ip4hdr {
    U8     ver_len;
    U8     tos;
    U16    total_len;
    U16    ident;
    U16    flag_offset;
    U8     ttl;
    U8     protocol;
    U16    checksum;
    U32    srcip;    
    U32    dstip;
}_ip4hdr;

typedef struct ip6hdr {
    U32    version:4,
           traffic:8,
           flowLabel:20;
    U16    payload;
    U8     protocol;
    U8     nextHop;
    U8     sip[sizeof(struct in6_addr)];
    U8     dip[sizeof(struct in6_addr)];
}__attribute__((packed)) _ip6hdr;

typedef struct icmphdr {
    U8     type;
    U8     code;
    U16    checksum;
    U16    identifier;
    U16    seq;
}_icmphdr;

typedef struct udphdr {
    U16    sport;
    U16    dport;
    U16    len;
    U16    checksum;
}_udphdr;

typedef struct tcphdr {
    U16    sport;
    U16    dport;
    U32    seq;
    U32    ack;
    U8     hdrlen;
    U8     flag;
    U16    win;
    U16    checksum;
    U16    urg;
}_tcphdr;

typedef struct dns{
    U16    tid;
    U16    flag;
    U16    que;
    U16    anrrs;
    U16    aurrs;
    U16    adrrs;
}_dnshdr;

#endif

