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
typedef int32_t  S32;
typedef uint16_t U16;
typedef int16_t  S16;
typedef uint8_t  U8;
typedef int8_t   S8;

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
    U32    sip;
    U32    dip;
    U8     flag;
    U8     protocol;
    U16    len;
}_pseudohdr;

typedef struct machdr {
    U8     dmac[6];
    U8     smac[6];
    U16    pro;
}_machdr;

typedef struct vlanhdr {
    U16    id;
    U16    pro;
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
    U8     hdlen:4,
           version:4;
    U8     tos;
    U16    ttlen;
    U16    ident;
    U16    flag_offset;
    U8     ttl;
    U8     protocol;
    U16    checksum;
    U32    sip;    
    U32    dip;
}_ip4hdr;

typedef struct ip6hdr {
/*
    U32    version:4,
           traffic:8,
           flowLabel:20;
            */
    U32    version;
    U16    payload;
    U8     protocol;
    U8     nextHop;
    U8     sip[sizeof(struct in6_addr)];
    U8     dip[sizeof(struct in6_addr)];
}__attribute__((packed)) _ip6hdr;

typedef struct icmp4hdr {
    U8     type;
    U8     code;
    U16    checksum;
    U16    identifier;
    U16    seq;
}_icmp4hdr;

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
    U16    hdrlen:8,
           flag:8;
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

typedef struct pkt{
    char*        pPacket;
    _pcaphdr*    pPcapHdr;
    _pkthdr*     pPktHdr;
    _machdr*     pMacHdr;
    _arphdr*     pArpHdr;
    _vlanhdr*    pVlanHdr;
    _vlanhdr*    pQinQHdr;
    _ip4hdr*     pIp4Hdr;
    _ip6hdr*     pIp6Hdr;
    _udphdr*     pUdpHdr;
    _tcphdr*     pTcpHdr;
    _icmp4hdr*   pIcmp4Hdr;
    char*        pData;
}stPktStrc;

typedef struct info{
    int iCursor;
    int iPktLen;
    U16 iUpperPro;
}stPktInfo;

#endif

