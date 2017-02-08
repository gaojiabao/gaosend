/*
 *  author   : Mr. Gao
 *
 *  function : To deal with packet structure.
 */

#ifndef __STRUCTURE_H__
#define __STRUCTURE_H__

/* Layer 2 */
#define MACOFFSET   PKTHDRLEN
#define VLAN1OFFSET (MACOFFSET + MACHDRLEN)
#define VLAN2OFFSET (VLAN1OFFSET + VLANTAGLEN)

/* Layer 3 */
#define ARPOFFSET(n)  (MACOFFSET + MACHDRLEN + n*VLANTAGLEN)
#define IP4OFFSET(n)  (MACOFFSET + MACHDRLEN + n*VLANTAGLEN)
#define IP6OFFSET(n)  (MACOFFSET + MACHDRLEN + n*VLANTAGLEN)

/* Layer 4 */
#define ICMP4OFFSET(n)     (IP4OFFSET(n) + IP4HDRLEN)
#define UDPOFFSET(n)       (IP4OFFSET(n) + IP4HDRLEN)
#define TCPOFFSET(n)       (IP4OFFSET(n) + IP4HDRLEN)
#define ICMP4DATAOFFSET(n) (ICMP4OFFSET(n) + ICMP4HDRLEN)

/* Layer 7 */
#define UDPDATAOFFSET(n)    (UDPOFFSET(n) + UDPHDRLEN)
#define TCPDATAOFFSET(n)    (TCPOFFSET(n) + TCPHDRLEN)
#define ICMP4DATAOFFSET(n)  (ICMP4OFFSET(n) + ICMP4HDRLEN)
#define DNSOFFSET(n)        (UDPOFFSET(n) + UDPHDRLEN)
#define DNSDATAOFFSET(n)    (DNSOFFSET(n) + DNSHDRLEN)
//date
#define UDPPAYLEN(pkt_len, n)   (pkt_len - UDPDATAOFFSET(n))
#define TCPPAYLEN(pkt_len, n)   (pkt_len - TCPDATAOFFSET(n))
#define ICMP4PAYLEN(pkt_len, n) (pkt_len - ICMP4DATAOFFSET(n))

#endif

