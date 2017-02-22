/*
 *  Author   : Mr Gao
 *
 *  Function : To define some default varibles and program default configure.
 */

#ifndef __DEFAULT_H__
#define __DEFAULT_H__

// Define protocol length
#define PCAPHDRLEN     24
#define PKTHDRLEN      16
#define MACHDRLEN      14
#define ARPHDRLEN      16
#define POSHDRLEN      4
#define VLANTAGLEN     4
#define IP4HDRLEN      20
#define IP6HDRLEN      40
#define ICMP4HDRLEN    8  
#define UDPHDRLEN      8
#define TCPHDRLEN      20
#define DNSHDRLEN      12
#define PSEUDOHDRLEN   12
#define PKTMINLEN      64 
#define PKTMAXLEN      1518

// Define MD5 character length
#define MD5LEN         16

// Define protocol number
#define ARP            0x0806
#define IPv4           0x0800
#define IPv6           0x86dd
#define VLAN           0x8100
#define UDP            0x11
#define TCP            0x06
#define ICMP4          0x01
#define ICMP6          0x3a

// Define default file permissions
#define PERM           644

// Define default coufigure
#define PACKETLEN      2000
#define SIP            "10.10.169.4"
#define DIP            "10.10.169.5"
#define SMAC           "00:23:76:00:00:01"
#define DMAC           "00:23:76:00:00:02"
#define VLANID         4032
#define SPORT          1024
#define DPORT          2048
#define PKTLEN         64
#define PROTOCOL       "udp"
#define INTERFACE      "lo"
#define INTERVAL       0    
#define COUNT          1
#define RULENUM        1
#define MODE           "1"
#define OFFSET         0
#define STRLEN         10
#define PCAPFILE       "temp.pcap"
#define ACLNMASKFILE   "aclnmask.cfg"
#define ACLEXFILE      "aclex.cfg"
#define MACTABLEFILE   "mac_table.cfg"
#define L2PRO          "ethernet"
#define VERSION        "v4.9.2"

#endif

