/*
 *  Author   : Mr Gao
 *
 *  Function : To define some default varibles and program default configure.
 */

#ifndef __DEFAULT_H__
#define __DEFAULT_H__

// Define protocol length
#define PCAP_HDR_LEN   24
#define PKT_HDR_LEN    16
#define MAC_HDR_LEN    14
#define ARP_HDR_LEN    16
#define VLAN_TAG_LEN   4
#define IP4_HDR_LEN    20
#define IP6_HDR_LEN    40
#define ICMP4_HDR_LEN  8  
#define UDP_HDR_LEN    8
#define TCP_HDR_LEN    20
#define DNS_HDR_LEN    12
#define PSEUDO_HDR_LEN 12
#define PKT_MIN_LEN    54
#define PKT_MAX_LEN    1518

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
#define SIP            "10.10.169.4"
#define DIP            "10.10.169.5"
#define SMAC           "00:23:76:00:00:01"
#define DMAC           "00:23:76:00:00:02"
#define VLANID         4000
#define SPORT          1024
#define DPORT          2048
#define PKTLEN         100
#define PROTOCOL       "udp"
#define INTERFACE      "lo"
#define OFFSET         0
#define INTERVAL       0    
#define COUNT          1
#define RULENUM        1
#define PCAPFILE       "temp.pcap"
#define ACLNMASKFILE   "aclnmask.cfg"
#define ACLEXFILE      "aclex.cfg"
#define MACTABLEFILE   "mac_table.cfg"
#define L2PRO          "ethernet"
#define VERSION        "v4.9.6"

#endif

