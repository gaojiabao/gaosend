/*******************************************************
 *
 *  Author        : Mr.Gao
 *  Email         : 729272771@qq.com
 *  Filename      : dpi.c
 *  Last modified : 2017-04-25 14:10
 *  Description   : Deep packet inspect
 *
 * *****************************************************/


#include    <unistd.h>
#include    <string.h>
#include    "runlog.h"
#include    "common.h"
#include    "storage.h"
#include    "statistic.h"


#define     PKTBUFLEN   SIZE_1K*10

/* Packet structure */
stPktStrc stPkt;
stPktInfo stInfo;

void StreamStorage(const char*, _tcphdr*, int);

/* Packet structure pointer Initialization */
void PacketStrcInit()
{
    stPkt.pMacHdr   = NULL;
    stPkt.pArpHdr   = NULL;
    stPkt.pVlanHdr  = NULL;
    stPkt.pQinQHdr  = NULL;
    stPkt.pIp4Hdr   = NULL;
    stPkt.pIp6Hdr   = NULL;
    stPkt.pUdpHdr   = NULL;
    stPkt.pTcpHdr   = NULL;
    stPkt.pIcmp4Hdr = NULL;
    stPkt.pIcmp6Hdr = NULL;
}

/* Pcap file header parsing */
void PcapHdrInspection(int iReadFd)
{
    static char cPcapHdrBuf[PCAP_HDR_LEN];
    stPkt.pPcapHdr = (_pcaphdr*) cPcapHdrBuf;

    if (read(iReadFd, stPkt.pPcapHdr, PCAP_HDR_LEN) < 0) {
        LOGRECORD(ERROR, "Pcap header read failed");
    }
    if (stPkt.pPcapHdr->magic != htonl(0xd4c3b2a1)) {
        LOGRECORD(ERROR, "File format not supported");
    }
}

/* Message header information analysis */
int PktHdrInspection(int iReadFd)
{
    static char cPktHdrBuf[PKT_HDR_LEN];
    stPkt.pPktHdr = (_pkthdr*) cPktHdrBuf;

    if (read(iReadFd, stPkt.pPktHdr, PKT_HDR_LEN) < 1) {
        return -1;
    }

    return stPkt.pPktHdr->len;
}

/* Layer four protocol analysis */
void L4HdrInspection(U16 iL3Pro, U8 iL4Pro)
{
    char * pL4Hdr =  stPkt.pPacket + stInfo.iCursor;

    if (iL4Pro == TCP) {
        stPkt.pTcpHdr = (_tcphdr *) pL4Hdr;
        stInfo.iCursor += ((stPkt.pTcpHdr->hdrlen >> 4) * 4);
    } else if (iL4Pro == UDP) {
        stInfo.iCursor += UDP_HDR_LEN;
        stPkt.pUdpHdr = (_udphdr *) pL4Hdr;
    } else if (iL4Pro == ICMP4) {
        stPkt.pIcmp4Hdr = (_icmp4hdr *) pL4Hdr;
    } else if (iL4Pro == ICMP6) {
        stPkt.pIcmp6Hdr = (_icmp6hdr *) pL4Hdr;
    }
}

/* Layer three protocol analysis */
U8 L3HdrInspection(U16 pro)
{
    U8 iPro = 0;
    char * pL3Hdr =  stPkt.pPacket + stInfo.iCursor;

    if (pro == IPv4) {
        stInfo.iCursor += IP4_HDR_LEN;
        stPkt.pIp4Hdr = (_ip4hdr *) pL3Hdr;
        iPro = stPkt.pIp4Hdr->pro;
        L4HdrInspection(pro, iPro);
    } else if (pro == VLAN) {
        stInfo.iCursor += VLAN_TAG_LEN;
        if (stInfo.iCursor == (MAC_HDR_LEN + VLAN_TAG_LEN)) { // VLAN
            stPkt.pVlanHdr = (_vlanhdr *) pL3Hdr;
            iPro = L3HdrInspection(htons(stPkt.pVlanHdr->pro));
        } else if (stInfo.iCursor == (MAC_HDR_LEN + VLAN_TAG_LEN*2)) { // QinQ
            stPkt.pQinQHdr = (_vlanhdr *) pL3Hdr;
            iPro = L3HdrInspection(htons(stPkt.pQinQHdr->pro));
        } 
    } else if (pro == ARP) {
        stPkt.pArpHdr = (_arphdr *) pL3Hdr;
    } else if (pro == IPv6) {
        stInfo.iCursor += IP6_HDR_LEN;
        stPkt.pIp6Hdr = (_ip6hdr *) pL3Hdr;
        iPro = stPkt.pIp6Hdr->pro;
        L4HdrInspection(pro, iPro);
    }

    return iPro;
}

/* Layer two protocol analysis */
void L2HdrInspection()
{
    stPkt.pMacHdr = (_machdr *) (stPkt.pPacket + stInfo.iCursor);
    stInfo.iCursor += MAC_HDR_LEN;
    L3HdrInspection(htons(stPkt.pMacHdr->pro));
}

/* Data content resolution portal */
void PacketInspection(int iReadFd)
{
    static char cPacketBuf[PKTBUFLEN];
    stPkt.pPacket = cPacketBuf;

    stInfo.iCursor = 0;
    memset(cPacketBuf, 0, PKTBUFLEN);
    if (read(iReadFd, stPkt.pPacket, stInfo.iPktLen) < 0) {
        LOGRECORD(ERROR, "Pcap header read failed");
    }

    PacketStrcInit();
    L2HdrInspection();
}

/* Deep packet inspection portal */
int DeepPacketInspection()
{
    static int  iReadFd = 0;
    int iPktNum = 1;

    if (iReadFd < 3) {
        iReadFd = OpenReadFile(GetStr("read"));
        PcapHdrInspection(iReadFd);
    }

    if ((stInfo.iPktLen = PktHdrInspection(iReadFd)) > 0) {
        if (stInfo.iPktLen > PKTBUFLEN) {
            LOGRECORD(ERROR, "Overlength packet[%d:%d]",
                    iPktNum, stInfo.iPktLen);
        }
        PacketInspection(iReadFd);
        iPktNum ++;
    } else {
        if (close(iReadFd) < 0) {
            LOGRECORD(ERROR, "Pcap file close failed");
        }
        iReadFd = 0;
    }

    return stInfo.iPktLen;
}

stPktStrc GetPktStrc()
{
    return stPkt;
}

