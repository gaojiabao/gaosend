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

int iStatisticCode = 0;
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

/* Layer seven protocol analysis */
void L7HdrInspection(int iSport, int iDport)
{
    if (iSport == 53 || iDport == 53) { // UDP
        iStatisticCode += EMPRO_L7_DNS;
    } else if (iDport == 25) { // TCP
        iStatisticCode += EMPRO_L7_SMTP;
    } else if (iSport == 80 || iDport == 80 
            || iSport == 8080 || iDport == 8080) {
        iStatisticCode += EMPRO_L7_HTTP;
    } else if (iDport == 110) {
        iStatisticCode += EMPRO_L7_POP3;
    } else if (iSport == 143 || iDport == 143) {
        iStatisticCode += EMPRO_L7_IMAP;
    } else if (iSport == 139 || iDport == 139 
            || iSport == 445 || iDport == 445) {
        iStatisticCode += EMPRO_L7_SMB;
    } else if (iSport == 20 || iDport == 20 
            || iSport == 21 || iDport == 21) {
        iStatisticCode += EMPRO_L7_FTP;
    }
}

/* Layer four protocol analysis */
void L4HdrInspection(U16 iL3Pro, U8 iL4Pro)
{
    char * pL4Hdr =  stPkt.pPacket + stInfo.iCursor;

    if (iL4Pro == TCP) {
        stPkt.pTcpHdr = (_tcphdr *) pL4Hdr;
        stInfo.iCursor += ((stPkt.pTcpHdr->hdrlen >> 4) * 4);
        if (GetNum("flow") && iL3Pro == IPv4) {
            int iTcpDataLen = htons(stPkt.pIp4Hdr->ttlen) 
                - (stPkt.pIp4Hdr->hdlen * 4)
                - ((stPkt.pTcpHdr->hdrlen >> 4) * 4);
            // TCP flow check
            char iFiveTupleSum[32];
            sprintf(iFiveTupleSum, "%d", stPkt.pIp4Hdr->sip 
                    + stPkt.pIp4Hdr->dip + stPkt.pTcpHdr->sport 
                    + stPkt.pTcpHdr->dport + stPkt.pIp4Hdr->pro);
            StreamStorage(iFiveTupleSum, stPkt.pTcpHdr, iTcpDataLen);
        } 

        // PacketProcessing();
        iStatisticCode += EMPRO_L4_TCP * 100;
        L7HdrInspection(htons(stPkt.pTcpHdr->sport), 
                htons(stPkt.pTcpHdr->dport));
    } else if (iL4Pro == UDP) {
        stInfo.iCursor += UDP_HDR_LEN;
        stPkt.pUdpHdr = (_udphdr *) pL4Hdr;
        iStatisticCode += EMPRO_L4_UDP * 100;
        L7HdrInspection(htons(stPkt.pUdpHdr->sport), 
                htons(stPkt.pUdpHdr->dport));
    } else if (iL4Pro == ICMP4) {
        stPkt.pIcmp4Hdr = (_icmp4hdr *) pL4Hdr;
        iStatisticCode += EMPRO_L4_ICMP4 * 100;
    } else if (iL4Pro == ICMP6) {
        //stPkt.pIcmp6Hdr = (_icmp6hdr *) pL4Hdr;
        iStatisticCode += EMPRO_L4_ICMP6 * 100;
    } else {
        iStatisticCode += EMPRO_L4_OTHER * 100;
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
        iStatisticCode += EMPRO_L3_IPv4 * 10000;
        L4HdrInspection(pro, iPro);
    } else if (pro == VLAN) {
        stInfo.iCursor += VLAN_TAG_LEN;
        if (stInfo.iCursor == (MAC_HDR_LEN + VLAN_TAG_LEN)) { // VLAN
            stPkt.pVlanHdr = (_vlanhdr *) pL3Hdr;
            iPro = L3HdrInspection(htons(stPkt.pVlanHdr->pro));
            iStatisticCode += EMPRO_L3_VLAN * 1000;
        } else if (stInfo.iCursor == (MAC_HDR_LEN + VLAN_TAG_LEN*2)) { // QinQ
            stPkt.pQinQHdr = (_vlanhdr *) pL3Hdr;
            iPro = L3HdrInspection(htons(stPkt.pQinQHdr->pro));
            iStatisticCode += EMPRO_L3_QinQ * 1000;
        } 
    } else if (pro == ARP) {
        stPkt.pArpHdr = (_arphdr *) pL3Hdr;
        iStatisticCode += EMPRO_L3_ARP * 10000;
    } else if (pro == IPv6) {
        stInfo.iCursor += IP6_HDR_LEN;
        stPkt.pIp6Hdr = (_ip6hdr *) pL3Hdr;
        iPro = stPkt.pIp6Hdr->pro;
        L4HdrInspection(pro, iPro);
        iStatisticCode += EMPRO_L3_IPv6 * 10000;
    } else {
        iStatisticCode = EMPRO_L3_OTHER * 10000;
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
    iStatisticCode = 0;

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

int GetStatisticCode()
{
    return iStatisticCode;
}

