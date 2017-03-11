#include    <unistd.h>
#include    "func.h"
#include    "runlog.h"
#include    "common.h"
#include    "storage.h"
#include    "statistic.h"

#define     ON   1 // Switch ON
#define     OFF  0 // Switch OFF

#define     PKTBUFLEN   SIZE_1K*2

/* Packet structure */
static stPktStrc stPkt;
static stPktInfo stInfo;

void ModifyPacket(stPktStrc);
void ExtractMessage(char*, int );


void StreamStorageInit();
void StreamStorage(const char*, _tcphdr*, int);
void DisplayStreamStorage();

/* Packet structure pointer Initialization */
void PacketStrcInit()
{
    stPkt.pMacHdr  = NULL;
    stPkt.pArpHdr  = NULL;
    stPkt.pVlanHdr = NULL;
    stPkt.pQinQHdr = NULL;
    stPkt.pIp4Hdr  = NULL;
    stPkt.pIp6Hdr  = NULL;
    stPkt.pUdpHdr  = NULL;
    stPkt.pTcpHdr  = NULL;
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

    if (htonl(stPkt.pPcapHdr->magic) != 0xd4c3b2a1) {
        LOGRECORD(ERROR, "File format not supported");
    }
    // ExtractMessage(stPkt.pPcapHdr, PCAP_HDR_LEN);
}

/* Message header information analysis */
int PktHdrInspection(int iReadFd)
{
    static char cPktHdrBuf[PKT_HDR_LEN];
    stPkt.pPktHdr = (_pkthdr*) cPktHdrBuf;
    if (read(iReadFd, stPkt.pPktHdr, PKT_HDR_LEN) < 1) {
        LOGRECORD(DEBUG, "Data has been read finished");
        return -1;
    }

    return stPkt.pPktHdr->len;
}

/* Layer four protocol analysis */
void L4HdrInspection(U8 pro)
{
    char * pL4Hdr =  stPkt.pPacket + stInfo.iCursor;

    if (pro == TCP) {
        stPkt.pTcpHdr = (_tcphdr *) pL4Hdr;
        stInfo.iCursor += ((stPkt.pTcpHdr->hdrlen >> 4) * 4);
        int iTcpDataLen = htons(stPkt.pIp4Hdr->total_len) 
            - (stPkt.pIp4Hdr->ver_len & 0x0f) * 4
            - ((stPkt.pTcpHdr->hdrlen >> 4) * 4);
        // TCP flow check
        if(GetiValue("flow") == ON) {
            char iFiveTupleSum[32];
            sprintf(iFiveTupleSum, "%d", stPkt.pIp4Hdr->sip 
                + stPkt.pIp4Hdr->dip + stPkt.pTcpHdr->sport 
                + stPkt.pTcpHdr->dport + stPkt.pIp4Hdr->protocol);
            StreamStorage(iFiveTupleSum, stPkt.pTcpHdr, iTcpDataLen);
        }

        // PacketProcessing();
        RecordStatisticsInfo(EMPRO_TCP);
        StatisticUpperTcp(htons(stPkt.pTcpHdr->sport), htons(stPkt.pTcpHdr->dport));
    } else if (pro == UDP) {
        stInfo.iCursor += UDP_HDR_LEN;
        stPkt.pUdpHdr = (_udphdr *) pL4Hdr;
        RecordStatisticsInfo(EMPRO_UDP);
        StatisticUpperUdp(htons(stPkt.pUdpHdr->sport), htons(stPkt.pUdpHdr->dport));  
    } else if (pro == ICMP4) {
        stPkt.pIcmp4Hdr = (_icmp4hdr *) pL4Hdr;
        RecordStatisticsInfo(EMPRO_ICMP4);
    } else if (pro == ICMP6) {
        stPkt.pIcmp4Hdr = (_icmp4hdr *) pL4Hdr;
    } else {
        RecordStatisticsInfo(EMPRO_L4OTHER);
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
        iPro = stPkt.pIp4Hdr->protocol;
        RecordStatisticsInfo(EMPRO_IPv4);
        L4HdrInspection(iPro);
    } else if (pro == VLAN) {
        stInfo.iCursor += VLAN_TAG_LEN;
        if (stInfo.iCursor == MAC_HDR_LEN+VLAN_TAG_LEN) { // VLAN layer 1
            stPkt.pVlanHdr = (_vlanhdr *) pL3Hdr;
            iPro = L3HdrInspection(htons(stPkt.pVlanHdr->pro));
            RecordStatisticsInfo(EMPRO_VLAN);
        } else if (stInfo.iCursor == MAC_HDR_LEN+VLAN_TAG_LEN*2){ // VLAN layer 2
            stPkt.pQinQHdr = (_vlanhdr *) pL3Hdr;
            iPro = L3HdrInspection(htons(stPkt.pQinQHdr->pro));
            RecordStatisticsInfo(EMPRO_QinQ);
        } 
    } else if (pro == ARP) {
        stPkt.pArpHdr = (_arphdr *) pL3Hdr;
        RecordStatisticsInfo(EMPRO_ARP);
    } else if (pro == IPv6) {
        stInfo.iCursor += IP6_HDR_LEN;
        stPkt.pIp6Hdr = (_ip6hdr *) pL3Hdr;
        iPro = stPkt.pIp6Hdr->protocol;
        RecordStatisticsInfo(EMPRO_IPv6);
        //L4HdrInspection(iPro);
    } else {
        RecordStatisticsInfo(EMPRO_L3OTHER);
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

/* Extracting data message */
void PacketProcessing()
{
    static int iNum = ON;
    if (iNum == ON) {
        ExtractMessage((char*)stPkt.pPcapHdr, PCAP_HDR_LEN);
        iNum = OFF;
    }
    ExtractMessage((char*)stPkt.pPktHdr, PKT_HDR_LEN);
    ExtractMessage((char*)stPkt.pPacket, stPkt.pPktHdr->len);
}

/* Data content resolution portal */
void PacketPraseEntrance()
{
    LOGRECORD(DEBUG, "Deep packet inspection start...");

    PacketStrcInit();
    L2HdrInspection();

    // Modify check
    if (GetiValue("entrance") == 106) {
        ModifyPacket(stPkt);
        if (GetcValue("save") != NULL) { // Save packet
            PacketProcessing();
        } else { // Send packet
            SendPacketProcess(stPkt.pPacket, stPkt.pPktHdr->len);
        }
    } else if (GetiValue("entrance") == 110) {
        SendPacketProcess(stPkt.pPacket, stPkt.pPktHdr->len);
    }

    LOGRECORD(DEBUG, "Deep packet inspection finished...");
}

/* Pcap file resolution portal */
void PcapFilePraseEntrance()
{
    int  iReadFd = OpenReadFile(GetcValue("read"));
    
    PcapHdrInspection(iReadFd);

    int iPktNum = 1;
    stInfo.iPktLen = 0;
    while ((stInfo.iPktLen = PktHdrInspection(iReadFd)) > 0) {
        if (stInfo.iPktLen > PKTBUFLEN) {
            LOGRECORD(ERROR, "Overlength packet[%d:%d]", iPktNum, stInfo.iPktLen);
        }
        if (read(iReadFd, stPkt.pPacket, stInfo.iPktLen) < 0) {
            LOGRECORD(ERROR, "Pcap header read failed");
        }
        PacketPraseEntrance();
        stInfo.iCursor = 0;
        iPktNum++;
    } // end of while

    close(iReadFd);
}

/* Deep packet inspection portal */
void DeepPacketInspection()
{
    static char cPacketBuf[PKTBUFLEN];
    stPkt.pPacket = cPacketBuf;

    // Turn on flow assoition
    if(GetiValue("flow") == ON) {
        StreamStorageInit();
    }

    PcapFilePraseEntrance();

    if (GetiValue("entrance") == 105) {
        DisplayStatisticsResults();
    }

    if (GetiValue("flow") == ON) {
        DisplayStreamStorage();
    }

    if (GetiValue("exec") == 0) {
        CloseSendConnect();
    }
}

