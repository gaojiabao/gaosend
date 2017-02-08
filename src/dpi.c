#include    <unistd.h>
#include    "auth.h"
#include    "runlog.h"
#include    "common.h"
#include    "socket.h"
#include    "storage.h"
#include    "statistic.h"

#define     ON   1 // Switch ON
#define     OFF  0 // Switch OFF

static int  iCursor = 0;
/* Packet structure */
static stPktStrc stPkt;

void ModifyPacket(stPktStrc);
void ExtractMessage(char*, int );


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
    static char cPcapHdrBuf[PCAPHDRLEN];
    stPkt.pPcapHdr = (_pcaphdr*) cPcapHdrBuf;
    
    if (read(iReadFd, stPkt.pPcapHdr, PCAPHDRLEN) < 0) {
        LOGRECORD(ERROR, "Pcap header read failed");
    }

    if (htonl(stPkt.pPcapHdr->magic) != 0xd4c3b2a1) {
        LOGRECORD(ERROR, "File format not supported");
    }
    // ExtractMessage(stPkt.pPcapHdr, PCAPHDRLEN);
}

/* Message header information analysis */
int PktHdrInspection(int iReadFd)
{
    static char cPktHdrBuf[PKTHDRLEN];
    stPkt.pPktHdr = (_pkthdr*) cPktHdrBuf;
    if (read(iReadFd, stPkt.pPktHdr, PKTHDRLEN) < 1) {
        LOGRECORD(DEBUG, "Data has been read finished");
        return -1;
    }

    return stPkt.pPktHdr->len;
}

/* Layer four protocol analysis */
void L4HdrInspection(U8 pro)
{
    char * pL4Hdr =  stPkt.pPacket + iCursor;

    if (pro == TCP) {
        iCursor += TCPHDRLEN;
        stPkt.pTcpHdr = (_tcphdr *) pL4Hdr;
        // TCP flow check
        if(GetiValue("flow") == ON) {
            char iFiveTupleSum[32];
            sprintf(iFiveTupleSum, "%d", stPkt.pIp4Hdr->srcip + stPkt.pIp4Hdr->dstip
                + stPkt.pTcpHdr->sport + stPkt.pTcpHdr->dport + stPkt.pIp4Hdr->protocol);
            StoreStreamInfo(MD5Digest(iFiveTupleSum));
        }

        // PacketProcessing();
        RecordStatisticsInfo(EMPRO_TCP);
        StatisticUpperTcp(htons(stPkt.pTcpHdr->sport), htons(stPkt.pTcpHdr->dport));
    } else if (pro == UDP) {
        iCursor += UDPHDRLEN;
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
    char * pL3Hdr =  stPkt.pPacket + iCursor;

    if (pro == IPv4) {
        iCursor += IP4HDRLEN;
        stPkt.pIp4Hdr = (_ip4hdr *) pL3Hdr;
        iPro = stPkt.pIp4Hdr->protocol;
        RecordStatisticsInfo(EMPRO_IPv4);
        L4HdrInspection(iPro);
    } else if (pro == VLAN) {
        iCursor += VLANTAGLEN;
        if (iCursor == MACHDRLEN+VLANTAGLEN) { // VLAN layer 1
            stPkt.pVlanHdr = (_vlanhdr *) pL3Hdr;
            iPro = L3HdrInspection(htons(stPkt.pVlanHdr->pro));
            RecordStatisticsInfo(EMPRO_VLAN);
        } else if (iCursor == MACHDRLEN+VLANTAGLEN*2){ // VLAN layer 2
            stPkt.pQinQHdr = (_vlanhdr *) pL3Hdr;
            iPro = L3HdrInspection(htons(stPkt.pQinQHdr->pro));
            RecordStatisticsInfo(EMPRO_QinQ);
        } 
    } else if (pro == ARP) {
        stPkt.pArpHdr = (_arphdr *) pL3Hdr;
        RecordStatisticsInfo(EMPRO_ARP);
    } else if (pro == IPv6) {
        iCursor += IP6HDRLEN;
        stPkt.pIp6Hdr = (_ip6hdr *) pL3Hdr;
        iPro = stPkt.pIp6Hdr->protocol;
        RecordStatisticsInfo(EMPRO_IPv6);
        L4HdrInspection(iPro);
    } else {
        RecordStatisticsInfo(EMPRO_L3OTHER);
    }

    return iPro;
}

/* Layer two protocol analysis */
void L2HdrInspection()
{
    stPkt.pMacHdr = (_machdr *) (stPkt.pPacket + iCursor);
    iCursor += MACHDRLEN;
    L3HdrInspection(htons(stPkt.pMacHdr->pro));
}

/* Extracting data message */
void PacketProcessing()
{
    static int iNum = ON;
    if (iNum == ON) {
        ExtractMessage((char*)stPkt.pPcapHdr, PCAPHDRLEN);
        iNum = OFF;
    }
    ExtractMessage((char*)stPkt.pPktHdr, PKTHDRLEN);
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

    int iPktLen = 0;
    while ((iPktLen = PktHdrInspection(iReadFd)) > 0) {
        if (read(iReadFd, stPkt.pPacket, iPktLen) < 0) {
            LOGRECORD(ERROR, "Pcap header read failed");
        }
        
        PacketPraseEntrance();
        iCursor = 0;
    } // end of while

    close(iReadFd);
}

/* Deep packet inspection portal */
void DeepPacketInspection()
{
    static char cPacketBuf[SIZE_1K*2];
    stPkt.pPacket = cPacketBuf;

    if (GetiValue("exec") == 0) {
        SendModeInitialization();
    }

    // Turn on flow assoition
    if(GetiValue("flow") == ON) {
        CreateStreamStorage();
    }

    PcapFilePraseEntrance();

    if (GetiValue("entrance") == 105) {
        DisplayStatisticsResults();
    }

    if (GetiValue("flow") == ON) {
        DisplayAllStreamMD5();
    }

    if (GetiValue("exec") == 0) {
        CloseSendConnect();
    }
}

