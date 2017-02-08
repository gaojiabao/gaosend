/*
 *  Author   : Mr. Gao
 *
 *  Function : To construct a data message and save or send 
 *
 */

#include    <unistd.h>
#include    <string.h>
#include    <sys/time.h>
#include    "common.h"
#include    "statistic.h"
#include    "socket.h"
#include    "runlog.h"
#include    "storage.h"

/* Packet structure */
static stPktStrc stPkt;
static stPktInfo stInfo;


/* Constructing pcap header used to identify file type */
void BuildPcapHeader()
{
    static char cPcapHdrBuf[PCAPHDRLEN];
    stPkt.pPcapHdr = (_pcaphdr *)cPcapHdrBuf;

    stPkt.pPcapHdr->magic = htonl(0xd4c3b2a1);
    stPkt.pPcapHdr->major = 2;
    stPkt.pPcapHdr->minor = 4;
    stPkt.pPcapHdr->thiszone = 0;
    stPkt.pPcapHdr->sigflags = 0;
    stPkt.pPcapHdr->snaplen = 1518;
    stPkt.pPcapHdr->linktype = 1;
}

/* Constructing packet header used to identify packet information */
void BuildPacketHeader()
{
    static char cPktHdrBuf[PKTHDRLEN];
    stPkt.pPktHdr = (_pkthdr *)cPktHdrBuf;

    struct timeval tp;
    gettimeofday(&tp, NULL);
    stPkt.pPktHdr->htimestamp = tp.tv_sec;
    stPkt.pPktHdr->ltimestamp = tp.tv_usec;
    stPkt.pPktHdr->caplen = stInfo.iPktLen;
    stPkt.pPktHdr->len = stInfo.iPktLen;
}

/* Constructing a pseudo header for calculating checksum */
U16* BuildPseduoPacket(void* pData, U8 iL4Pro, int iL4Len)
{
    // Build pseudo header
    static char cPseudoPacket[PACKETLEN];
    _pseudohdr* pPseudoHdr = (_pseudohdr *)cPseudoPacket;
    pPseudoHdr->srcip = stPkt.pIp4Hdr->srcip;
    pPseudoHdr->dstip = stPkt.pIp4Hdr->dstip;
    pPseudoHdr->flag = 0;
    pPseudoHdr->protocol = iL4Pro;
    pPseudoHdr->len = htons(iL4Len);

    // Build pseudo packet data
    char *pPseudoData = cPseudoPacket + PSEUDOHDRLEN;
    memcpy(pPseudoData, pData, iL4Len);
    
    return (U16 *)cPseudoPacket;
}

/* Write mode initialization for saving data */
int WriteModeInitialization()
{
    int iSaveFd = OpenSaveFile(GetcValue("save"));;

    BuildPcapHeader();
    
    if (iSaveFd < 0) {
        LOGRECORD(ERROR, "File doesn't exist");
    }
    if (write(iSaveFd, stPkt.pPcapHdr, PCAPHDRLEN) < 0 ) {
        LOGRECORD(ERROR, "Failed to write pcap-file");
    }
    if (GetiValue("debug")) {
        DisplayPacketData((char *)stPkt.pPcapHdr, PCAPHDRLEN);
    }

    return iSaveFd;
}

/* Constructing ethernet data header */
void BuildMacHeader()
{
    stPkt.pMacHdr = (_machdr *)(stPkt.pPacket + stInfo.iCursor);

    FillInMacAddr(GetcValue("dmac"), (char*)&stPkt.pMacHdr->dmac);
    FillInMacAddr(GetcValue("smac"), (char*)&stPkt.pMacHdr->smac);
    stPkt.pMacHdr->pro = htons(GetL3HexPro(GetcValue("l3pro")));

    stInfo.iCursor += MACHDRLEN;
}

/* Constructing vlan tag  */
void BuildVlanTag(int iVlanNum)
{
    _vlanhdr* pVlanInfo[] = {
        stPkt.pVlanHdr,
        stPkt.pQinQHdr
    }; 

    int iVlanLayer = (stInfo.iCursor == MACHDRLEN ? 0 : 1);
    pVlanInfo[iVlanLayer] = (_vlanhdr *)(stPkt.pPacket + stInfo.iCursor);

    pVlanInfo[iVlanNum]->id = ((iVlanNum - iVlanLayer) == 1 ?  
        htons(VLAN) : htons(GetL3HexPro(GetcValue("l3pro"))));
    pVlanInfo[iVlanNum]->pro = (iVlanNum == 1 ? 
        GetiValue("vlan") : GetiValue("qinq"));

    stInfo.iCursor += VLANTAGLEN;
}

/* Building IP protocol header */
void BuildIp4Header()
{
    stPkt.pIp4Hdr = (_ip4hdr *)(stPkt.pPacket + stInfo.iCursor);

    stPkt.pIp4Hdr->ver_len = (4 << 4 | IP4HDRLEN / 4);
    stPkt.pIp4Hdr->tos = 0;
    stPkt.pIp4Hdr->total_len = htons(stInfo.iPktLen - stInfo.iCursor);
    stPkt.pIp4Hdr->ident = 1;
    stPkt.pIp4Hdr->flag_offset = 0;
    stPkt.pIp4Hdr->ttl = 128;
    stPkt.pIp4Hdr->protocol = GetL4HexPro(GetcValue("l4pro"));
    stPkt.pIp4Hdr->checksum = GetCheckSum((U16 *)stPkt.pIp4Hdr, IP4HDRLEN);
    stPkt.pIp4Hdr->srcip = inet_addr(GetcValue("sip"));
    stPkt.pIp4Hdr->dstip = inet_addr(GetcValue("dip"));

    stInfo.iCursor += IP4HDRLEN;
}

/* Building ARP protocol header */
void BuildArpHeader(int iOperationType)
{
    stPkt.pArpHdr = (_arphdr *)(stPkt.pPacket + stInfo.iCursor);
    stPkt.pArpHdr->hrd = 0x01; // Ethernet
    stPkt.pArpHdr->pro = htons(IPv4);
    stPkt.pArpHdr->len = 0x06;
    stPkt.pArpHdr->plen = 0x04;
    stPkt.pArpHdr->option = htons(iOperationType); // 1:ARP req 2:ARP res 3:RARP req 4:RARP res
    FillInMacAddr(GetcValue("smac"), (char*)&stPkt.pArpHdr->smac);
    stPkt.pArpHdr->sip = inet_addr(GetcValue("sip"));
    FillInMacAddr(GetcValue("dmac"), (char*)&stPkt.pArpHdr->dmac);
    stPkt.pArpHdr->dip = inet_addr(GetcValue("dip"));

    stInfo.iCursor += ARPHDRLEN;
}

/* Building TCP protocol header */
void BuildTcpHeader()
{
    stPkt.pTcpHdr = (_tcphdr *)(stPkt.pPacket + stInfo.iCursor);

    int iTcpLen = stInfo.iPktLen - stInfo.iCursor;
    stPkt.pTcpHdr->sport = htons(GetiValue("sport"));
    stPkt.pTcpHdr->dport = htons(GetiValue("dport")); 
    stPkt.pTcpHdr->seq = 1; 
    stPkt.pTcpHdr->ack = 0;
    stPkt.pTcpHdr->hdrlen = 0x5f;
    stPkt.pTcpHdr->flag = 128; /*cwr|ecn|urg|ack|psh|rst|syn|fin*/
    stPkt.pTcpHdr->win = htons(65535);
    stPkt.pTcpHdr->checksum = 0;
    stPkt.pTcpHdr->urg = 0;
    stPkt.pTcpHdr->checksum = GetCheckSum( \
        BuildPseduoPacket(stPkt.pTcpHdr, TCP, iTcpLen),
        iTcpLen+PSEUDOHDRLEN);

    stInfo.iCursor += TCPHDRLEN;
}

/* Building UDP protocol header */
void BuildUdpHeader()
{
    stPkt.pUdpHdr = (_udphdr *)(stPkt.pPacket + stInfo.iCursor);

    stPkt.pUdpHdr->sport = htons(GetiValue("sport"));
    stPkt.pUdpHdr->dport = htons(GetiValue("dport"));
    int iUdpLen = stInfo.iPktLen - stInfo.iCursor;
    stPkt.pUdpHdr->len = htons(iUdpLen);
    stPkt.pUdpHdr->checksum = 0;
    stPkt.pUdpHdr->checksum = GetCheckSum( \
        BuildPseduoPacket(stPkt.pUdpHdr, UDP, iUdpLen),
        iUdpLen+PSEUDOHDRLEN);

    stInfo.iCursor += UDPHDRLEN;
}

/* Building ICMP protocol header */
void BuildIcmp4Header(int iOperationType)
{
    stPkt.pIcmp4Hdr = (_icmp4hdr *)(stPkt.pPacket + stInfo.iCursor);

    // Echo request(type:8 code:0), Echo reply(type:0 code:0)
    stPkt.pIcmp4Hdr->type= htons(iOperationType);
    stPkt.pIcmp4Hdr->code = 0;
    //stPkt.pIcmp4Hdr->checksum = GetCheckSum((uint16_t *)stPkt.pIcmp4Hdr, 30);
    stPkt.pIcmp4Hdr->checksum = GetCheckSum((uint16_t *)stPkt.pIcmp4Hdr, ICMP4HDRLEN);
    stPkt.pIcmp4Hdr->identifier = htons(getpid());
    stPkt.pIcmp4Hdr->seq = 256;

    stInfo.iCursor += ICMP4HDRLEN;
}

/* Constructing DNS data context */
void BuildDnsContext()
{
    char* pDnsData = (char *)(stPkt.pPacket + stInfo.iCursor);
    char* pUrlStr = GetRandURL();
    int iUrlLen = strlen(pUrlStr);
    // Amand packet length
    stInfo.iPktLen = 59 + iUrlLen;
    stPkt.pPktHdr->len = stPkt.pPktHdr->caplen = stInfo.iPktLen;

    memcpy(pDnsData, pUrlStr, iUrlLen); 
    pDnsData += iUrlLen;
    *(pDnsData+0) = 0x00; // End flag
    *(pDnsData+1) = 0x00;
    *(pDnsData+2) = 0x01;
    *(pDnsData+3) = 0x00;
    *(pDnsData+4) = 0x01;
}

/* Constructing DNS information */
void BuildDnsMessage()
{
    _dnshdr* pDnsHdr = (_dnshdr *)(stPkt.pPacket + stInfo.iCursor);

    pDnsHdr->tid   = htons(0x1234);
    pDnsHdr->flag  = htons(0x0001);
    pDnsHdr->que   = htons(0x0001);
    pDnsHdr->anrrs = htons(0x0000);
    pDnsHdr->aurrs = htons(0x0000);
    pDnsHdr->adrrs = htons(0x0000);

    stInfo.iCursor += DNSHDRLEN;
    BuildDnsContext();
}

/* Building HTTP messages */
void BuildHttpMessage()
{
    char* pHttpData = (char *)(stPkt.pPacket + stInfo.iCursor);
    int   iPayLen = stInfo.iPktLen - stInfo.iCursor;
    char* pL7Pro = GetcValue("l7pro");
    char* pUrlStr = GetcValue("pUrlStr");
    char* pUriStr = NULL;
    char* pHostStr = "";

    if (pUrlStr == NULL) {
        char* pUrlStr = GetRandURL();
        pHostStr = strtok(pUrlStr, "/");
        pUriStr = pUrlStr + strlen(pHostStr) + 1;
    } else {
        pHostStr = strtok(pUrlStr, "/");
        pUriStr = strtok(NULL, "/");
    }

    char cDataBuf[BUFSIZ];
    char* pBufCursor = cDataBuf;

    char* pMethod = NULL;
    if (strcmp(pL7Pro, "HTTP-GET") == 0) {
        pMethod = "GET /";
    } else if (strcmp(pL7Pro, "HTTP-POST") == 0) {
        pMethod = "POST /";
    }

    sprintf(pBufCursor, "%s%s%s%s%s%s%s%s%s%s%s%s%s", 
        pMethod,
        pUriStr, 
        " HTTP/1.1\r\n", 
        "Host: ", pHostStr, 
        "\r\nConnection: Keep-Alive\r\n",
        "Accept: */*\r\n", 
        "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0;"
            "Windows NT 5.1; Trident/4.0;"
            ".NET CLR 2.0.50727; .NET CLR 3.0.04506.648; " 
            ".NET CLR 3.5.21022; InfoPath.2)\r\n",
        "Accept-Encoding: gzip, deflate/r/n",
        "Accept-Language: zh-cn\r\n",
        "Cookie:", GetRandStr(iPayLen - strlen(cDataBuf) - 4),
        "\r\n\r\n"
    );

    memcpy(pHttpData, cDataBuf, strlen(cDataBuf));
}

/* Construction layer 7 data content */
void BuildDataContexts()
{
    int iStrOffset = GetiValue("offset");
    int iStrType = GetFlag("string");
    int iPayLen = stInfo.iPktLen - stInfo.iCursor;
    if (iPayLen < 0) {
        LOGRECORD(ERROR, "Payload length error");
    }

    // Dead work
    int iStrLen = 0;
    char* pData = (char *)(stPkt.pPacket + stInfo.iCursor);
    if (iStrOffset >= iPayLen) {
        pData += iPayLen;
        stInfo.iCursor += iPayLen;
        LOGRECORD(WARNING, "Offset grate than payload length");
    } else {
        pData += iStrOffset;
        iStrLen = iPayLen - iStrOffset;
        stInfo.iCursor += iStrOffset;
    }

    // Generate data
    if (iStrType == FG_RAND) {
        memcpy(pData, GetRandStr(iPayLen), iPayLen);
        stInfo.iCursor += iStrLen;
    } else if (iStrType == FG_FIXD) {
        char* pFixedStr = GetcValue("string");
        int iFixedStrLen = strlen(pFixedStr);
        // Handling strings beginning with '0x'
        if (pFixedStr[0] == '0' && pFixedStr[1] == 'x') {
            // Amand string length
            iFixedStrLen = (iFixedStrLen - 2) / 2; 
            unsigned long iHexNum = strtol(pFixedStr, NULL, 16);

            int iNumI = iFixedStrLen-1;
            int iNumJ = 0;
            for (; iNumI>=0 && iNumJ<iStrLen; iNumI--, iNumJ++) {
                sprintf(&pData[iNumJ], "%c", (char)(iHexNum>>(iNumI*8)&0xff));
            }
        } else { // Handling normal input strings 
            iFixedStrLen = (iFixedStrLen > iStrLen ? iStrLen : iFixedStrLen);
            memcpy(pData, pFixedStr, iFixedStrLen);
        }
        stInfo.iCursor += iStrLen;
    } else if (iStrType == FG_NOINPUT) { // Handling no input situation
        stInfo.iCursor += iPayLen;
        DisplayPacketData(stPkt.pPacket, stInfo.iPktLen);
    } else {
        LOGRECORD(ERROR, "String type not supported");
    }

    // Check packet length
    if (stInfo.iCursor != stInfo.iPktLen) {
        LOGRECORD(ERROR, "Packet Message build error");
    }
}

/* Two layer protocol processing */
void BuildLayer2Header()
{
    BuildMacHeader();

    int iVlanNum = GetiValue("vlannum");
    while (iVlanNum) {
        BuildVlanTag(iVlanNum);
        iVlanNum--;
    }
}

/* Three layer protocol processing */
void BuildLayer3Header()
{
    switch(GetL3HexPro(GetcValue("l3pro"))) {
        case IPv4 : BuildIp4Header(); break;
        case ARP  : BuildArpHeader(2); break; // 2:ARP response
        default   : LOGRECORD(ERROR, "Layer three protocol is not found");
    }
}

/* Four layer protocol processing*/
void BuildLayer4Header()
{
    switch(GetL4HexPro(GetcValue("l4pro"))) {
        case TCP   : BuildTcpHeader(); break;
        case UDP   : BuildUdpHeader(); break;
        case ICMP4 : BuildIcmp4Header(8); break;
        default    : LOGRECORD(ERROR, "Layer four protocol is not found");
    }
}

/* Seventh layer protocol processing*/
void BuildLayer7Header()
{
    char *pL7Pro = GetcValue("l7pro");

    if (pL7Pro == NULL) {
        BuildDataContexts();
    } else if (strcmp(pL7Pro, "DNS") == 0) {
        BuildDnsMessage();
    } else if (strcmp(pL7Pro, "HTTP-GET") == 0 
            || strcmp(pL7Pro, "HTTP-POST") == 0) {
        BuildHttpMessage();
    } else {
        LOGRECORD(ERROR, "Unrecognized seventh layer protocol");
    }
}

/*
int RuleModeInitialization()
{
    int iSaveFd = 0;
    if (strcmp(rule_tag, "aclnmask") == 0) {
        iSaveFd = OpenSaveFile(ACLNMASKFILE);
    } else if (strcmp(rule_tag, "aclex") == 0) {
        iSaveFd = OpenSaveFile(ACLEXFILE);
    } else if (strcmp(rule_tag, "mac_table") == 0) {
        iSaveFd = OpenSaveFile(MACTABLEFILE);
    }

    return iSaveFd;
}

void RulesGenerationEntrance(int fd, int iRuleNum)
{
    // to print reletive ACL rules into file
    if (strcmp(rule_tag, "aclnmask") == 0) {
        if (dprintf(fd, "add ruleset test aclnmask %d "
                "action=drop, sip=%s, dip=%s, sport=%d, dport=%d, protocol=%s\n", 
                iRuleNum, GetcValue("sip"), GetcValue("dip"), GetiValue("sport"), GetiValue("dport"),
                GetStrPro(l4_pro)) < 0) {
            LOGRECORD(ERROR, "write aclmask rules error");
        }
    } else if (strcmp(rule_tag, "aclex") == 0) {
        int offset = GetiValue("offset");
        if (dprintf(fd, "add ruleset test aclex %d "
                "action=drop, offset=%d, strkey=%s\n", 
                iRuleNum, offset, data+offset) < 0) {
            LOGRECORD(ERROR, "write aclex rules error");
        }
    } else if (strcmp(rule_tag, "mac_table") == 0) {
        if (dprintf(fd, "add mac_table %s "
                "action=forward, outgroup=1\n", GetcValue("smac")) < 0) {
            LOGRECORD(ERROR, "write mac table rules error");
        }
    }
}

void CloseRuleMode(int fd)
{
    close(fd);
    LOGRECORD(DEBUG, "Write rules finished");
}
*/

void CloseWriteMode(int fd)
{
    close(fd);
    LOGRECORD(DEBUG, "Write packets finished");
}

void BuildInitialization()
{
    static char cPacketBuf[PACKETLEN];
    stPkt.pPacket = cPacketBuf;
    stInfo.iPktLen = GetiValue("pktlen");
    stInfo.iCursor = 0;
}

/* Building data packets */
void BuildPacket()
{
    LOGRECORD(DEBUG, "Build Packet start...");
    BuildInitialization();

    int iPcapFd = -1;
    int iLoop = 0;
    int iCount = GetiValue("count");
    int iIntervalTime= GetiValue("interval");
    int iDebugSwitch = GetiValue("debug");
    while (!iCount || iLoop<iCount)
    {
        BuildPacketHeader();
        BuildLayer2Header();
        BuildLayer3Header();
        BuildLayer4Header();
        BuildLayer7Header();

        // how to deal with packets 
        if (GetiValue("exec") == 0) { //send
            SendModeInitialization();
            SendPacketProcess(stPkt.pPacket, stInfo.iPktLen);
        } else { //save
            if (iPcapFd <= 0) {
                iPcapFd = WriteModeInitialization();
            } else {
                if (write(iPcapFd, stPkt.pPktHdr, PKTHDRLEN) < 0) {
                    LOGRECORD(ERROR, "write packet to pacp file error");
                }
                if (write(iPcapFd, stPkt.pPacket, stInfo.iPktLen) < 0) {
                    LOGRECORD(ERROR, "write packet to pacp file error");
                }
            }
        }
        if (iDebugSwitch) {
            ShowParameter();
            DisplayPacketData(stPkt.pPacket, stInfo.iPktLen);
        }
        // time interval 
        usleep(iIntervalTime);

        // display program process 
        ProgramProgress(++iLoop, iCount);
    } // End of while
    printf("\n");

    if (iDebugSwitch) {
        DisplayStatisticsResults();
    }

    CloseWriteMode(iPcapFd);
    CloseSendConnect();

    LOGRECORD(DEBUG, "Build packet finished");
} // End of Build 

