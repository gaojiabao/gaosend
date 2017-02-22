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
static void BuildPcapHeader()
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
static void BuildPacketHeader()
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
static U16 BuildPseduoPacket(void* pData)
{
    int iDataLen = stInfo.iPktLen - stInfo.iCursor;
    U8  iL4Pro = GetL4HexPro(GetcValue("l4pro"));

    // Build pseudo header
    static char cPseudoPacket[PACKETLEN];
    _pseudohdr* pPseudoHdr = (_pseudohdr *)cPseudoPacket;
    pPseudoHdr->sip = stPkt.pIp4Hdr->sip;
    pPseudoHdr->dip = stPkt.pIp4Hdr->dip;
    pPseudoHdr->flag = 0;
    pPseudoHdr->protocol = iL4Pro;
    pPseudoHdr->len = iDataLen;

    // Build pseudo packet data
    char *pPseudoData = cPseudoPacket + PSEUDOHDRLEN;
    memcpy(pPseudoData, pData, iDataLen);

    return GetCheckSum((U16 *)cPseudoPacket, PSEUDOHDRLEN+iDataLen);
}

/* Data save program entry */
static void SaveModeProgram(int iSwitch)
{
    static int iSaveFd = -1;

    if (iSwitch) {
        if (iSaveFd < 0) {
            // Data save initialization
            if ((iSaveFd = OpenSaveFile(GetcValue("save"))) < 0) {
                LOGRECORD(ERROR, "File doesn't exist");
            }
            BuildPcapHeader();
            if (write(iSaveFd, stPkt.pPcapHdr, PCAPHDRLEN) < 0) {
                LOGRECORD(ERROR, "write packet to pacp file error");
            }
        } 

        // Data saving 
        BuildPacketHeader();
        if (write(iSaveFd, stPkt.pPktHdr, PKTHDRLEN) < 0) {
            LOGRECORD(ERROR, "write packet to pacp file error");
        }
        if (write(iSaveFd, stPkt.pPacket, stInfo.iPktLen) < 0) {
            LOGRECORD(ERROR, "write packet to pacp file error");
        }
        if (GetiValue("debug")) {
            DisplayPacketData((char *)stPkt.pPcapHdr, PCAPHDRLEN);
        }
        
    } else {
        close(iSaveFd);
        LOGRECORD(DEBUG, "Write packets finished");
    }
}

/* Close socket of save-file descriptor */
static void RecycleProgram()
{
    if (GetiValue("exec") == 0) { //send
        CloseSendConnect();
    } else {
        SaveModeProgram(0);
    }
}

/* Constructing ethernet data header */
static void BuildMacHeader()
{
    stInfo.iCursor -= MACHDRLEN;
    stPkt.pMacHdr = (_machdr *)(stPkt.pPacket + stInfo.iCursor);

    FillInMacAddr(GetcValue("dmac"), (char*)&stPkt.pMacHdr->dmac);
    FillInMacAddr(GetcValue("smac"), (char*)&stPkt.pMacHdr->smac);
    stPkt.pMacHdr->pro = htons(GetL3HexPro(GetcValue("l3pro")));
}

/* Constructing vlan tag */
static void BuildVlanTag(int iVlanNum)
{
    _vlanhdr* pVlanInfo[] = {
        stPkt.pVlanHdr,
        stPkt.pQinQHdr
    }; 

    stInfo.iCursor -= VLANTAGLEN;
    int iVlanLayer = (stInfo.iCursor == MACHDRLEN ? 0 : 1);
    pVlanInfo[iVlanLayer] = (_vlanhdr *)(stPkt.pPacket + stInfo.iCursor);

    pVlanInfo[iVlanNum]->id = ((iVlanNum - iVlanLayer) == 1 ?  
            htons(VLAN) : htons(GetL3HexPro(GetcValue("l3pro"))));
    pVlanInfo[iVlanNum]->pro = (iVlanNum == 1 ? 
            GetiValue("vlan") : GetiValue("qinq"));
}

/* Building IP protocol header */
static void BuildIp4Header()
{
    stInfo.iCursor -= IP4HDRLEN;
    stPkt.pIp4Hdr = (_ip4hdr *)(stPkt.pPacket + stInfo.iCursor);

    U8 iL4Pro = GetL4HexPro(GetcValue("l4pro"));
    stPkt.pIp4Hdr->ver_len = (4 << 4 | IP4HDRLEN / 4);
    stPkt.pIp4Hdr->tos = 0;
    stPkt.pIp4Hdr->total_len = htons(stInfo.iPktLen - stInfo.iCursor);
    stPkt.pIp4Hdr->ident = 1;
    stPkt.pIp4Hdr->flag_offset = (4 << 4);
    stPkt.pIp4Hdr->ttl = 128;
    stPkt.pIp4Hdr->protocol = iL4Pro;
    stPkt.pIp4Hdr->checksum = 0;
    stPkt.pIp4Hdr->sip = inet_addr(GetcValue("sip"));
    stPkt.pIp4Hdr->dip = inet_addr(GetcValue("dip"));
    stPkt.pIp4Hdr->checksum = GetCheckSum((U16 *)stPkt.pIp4Hdr, IP4HDRLEN);

    // Calculate TCP of UDP checksum
    if (iL4Pro == TCP) {
       stPkt.pTcpHdr->checksum = BuildPseduoPacket(stPkt.pTcpHdr);
    } else if (iL4Pro == UDP) {
       stPkt.pUdpHdr->checksum = BuildPseduoPacket(stPkt.pUdpHdr);
    }
}

/* Building ARP protocol header */
static void BuildArpHeader(int iOperationType)
{
    stInfo.iCursor = stInfo.iPktLen = 60;
    stInfo.iCursor = MACHDRLEN;
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
}

/* Building TCP protocol header */
static void BuildTcpHeader()
{
    stInfo.iCursor -= TCPHDRLEN;
    stPkt.pTcpHdr = (_tcphdr *)(stPkt.pPacket + stInfo.iCursor);

    stPkt.pTcpHdr->sport = htons(GetiValue("sport"));
    stPkt.pTcpHdr->dport = htons(GetiValue("dport")); 
    stPkt.pTcpHdr->seq = htonl(GetiValue("tcp-seq")); 
    stPkt.pTcpHdr->ack = htonl(GetiValue("tcp-ack"));
    stPkt.pTcpHdr->hdrlen = ((GetiValue("tcp-hdrlen") / 4) << 4);
    // TCP FLAG: CWR|ECN|URG|ACK|PSH|RST|SYN|FIN
    stPkt.pTcpHdr->flag = GetiValue("tcp-flag"); 
    stPkt.pTcpHdr->win = htons(65535);
    stPkt.pTcpHdr->checksum = 0;
    stPkt.pTcpHdr->urg = 0;
}

/* Building UDP protocol header */
static void BuildUdpHeader()
{
    stInfo.iCursor -= UDPHDRLEN;
    stPkt.pUdpHdr = (_udphdr *)(stPkt.pPacket + stInfo.iCursor);

    stPkt.pUdpHdr->sport = htons(GetiValue("sport"));
    stPkt.pUdpHdr->dport = htons(GetiValue("dport"));
    stPkt.pUdpHdr->len = htons(stInfo.iPktLen - stInfo.iCursor);
    stPkt.pUdpHdr->checksum = 0;
}

/* Building ICMP protocol header */
static void BuildIcmp4Header(int iOperationType)
{
    stInfo.iPktLen = 74;
    stInfo.iCursor = MACHDRLEN + IP4HDRLEN;
    int iIcmpMessageLen = stInfo.iPktLen - stInfo.iCursor;
    stPkt.pIcmp4Hdr = (_icmp4hdr *)(stPkt.pPacket + stInfo.iCursor);

    // Build ICMP message header
    stPkt.pIcmp4Hdr->type= htons(iOperationType);
    // Echo request(type:8 code:0), Echo reply(type:0 code:0)
    stPkt.pIcmp4Hdr->code = 0;
    stPkt.pIcmp4Hdr->checksum = 0;
    stPkt.pIcmp4Hdr->identifier = htons(getpid());
    stPkt.pIcmp4Hdr->seq = 256;

    // Build ICMP message data
    char* pData = stPkt.pPacket + stInfo.iCursor + ICMP4HDRLEN;
    int iDataLen = iIcmpMessageLen - ICMP4HDRLEN;
    int iNum = 0;
    U8  iStartPos = 0x61; // 'a' = 0x61
    for (; iNum<iDataLen; iNum++) {
        pData[iNum] = iStartPos++;
        if (iStartPos > 0x77) { // 'w' = 0x77
            iStartPos = 0x41;
        }
    }
    stPkt.pIcmp4Hdr->checksum = 
        GetCheckSum((U16 *)stPkt.pIcmp4Hdr, iIcmpMessageLen);
}

/* Constructing DNS data */
static void BuildDnsMessage()
{
    char* pUrlStr = GetRandURL("HOST", 0);
    int iUrlLen = strlen(pUrlStr);

    // Amand packet length
    stInfo.iPktLen = 60 + iUrlLen;
    int iPayLen = GetDataLen(stInfo.iPktLen);
    stInfo.iCursor = stInfo.iPktLen;

    // Build DNS message header
    stInfo.iCursor -= iPayLen;
    _dnshdr* pDnsHdr = (_dnshdr *)(stPkt.pPacket + stInfo.iCursor);

    pDnsHdr->tid   = htons(0x1234);
    pDnsHdr->flag  = htons(0x0001);
    pDnsHdr->que   = htons(0x0001);
    pDnsHdr->anrrs = htons(0x0000);
    pDnsHdr->aurrs = htons(0x0000);
    pDnsHdr->adrrs = htons(0x0000);

    // Build DNS message data
    int iCursor = stInfo.iCursor + DNSHDRLEN;
    char* pDnsData = (char *)(stPkt.pPacket + iCursor);

    // Switch url format, Eg: 03www09venustech03com 
    char cDomain[1024];
    sprintf(cDomain, ".%s.", pUrlStr);

    int iNum = 1;
    int iCounter = 0;
    int iDomainLen = strlen(cDomain);
    for (; iNum<iDomainLen; iNum++) {
         if (cDomain[iNum] == '.') {
            cDomain[iNum-iCounter-1] = iCounter;
            iCounter = 0;
         } else {
             iCounter++;
         }
    }
    cDomain[iNum-1] = 0;

    memcpy(pDnsData, cDomain, iDomainLen); 
    pDnsData += iDomainLen;
    *(pDnsData+0) = 0x00;
    *(pDnsData+1) = 0x01;
    *(pDnsData+2) = 0x00;
    *(pDnsData+3) = 0x01;
}

/* Building HTTP messages */
static void BuildHttpMessage()
{
    if (stInfo.iPktLen < 360) {
        stInfo.iCursor = stInfo.iPktLen = 360;
    }
    int iPayLen = GetDataLen(stInfo.iPktLen);

    
    char* pUriStr = NULL;
    char* pHostStr = NULL;
    char* pUrlStr = GetcValue("url");
    if (pUrlStr == NULL) {
        char* pUrlStr = GetRandURL("ALL", 20);
        pHostStr = strtok(pUrlStr, "/");
        pUriStr = pUrlStr + strlen(pHostStr) + 1;
    } else {
        pHostStr = strtok(pUrlStr, "/");
        pUriStr = strtok(NULL, "/");
    }

    stInfo.iCursor -= iPayLen;
    char* pHttpData = (char *)(stPkt.pPacket + stInfo.iCursor);
    char* pL7Pro = GetcValue("l7pro");


    char cDataBuf[BUFSIZ];
    char* pBufCursor = cDataBuf;

    char* pMethod = NULL;
    if (strcmp(pL7Pro, "HTTP-GET") == 0) {
        pMethod = "GET /";
    } else if (strcmp(pL7Pro, "HTTP-POST") == 0) {
        pMethod = "POST /";
    }

    int iCookieLen = iPayLen - strlen(pMethod) 
        - strlen(pUriStr) - strlen(pHostStr) - 276;
    sprintf(pBufCursor, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", 
            pMethod,
            pUriStr, 
            " HTTP/1.1\r\n", 
            "Host: ", pHostStr, 
            "\r\nConnection: Keep-Alive\r\n",
            "Accept: */*\r\n", 
            "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0;",
            "Windows NT 5.1; Trident/4.0;",
            ".NET CLR 2.0.50727; .NET CLR 3.0.04506.648; ",
            ".NET CLR 3.5.21022; InfoPath.2)\r\n",
            "Accept-Encoding: gzip, deflate/r/n",
            "Accept-Language: zh-cn\r\n",
            "Cookie:", GetRandStr(iCookieLen),
            "\r\n\r\n"
           );

    memcpy(pHttpData, cDataBuf, strlen(cDataBuf));
}

/* Construction data content */
static void BuildDataContexts()
{
    int iPayLen = GetDataLen(stInfo.iPktLen);
    stInfo.iCursor -= iPayLen;

    int iStrOffset = GetiValue("offset");
    int iStrType = GetFlag("string");
    if (iPayLen < 0) {
        LOGRECORD(ERROR, "Payload length error");
    } else if (iPayLen > 0) {
        // Dead work
        int iStrLen = 0;
        char* pData = (char *)(stPkt.pPacket + stInfo.iCursor);
        if (iStrOffset >= iPayLen) {
            iStrLen = 0;
            LOGRECORD(WARNING, "Offset grate than payload length");
        } else {
            pData += iStrOffset;
            iStrLen = iPayLen - iStrOffset;
        }

        // Generate data
        if (iStrType == FG_RAND) {
            memcpy(pData, GetRandStr(iStrLen), iStrLen);
        } else if (iStrType == FG_FIXD) {
            char* pFixedStr = GetcValue("string");
            int iFixedStrLen = strlen(pFixedStr);
            // Handling strings beginning with '0x'
            if (pFixedStr[0] == '0' && pFixedStr[1] == 'x') {
                // Amand string length
                iFixedStrLen = (iFixedStrLen - 2) / 2; 
                iStrLen = (iFixedStrLen > iStrLen ? iStrLen : iFixedStrLen);

                int  iNum = 1;
                char cTmpStr[2];
                for (; iNum<=iStrLen; iNum++) {
                    memcpy(cTmpStr, pFixedStr+(2*iNum), 2);
                    pData[iNum-1] = strtol(cTmpStr, NULL, 16);
                }
            } else { // Handling normal input strings 
                iFixedStrLen = (iFixedStrLen > iStrLen ? iStrLen : iFixedStrLen);
                memcpy(pData, pFixedStr, iFixedStrLen);
            }
        } else if (iStrType == FG_NOINPUT) { // Handling no input situation
            LOGRECORD(DEBUG, "No input string");
        } else {
            LOGRECORD(ERROR, "String type not supported");
        }
    }
}

/* Layer two protocol processing */
static void BuildLayer2Header()
{
    BuildMacHeader();

    int iVlanNum = GetiValue("vlannum");
    while (iVlanNum) {
        BuildVlanTag(iVlanNum);
        iVlanNum--;
    }
}

/* Layer three protocol processing */
static void BuildLayer3Header()
{
    switch(GetL3HexPro(GetcValue("l3pro"))) {
        case IPv4 : BuildIp4Header(); break;
        case ARP  : BuildArpHeader(2); break; // 2:ARP response
        default   : LOGRECORD(ERROR, "Layer three protocol is not found");
    }

    BuildLayer2Header();
}

/* Layer four protocol processing */
static void BuildLayer4Header()
{
    char* pL4Pro = GetcValue("l4pro");
    
    if (pL4Pro != NULL) {
        switch(GetL4HexPro(pL4Pro)) {
            case TCP   : BuildTcpHeader(); break;
            case UDP   : BuildUdpHeader(); break;
            case ICMP4 : BuildIcmp4Header(8); break;
        }
    }

    BuildLayer3Header();
}

/* Layer seven protocol processing */
static void BuildApplicationData()
{
    char *pProStr = GetcValue("l7pro");
    if (pProStr == NULL) {
        pProStr = GetcValue("l4pro");
    }

    if (pProStr != NULL && (strcmp(pProStr, "DNS") == 0)) {
        BuildDnsMessage();
    } else if (pProStr != NULL 
        && ((strcmp(pProStr, "HTTP-GET") == 0) 
        || (strcmp(pProStr, "HTTP-POST") == 0))) {
        BuildHttpMessage();
    } else if (pProStr != NULL 
        && ((strcmp(pProStr, "TCP") == 0)
        || (strcmp(pProStr, "UDP") == 0))) {
        BuildDataContexts();
    }

    BuildLayer4Header();
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

static void BuildInitialization()
{
    static char cPacketBuf[PACKETLEN];
    stPkt.pPacket = cPacketBuf;

    stInfo.iPktLen = GetiValue("pktlen");
    stInfo.iCursor = stInfo.iPktLen;
    RefreshParameter();
}

/* Data generator program entry */
static void MessageGenerator()
{
    int iLoop = 0;
    int iCount = GetiValue("count");
    int iDebugSwitch = GetiValue("debug");

    while (!iCount || iLoop<iCount) {
        BuildInitialization();
        BuildApplicationData();

        // Message sending or saving program 
        if (GetiValue("exec") == 0) { //send
            SendPacketProcess(stPkt.pPacket, stInfo.iPktLen);
        } else { //save
            SaveModeProgram(1);
        }

        if (iDebugSwitch) {
            ShowParameter();
            DisplayPacketData(stPkt.pPacket, stInfo.iPktLen);
        }

        // Display program process 
        ProgramProgress(++iLoop, iCount);
    } // End of while
    printf("\n");
    RecycleProgram();
}

/* Building data packets */
void BuildPacket()
{
    LOGRECORD(DEBUG, "Build Packet start...");

    MessageGenerator();

    if (GetiValue("entrance") == 105) {
        DisplayStatisticsResults();
    }

    LOGRECORD(DEBUG, "Build packet finished");
} // End of Build 

