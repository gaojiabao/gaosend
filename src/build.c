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
#include    "func.h"
#include    "runlog.h"
#include    "storage.h"


/* Packet structure */
static stPktStrc stPkt;
static stPktInfo stInfo;

#define PKT_BUF_LEN SIZE_1K*10

/* Constructing pcap header used to identify file type */
static void BuildPcapHeader()
{
    static char cPcapHdrBuf[PCAP_HDR_LEN];
    stPkt.pPcapHdr = (_pcaphdr *)cPcapHdrBuf;

    stPkt.pPcapHdr->magic = htonl(0xd4c3b2a1);
    stPkt.pPcapHdr->major = 2;
    stPkt.pPcapHdr->minor = 4;
    stPkt.pPcapHdr->thiszone = 0;
    stPkt.pPcapHdr->sigflags = 0;
    stPkt.pPcapHdr->snaplen = htonl(65535);
    stPkt.pPcapHdr->linktype = 1;
}

/* Constructing packet header used to identify packet information */
static void BuildPacketHeader()
{
    static char cPktHdrBuf[PKT_HDR_LEN];
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
    static char cPseudoPacket[PKT_BUF_LEN];
    _pseudohdr* pPseudoHdr = (_pseudohdr *)cPseudoPacket;
    pPseudoHdr->sip = stPkt.pIp4Hdr->sip;
    pPseudoHdr->dip = stPkt.pIp4Hdr->dip;
    pPseudoHdr->flag = 0;
    pPseudoHdr->protocol = iL4Pro;
    pPseudoHdr->len = iDataLen;

    // Build pseudo packet data
    char *pPseudoData = cPseudoPacket + PSEUDO_HDR_LEN;
    memcpy(pPseudoData, pData, iDataLen);

    return GetCheckSum((U16 *)cPseudoPacket, PSEUDO_HDR_LEN+iDataLen);
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
            if (write(iSaveFd, stPkt.pPcapHdr, PCAP_HDR_LEN) < 0) {
                LOGRECORD(ERROR, "write packet to pacp file error");
            }
        } 

        // Data saving 
        BuildPacketHeader();
        if (write(iSaveFd, stPkt.pPktHdr, PKT_HDR_LEN) < 0) {
            LOGRECORD(ERROR, "write packet to pacp file error");
        }
        if (write(iSaveFd, stPkt.pPacket, stInfo.iPktLen) < 0) {
            LOGRECORD(ERROR, "write packet to pacp file error");
        }
        if (GetiValue("debug")) {
            DisplayPacketData((char *)stPkt.pPcapHdr, PCAP_HDR_LEN);
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
    stInfo.iCursor -= MAC_HDR_LEN;
    stPkt.pMacHdr = (_machdr *)(stPkt.pPacket + stInfo.iCursor);

    FillInMacAddr((char*)&stPkt.pMacHdr->dmac, GetcValue("dmac"));
    FillInMacAddr((char*)&stPkt.pMacHdr->smac, GetcValue("smac"));
    U16 iNextPro = GetiValue("vlannum") ? 
        htons(VLAN) : htons(GetL3HexPro(GetcValue("l3pro"))); 
    stPkt.pMacHdr->pro = iNextPro;
}

/* Constructing vlan tag */
static void BuildVlanTag(int iVlanNum, int iTotleNum)
{
    _vlanhdr* pVlanInfo[] = {
        stPkt.pVlanHdr,
        stPkt.pQinQHdr
    }; 

    stInfo.iCursor -= VLAN_TAG_LEN;

    int iVlanLayer = (stInfo.iCursor == MAC_HDR_LEN ? 0 : 1);
    pVlanInfo[iVlanLayer] = (_vlanhdr *)(stPkt.pPacket + stInfo.iCursor);

    pVlanInfo[iVlanLayer]->id = ((iVlanNum == 1) ? 
            htons(GetiValue("vlan")) : htons(GetiValue("qinq")));
    pVlanInfo[iVlanLayer]->pro = ((iVlanNum == iTotleNum) ?  
            htons(GetL3HexPro(GetcValue("l3pro"))) : htons(VLAN));
}

/* Building IP protocol header */
static void BuildIp4Header()
{
    stInfo.iCursor -= IP4_HDR_LEN;
    stPkt.pIp4Hdr = (_ip4hdr *)(stPkt.pPacket + stInfo.iCursor);

    U8 iL4Pro = GetL4HexPro(GetcValue("l4pro"));
    stPkt.pIp4Hdr->version = 4;
    stPkt.pIp4Hdr->hdlen = (IP4_HDR_LEN / 4);
    stPkt.pIp4Hdr->tos = 0;
    stPkt.pIp4Hdr->ttlen = htons(stInfo.iPktLen - stInfo.iCursor);
    stPkt.pIp4Hdr->ident = 1;
    stPkt.pIp4Hdr->flag_offset = (GetiValue("ip_flags") << 6) 
        | (htons(GetiValue("ip_offset") / 8));
    stPkt.pIp4Hdr->ttl = 128;
    stPkt.pIp4Hdr->protocol = iL4Pro;
    stPkt.pIp4Hdr->checksum = 0;
    stPkt.pIp4Hdr->sip = inet_addr(GetcValue("sip"));
    stPkt.pIp4Hdr->dip = inet_addr(GetcValue("dip"));
    stPkt.pIp4Hdr->checksum = GetCheckSum((U16 *)stPkt.pIp4Hdr, IP4_HDR_LEN);

    // Calculate TCP of UDP checksum
    if (iL4Pro == TCP) {
        stPkt.pTcpHdr->checksum = BuildPseduoPacket(stPkt.pTcpHdr);
    } else if (iL4Pro == UDP) {
        stPkt.pUdpHdr->checksum = BuildPseduoPacket(stPkt.pUdpHdr);
    }
}

/* Building IP protocol header */
static void BuildIp6Header()
{
    int iPayLen = stInfo.iPktLen - stInfo.iCursor;
    stInfo.iCursor -= IP6_HDR_LEN;
    stPkt.pIp6Hdr = (_ip6hdr *)(stPkt.pPacket + stInfo.iCursor);

    U8 iL4Pro = GetL4HexPro(GetcValue("l4pro"));
    stPkt.pIp6Hdr->version = htons(24576);
    /*
    stPkt.pIp6Hdr->traffic = 0;
    stPkt.pIp6Hdr->flowLabel = 0;
    */
    stPkt.pIp6Hdr->payload = htons(iPayLen);
    stPkt.pIp6Hdr->protocol = iL4Pro;
    stPkt.pIp6Hdr->nextHop = 0xff;
    inet_pton(AF_INET6, "::192.168.1.1", stPkt.pIp6Hdr->sip);
    inet_pton(AF_INET6, "2a01:198:603:0::", stPkt.pIp6Hdr->dip);

    // Calculate TCP of UDP checksum
    if (iL4Pro == TCP) {
        //stPkt.pTcpHdr->checksum = BuildPseduoPacket(stPkt.pTcpHdr);
        stPkt.pTcpHdr->checksum = 0;
    } else if (iL4Pro == UDP) {
        //stPkt.pUdpHdr->checksum = BuildPseduoPacket(stPkt.pUdpHdr);
        stPkt.pUdpHdr->checksum = htons(0xffff);
    }
}

/* Building ARP protocol header */
static void BuildArpHeader(int iOperationType)
{
    stInfo.iCursor = stInfo.iPktLen = 60;
    stInfo.iCursor = MAC_HDR_LEN;
    stPkt.pArpHdr = (_arphdr *)(stPkt.pPacket + stInfo.iCursor);

    stPkt.pArpHdr->hrd = 0x01; // Ethernet
    stPkt.pArpHdr->pro = htons(IPv4);
    stPkt.pArpHdr->len = 0x06;
    stPkt.pArpHdr->plen = 0x04;
    stPkt.pArpHdr->option = htons(iOperationType); // 1:ARP req 2:ARP res 3:RARP req 4:RARP res
    FillInMacAddr((char*)&stPkt.pArpHdr->smac, GetcValue("smac"));
    stPkt.pArpHdr->sip = inet_addr(GetcValue("sip"));
    FillInMacAddr((char*)&stPkt.pArpHdr->dmac, GetcValue("dmac"));
    stPkt.pArpHdr->dip = inet_addr(GetcValue("dip"));
}

/* Building TCP protocol header */
static void BuildTcpHeader()
{
    stInfo.iCursor -= TCP_HDR_LEN;
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
    stInfo.iCursor -= UDP_HDR_LEN;
    stPkt.pUdpHdr = (_udphdr *)(stPkt.pPacket + stInfo.iCursor);

    stPkt.pUdpHdr->sport = htons(GetiValue("sport"));
    stPkt.pUdpHdr->dport = htons(GetiValue("dport"));
    stPkt.pUdpHdr->len = htons(stInfo.iPktLen - stInfo.iCursor);
    stPkt.pUdpHdr->checksum = 0;
}

/* Building ICMP protocol header */
static void BuildIcmp4Header(int iOperationType)
{
    int iVlanLen = VLAN_TAG_LEN * GetiValue("vlannum");
    stInfo.iCursor = (strcmp(GetcValue("l3pro"), "IPv4") == 0) ? 
        MAC_HDR_LEN + iVlanLen + IP4_HDR_LEN : MAC_HDR_LEN + iVlanLen + IP6_HDR_LEN;
    int iIcmpMessageLen = stInfo.iPktLen - stInfo.iCursor;
    stPkt.pIcmp4Hdr = (_icmp4hdr *)(stPkt.pPacket + stInfo.iCursor);

    // Build ICMP message header
    stPkt.pIcmp4Hdr->type = iOperationType;
    // Echo request(type:8 code:0), Echo reply(type:0 code:0)
    stPkt.pIcmp4Hdr->code = 0;
    stPkt.pIcmp4Hdr->checksum = 0;
    stPkt.pIcmp4Hdr->identifier = htons(getpid());
    stPkt.pIcmp4Hdr->seq = 256;

    // Build ICMP message data
    char* pData = stPkt.pPacket + stInfo.iCursor + ICMP4_HDR_LEN;
    int iDataLen = iIcmpMessageLen - ICMP4_HDR_LEN;
    int iNum = 0;
    U8  iStartPos = 0x61; // 'a' = 0x61
    for (; iNum < iDataLen; iNum ++) {
        pData[iNum] = iStartPos ++;
        if (iStartPos > 0x77) { // 'w' = 0x77
            iStartPos = 0x61;
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
    stPkt.pData = (char *)pDnsHdr;

    pDnsHdr->tid   = htons(0x1234);
    pDnsHdr->flag  = htons(0x0001);
    pDnsHdr->que   = htons(0x0001);
    pDnsHdr->anrrs = htons(0x0000);
    pDnsHdr->aurrs = htons(0x0000);
    pDnsHdr->adrrs = htons(0x0000);

    // Build DNS message data
    int iCursor = stInfo.iCursor + DNS_HDR_LEN;
    char* pDnsData = (char *)(stPkt.pPacket + iCursor);

    // Switch url format, Eg: 03www09venustech03com 
    char cDomain[1024];
    sprintf(cDomain, ".%s.", pUrlStr);

    int iNum;
    int iCounter = 0;
    int iDomainLen = strlen(cDomain);
    for (iNum = 1; iNum < iDomainLen; iNum ++) {
        if (cDomain[iNum] == '.') {
            cDomain[iNum-iCounter-1] = iCounter;
            iCounter = 0;
        } else {
            iCounter ++;
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
    stPkt.pData = (char *)(stPkt.pPacket + stInfo.iCursor);
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

    memcpy(stPkt.pData, cDataBuf, strlen(cDataBuf));
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
        stPkt.pData = pData;
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

                int  iNum;
                char cTmpStr[2];
                for (iNum = 1; iNum <= iStrLen; iNum ++) {
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
    int iVlanNum = GetiValue("vlannum");
    int iTotleNum = iVlanNum;
    while (iVlanNum) {
        BuildVlanTag(iVlanNum, iTotleNum);
        iVlanNum--;
    }

    BuildMacHeader();
}

/* Layer three protocol processing */
static void BuildLayer3Header()
{
    switch(GetL3HexPro(GetcValue("l3pro"))) {
        case IPv4 : BuildIp4Header(); break;
        case IPv6 : BuildIp6Header(); break;
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
            case ICMP6 : BuildIcmp4Header(128); break;
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
                || (strcmp(pProStr, "UDP") == 0)
                || (strcmp(pProStr, "TCP6") == 0)
                || (strcmp(pProStr, "UDP6") == 0))) { 
        BuildDataContexts();
    }

    BuildLayer4Header();
}

static void BuildInitialization()
{
    static char cPacketBuf[PKT_BUF_LEN];
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
            //SendPacketProcess(stPkt.pPacket, stInfo.iPktLen);
            char buf[5000];
            memcpy(buf, stPkt.pPacket, stInfo.iPktLen);
            int i = 0;
            for (;i<7;i ++) {
                buf[stInfo.iPktLen+i] = 0x00;
            }
            memcpy(buf+stInfo.iPktLen+7, stPkt.pPacket, stInfo.iPktLen);
            SendPacketProcess(buf, stInfo.iPktLen*2+7);

        } else { //save
            SaveModeProgram(1);
        }

        if (iDebugSwitch) {
            ShowParameter();
            DisplayPacketData(stPkt.pPacket, stInfo.iPktLen);
        }

        if (GetcValue("rule")) {
            RulesGenerationEntrance(stPkt, iLoop);
        }

        // Display program process 
        ProgramProgress( ++iLoop, iCount);
    } // End of while
    printf("\n");
    RecycleProgram();
}

/* Building data packets */
void BuildPacket()
{
    LOGRECORD(DEBUG, "Build Packet start...");

    MessageGenerator();

    LOGRECORD(DEBUG, "Build packet finished");
} // End of Build 

