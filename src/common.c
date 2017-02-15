/*
 *  Author   : Mr. Gao
 *
 *  Function : This file include some extracted informations 
 *             in a little function and all of them will be
 *             used in whole programs.
 */

#include    <string.h>
#include    <sys/time.h>
#include    "common.h"
#include    "runlog.h"
#include    "storage.h"


/* Get a random number with microsecond */
int GetRandNum()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    srandom(tp.tv_usec + tp.tv_sec);

    return random();
}

/* Get random string */
char* GetRandStr(int iLength)
{
    int iNum;
    int iRandNum = 0;
    static char cRandStrBuf[SIZE_1K*2] = {0};

    for (iNum = 0; iNum < iLength; iNum++) {
        iRandNum = GetRandNum() % 200;
        if (((iRandNum <= 122) && (iRandNum >= 97)) ||
            ((iRandNum <= 90)  && (iRandNum >= 65)) ||
            ((iRandNum <= 57)  && (iRandNum >= 48))) {
            sprintf(cRandStrBuf+iNum, "%c", iRandNum);
        } else {
            iNum--;
        }
    }

    return cRandStrBuf;
}

/* Calculate udp, tcp or icmp checksum */
uint16_t GetCheckSum(uint16_t* pDataBuf, int iLength)
{
    unsigned long iSum;
    for (iSum=0; iLength>0; iLength--) {
        iSum += *pDataBuf++;
    }
    iSum = (iSum >> 16) + (iSum & 0xffff);
    iSum += (iSum >> 16);

    return (uint16_t)(~iSum);
}

/* Get hexadecimal charator */
char GetHexChar(int iNum)
{
    if (iNum < 0 || iNum > 15) {
        LOGRECORD(ERROR, "Character conversion failed");
    }

    char cLetter = 0;
    switch(iNum) {
        case 0:  cLetter = '0';
        case 1:  cLetter = '1';
        case 2:  cLetter = '2';
        case 3:  cLetter = '3';
        case 4:  cLetter = '4';
        case 5:  cLetter = '5';
        case 6:  cLetter = '6';
        case 7:  cLetter = '7';
        case 8:  cLetter = '8';
        case 9:  cLetter = '9';
        case 10: cLetter = 'A';
        case 11: cLetter = 'B';
        case 12: cLetter = 'C';
        case 13: cLetter = 'D';
        case 14: cLetter = 'E';
        case 15: cLetter = 'F';
    }

    return cLetter;
}

/* URL generator */
char* GetRandURL(char* pField)
{
    int iTotleLen = 18;
    static char cURLBuf[SIZE_1K];
    memset(cURLBuf, 0, sizeof(cURLBuf));

    if (iTotleLen < 18 && iTotleLen > sizeof(cURLBuf)) {
        LOGRECORD(ERROR, "Random URL length out of range");
    }

    char* pComName[] = {"juson", "topsec", "venustech", "360"};
    int iComNameLen = sizeof(pComName) / sizeof(char*);

    char* pFirstDomain  = "com";
    char* pSecondDomain = pComName[GetRandNum() % iComNameLen];
    char* pThirdDomain  = "www";

    int iURILen = iTotleLen - strlen(pFirstDomain) 
                    - strlen(pSecondDomain) - strlen(pSecondDomain);
    if (strcmp(pField, "HOST") == 0) {
        sprintf(cURLBuf, "%s.%s.%s", 
            pThirdDomain, pSecondDomain, pFirstDomain);
    } else {
        sprintf(cURLBuf, "%s.%s.%s/%s", 
            pThirdDomain, pSecondDomain, pFirstDomain , GetRandStr(iURILen));
    }

    return cURLBuf;
}

/* Get random MAC address */
char* GetRandMacAddr(int iSoD)
{
    static char cMacAddr[][20] = {
        "00:00:00:00:00:00",
        "00:00:00:00:00:00"
    };

    if (iSoD < 0 || iSoD > 1) {
        LOGRECORD(ERROR, "Unrecognized identifier");
    }

    int iMacLenth = strlen(cMacAddr[iSoD]);
    while (iMacLenth != 2) {
        iMacLenth--;
        if (cMacAddr[iSoD][iMacLenth] == ':') {
            continue;
        }
        cMacAddr[iSoD][iMacLenth] = GetHexChar(GetRandNum()%15);
    }

    return cMacAddr[iSoD];
}

/* Get increment MAC address */
char* GetIncrMacAddr(int iSoD)
{
    static char cMacAddr[][20] = {
        "00:00:00:00:00:00",
        "00:00:00:00:00:00"
    };

    if (iSoD < 0 || iSoD > 1) {
        LOGRECORD(ERROR, "Unrecognized identifier");
    }

    int iMacLenth = strlen(cMacAddr[iSoD]) - 1;
    while (iMacLenth != -1) {
        if (cMacAddr[iSoD][iMacLenth] == '9') {
            cMacAddr[iSoD][iMacLenth] = 'a' -1;
        }
        if (cMacAddr[iSoD][iMacLenth] == 'f' 
                || cMacAddr[iSoD][iMacLenth] == ':') {
            if (cMacAddr[iSoD][iMacLenth] == 'f') {
                cMacAddr[iSoD][iMacLenth] = '0';
            }
            iMacLenth--;
        } else {
            cMacAddr[iSoD][iMacLenth]++;
            break;
        }
    }
    return cMacAddr[iSoD];
}

/* Writes a string MAC address to the packet */
int FillInMacAddr(char *pMacStr, char *pMacBuf)
{
    if ((pMacBuf == NULL) || (pMacStr == NULL)) {
        LOGRECORD(ERROR, "Failed to fill MAC address");
    }

    int iNum = 0;
    char *pMacTmp = NULL;
    for (; iNum < 6; iNum++) {
        pMacBuf[iNum] = pMacStr ? strtoul (pMacStr, &pMacTmp, 16) : 0;
        if (pMacStr) {
            pMacStr = (*pMacTmp) ? pMacTmp + 1 : pMacTmp;
        }
    }

    return 0;
}

/* Check the legality of the IP address */
int CheckIpAddrLegal(char* pIpStr)
{
    int  iCheckRes;
    int  iIpNum[4];
    char cIpDot[3];
    char cTmpArray[50];
    char *pIpToken = NULL;

    if (pIpStr == NULL) {
        LOGRECORD(ERROR, "IPv4 address is NULL");
    }

    // The legitimacy of the detection with ":" separated IP address 
    if (strchr(pIpStr, ':') != NULL) { // eg: -s 1.1.1.1:2.2.2.2
        memset(cTmpArray, 0, sizeof(cTmpArray));
        memcpy(cTmpArray, pIpStr, strlen(pIpStr));
        if ((pIpToken = strtok(cTmpArray, ":")) != NULL) { // First IP
            iCheckRes = CheckIpAddrLegal(pIpToken);
            if (iCheckRes == SUCCESS) { // Second IP
                pIpToken = strtok(NULL, ":"); 
                iCheckRes = CheckIpAddrLegal(pIpToken);
                if (iCheckRes == SUCCESS) {
                    return 2;
                } else {
                    return FALSE;
                }
            } else {
                return FALSE;
            }
        }
    } 
    
    // IP address detection 
    if (sscanf(pIpStr, "%d%c%d%c%d%c%d", 
            &iIpNum[0], &cIpDot[0], &iIpNum[1], &cIpDot[1],
            &iIpNum[2], &cIpDot[2], &iIpNum[3]) == 7) {
        int iNum;
        for (iNum = 0; iNum < 3; ++iNum) {
            if (cIpDot[iNum] != '.') {
                return ERROR;
            }
        }
        for (iNum = 0; iNum < 4; ++iNum) {
            if (iIpNum[iNum] > 255 || iIpNum[iNum] < 0) {
                return ERROR;
            }
        }
        return SUCCESS;
    }

    return ERROR;
}

/* Get random IP address */
char* GetRandIp4Addr()
{
    static char cIpAddr[SIZE_16B*2];

    sprintf(cIpAddr, "%d.%d.%d.%d", 192, GetRandNum() % 256, 
            GetRandNum() % 256, GetRandNum() % 255 + 1);

    return cIpAddr;
}

/* Get increased IP address */
char* GetIncrIp4Addr(int iSoD)
{
    if (iSoD < 0 || iSoD > 1) {
        LOGRECORD(ERROR, "Unrecognized identifier");
    }

    // SIP:192.168.1.1 DIP:10.10.1.1
    static unsigned int iIpAddr[] = {3232235777, 168430081};
    unsigned int iIpSwitch = htonl(iIpAddr[iSoD]++);
    static char cIpAddrBuf[SIZE_16B*2];
    if (((unsigned char *)&iIpSwitch)[3] != 0) {
        sprintf(cIpAddrBuf, "%u.%u.%u.%u", 
            ((unsigned char *)&iIpSwitch)[0],
            ((unsigned char *)&iIpSwitch)[1],
            ((unsigned char *)&iIpSwitch)[2],
            ((unsigned char *)&iIpSwitch)[3]);
    }

    return cIpAddrBuf;
}

/* Get random port number */
int GetRandPort()
{
    // Return registered port number
    return (1025 + GetRandNum() % (65535 - 1025));
}

/* Get increase port number */
int GetIncrPort(int iSoD)
{
    if (iSoD < 0 || iSoD > 1) {
        LOGRECORD(ERROR, "Unrecognized identifier");
    }

    static int iPortArray[] = {0, 0};
    if (iPortArray[iSoD]++ > 65535) {
        iPortArray[iSoD] = 0;
    }

    return iPortArray[iSoD];
}

/* Get random packet length */
int GetRandPktLen()
{
    // Minimum packet length is 64 bytes
    return (64 + GetRandNum() % (1518 - 64));
}

/* Get increase packet length */
int GetIncrPktLen()
{
    // Minimum packet length is 64 bytes
    static int iLength = 64;
    return ((iLength >= 1518) ? 64 : iLength++); 
}

/* Get random VLAN ID */
int GetRandVlan()
{
    // 0 and 4095 retain VLAN, 1 is Management VLAN
    return (2 + GetRandNum() % (4095 - 2));
}

/* Get increased VLAN ID */
int GetIncrVlan(int iVoQ)
{
    if (iVoQ < 0 || iVoQ > 1) {
        LOGRECORD(ERROR, "Unrecognized identifier");
    }

    static int iVlanId[] = {0, 0};
    return ((iVlanId[iVoQ] > 4094) ? 1 : iVlanId[iVoQ]++);
}

/* Get random protocol */
uint8_t GetRandL4HexPro()
{
    uint8_t iResPro;
    
    // UDP:45% TCP:45% ICMP4:10%
    switch(random() % 100 / 45) {
        case 0 : iResPro = UDP;
        case 1 : iResPro = TCP;
        case 2 : iResPro = ICMP4;
    }

    return iResPro;
}

/* Get random protocol with string format */
char* GetStrPro(uint16_t iHexPro)
{
    char* pStrPro = NULL;

    switch(iHexPro) {
        case ARP    : pStrPro = "ARP";  
        case VLAN   : pStrPro = "VLAN";  
        case ICMP4 : pStrPro = "ICMP4";  
        case IPv4   : pStrPro = "IPv4";  
        case UDP    : pStrPro = "UDP";  
        case TCP    : pStrPro = "TCP";  
        default     : LOGRECORD(ERROR, "Protocol not identified");
    }

    return pStrPro;
}

/* Get layer three protocol number*/
uint16_t GetL3HexPro(char* pStrPro)
{
    if (pStrPro == NULL) {
        LOGRECORD(ERROR, "Layer 3 protocol string is NULL");
    }

    uint16_t iResPro = 0;

    if (strcmp(pStrPro, "ARP") == 0) {
        iResPro = ARP;
    } else if (strcmp(pStrPro, "VLAN") == 0) { 
        iResPro = VLAN;
    } else if (strcmp(pStrPro, "IPv4") == 0) { 
        iResPro = IPv4;
    } else {
        LOGRECORD(ERROR, "Protocol input error");
    }

    return iResPro;
}

/* Get layer four protocol number*/
uint8_t GetL4HexPro(char* pStrPro)
{
    if (pStrPro == NULL) {
        LOGRECORD(ERROR, "Layer 3 protocol string is NULL");
    }

    uint8_t iResPro = 0;

    if (strcmp(pStrPro, "ICMP4") == 0) {
        iResPro = ICMP4;
    } else if (strcmp(pStrPro, "TCP") == 0) {
        iResPro = TCP;
    } else if (strcmp(pStrPro, "UDP") == 0) {
        iResPro = UDP;
    }

    return iResPro;
}

int GetDataLen(int iPktLen)
{
    int iDataLen = 0;
    char* pL4Pro = GetcValue("l4pro");
    if (strcmp(pL4Pro, "UDP") == 0) {
        iDataLen = iPktLen - MACHDRLEN - IP4HDRLEN - UDPHDRLEN;
    } else if (strcmp(pL4Pro, "TCP") == 0) {
        iDataLen = iPktLen - MACHDRLEN - IP4HDRLEN - TCPHDRLEN;
    }

    return iDataLen;
}

/* Output program progress */
void ProgramProgress(int iVaribleNum, int iStanderNum)
{
    // To display program process with 20 '>'
    int iProgressBarLength = 20;
    int iProgressPercent = iVaribleNum * iProgressBarLength / iStanderNum ;
    static int iProgressPercentLength = 2; // Percentage position length
    static int iLastPercent = -1; // Remeber last percent, can't equal
    static unsigned int iCounter = 1;

    int iNumI, iNumJ, iNumK;
    if (iProgressPercent != iLastPercent) {
        if (iCounter != 1) {
            // Back to init state
            for (iNumI=0; iNumI<iProgressBarLength+iProgressPercentLength; iNumI++) {
                putchar('\b');
            }
        }

        // Progress display
        for (iNumJ=0; iNumJ<iProgressPercent; iNumJ++) {
            putchar('>');
        }
        for (iNumK=iProgressBarLength-1; iNumK>=iProgressPercent; iNumK--) {
            putchar('=');
        }
        // True percentage
        printf("%d%%", iProgressPercent * (100 / iProgressBarLength)); 

        iLastPercent = iProgressPercent;
        fflush(stdout);

        // Correction is greater than 10% of the show 
        if (iProgressPercent > 1) {
            iProgressPercentLength = 3;
        }
        iCounter++;
    }
}

/* Display packet */
void DisplayPacketData(char* pPacket, int iPacketLength)
{
    if (pPacket == NULL || iPacketLength <= 0) {
        LOGRECORD(ERROR, "Packet display failed");
    }

    int iNum = 0;
    for (; iNum<iPacketLength; iNum+=2) {
        printf("%02hhx%02hhx ", pPacket[iNum], pPacket[iNum+1]);
        if (iNum%16 == 14) {
            printf("\n");
        }
    }
    printf("\n");
}

/* Copy function */
void BufferCopy(char* pDstBuf, int iPos, char* pSrcStr, int iLength)
{
    int iNum = 0;
    for (; iNum<iLength; iNum++)
        pDstBuf[iPos+iNum] = pSrcStr[iNum];
}

/* Compare IPv6 address */
int CompareIpv6Address(unsigned char* pSrcIp6Addr, unsigned char* pDstIp6Addr)
{
    int iNum = 0;
    int iLength = sizeof(struct in6_addr);
    for (; iNum<iLength; iNum++) {
        if (pSrcIp6Addr[8+iNum] != pDstIp6Addr[iNum])
            return -1 ;
    }

    return 0;
}

/* Packet format conversion to *.pcap */
void SwitchPcapFormat()
{
    char* pReadFile = GetcValue("read");
    char* pSaveFile = GetcValue("save");

    if (pReadFile == NULL || pSaveFile == NULL) {
        LOGRECORD(ERROR, "Incomplete command");
    }

    char cCmdBuf[SIZE_16B*2] = "tcpdump -r ";
    sprintf(cCmdBuf, "%s%s%s", pReadFile, " -w ", pSaveFile);
    if (system(cCmdBuf) > 0) {
        LOGRECORD(ERROR, "Command <tcpdump> not install");
    }
}

/* Get the descriptor of the file being written */
int OpenSaveFile(char* pFileName)
{
    int iSaveFd = 0;
    if (pFileName == NULL) {
        LOGRECORD(ERROR, "Filename is NULL");
    }
    if ((iSaveFd = open(pFileName, \
        O_WRONLY | O_CREAT | O_APPEND, PERM)) < 0 ) {
        LOGRECORD(ERROR, "Open save-file failed:%d", iSaveFd);
    }

    return iSaveFd;
}

/* Get the descriptor of the file being read */
int OpenReadFile(char* pFileName)
{
    int iReadFd = 0;
    if (pFileName == NULL) {
        LOGRECORD(ERROR, "Filename is NULL");
    }
    if ((iReadFd = open(pFileName, O_RDONLY)) < 0 ) {
        LOGRECORD(ERROR, "Open read-file failed:%d", iReadFd);
    }

    return iReadFd;
}

