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


int iIpArray[][4] = { 
    {1, 0, 0, 0}, 
    {1, 0, 0, 0} 
};

char cIpAddress[][20] = {"",""};
char cMacAddress[][20] = {
    "00:00:00:00:00:00",
    "00:00:00:00:00:00"
};

char    ram_buf[2000] = {0};
char    url[30];
char    mopt[100];
char    substr[1500];

/* Calculate udp, tcp or icmp checksum */
uint16_t GetCheckSum(uint16_t* buf, int len)
{
    unsigned long sum;
    for (sum=0; len>0; len--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}

/* Get hexadecimal charator */
char ChangeHexToString(int iChoice)
{
    switch(iChoice) {
        case 0:  return '0';
        case 1:  return '1';
        case 2:  return '2';
        case 3:  return '3';
        case 4:  return '4';
        case 5:  return '5';
        case 6:  return '6';
        case 7:  return '7';
        case 8:  return '8';
        case 9:  return '9';
        case 10: return 'A';
        case 11: return 'B';
        case 12: return 'C';
        case 13: return 'D';
        case 14: return 'E';
        case 15: return 'F';
    }

    return -1;
}

/* URL generator */
char* GetUrlString()
{
    memset(url,0,sizeof(url));
    strcat(url,"www.");
    strcat(url,GetRandomString(5));
    strcat(url,".com/");
    strcat(url,GetRandomString(6));

    return url;
}

/* Get sub string */
char* subs(char *s, int n, int m)
{
    memset(substr, 0, sizeof(substr));
    memcpy(substr, &s[n], m);

    return substr;
}

/* Get a random number with microsecond */
int GetRandomNumber()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    srandom(tp.tv_usec + tp.tv_sec);

    return random();
}

/* Get random string */
char* GetRandomString(int iLength)
{
    int iNum;
    int iRandomNum = 0;

    for (iNum = 0; iNum < iLength; iNum++) {
        iRandomNum = GetRandomNumber() % 200;
        if (((iRandomNum <= 122) && (iRandomNum >= 97)) ||
                ((iRandomNum <= 90) && (iRandomNum >= 65)) ||
                ((iRandomNum <= 57) && (iRandomNum >= 48))) {
            sprintf((char *)ram_buf + iNum, "%c", iRandomNum);
        } else {
            iNum--;
        }
    }

    return ram_buf;
}

/* Get random MAC address */
char* GetRandMacAddr(int iSmacOrDmac)
{
    int iMacLenth;
    iMacLenth = strlen(cMacAddress[iSmacOrDmac]);
    while (iMacLenth != 2) {
        iMacLenth--;
        if (cMacAddress[iSmacOrDmac][iMacLenth] == ':') {
            continue;
        }
        cMacAddress[iSmacOrDmac][iMacLenth] \
            = ChangeHexToString(GetRandomNumber()%15);
    }
    return cMacAddress[iSmacOrDmac];
}

/* Get increment MAC address */
char* GetIncrMacAddr(int iSmacOrDmac)
{
    int iMacLenth;
    iMacLenth = strlen(cMacAddress[iSmacOrDmac]) - 1;
    while (iMacLenth != -1) {
        if (cMacAddress[iSmacOrDmac][iMacLenth] == '9') {
            cMacAddress[iSmacOrDmac][iMacLenth] = 'a' -1;
        }
        if (cMacAddress[iSmacOrDmac][iMacLenth] == 'f' 
                || cMacAddress[iSmacOrDmac][iMacLenth] == ':') {
            if (cMacAddress[iSmacOrDmac][iMacLenth] == 'f') {
                cMacAddress[iSmacOrDmac][iMacLenth] = '0';
            }
            iMacLenth--;
        } else {
            cMacAddress[iSmacOrDmac][iMacLenth]++;
            break;
        }
    }
    return cMacAddress[iSmacOrDmac];
}

/* Writes a string MAC address to the packet */
int FillInMacAddr(char *pMacStr, char *pMacBuf)
{
    if ((pMacBuf == NULL) || (pMacStr == NULL)) {
        return -1;
    }

    int i = 0;
    char *pMacTmp = NULL;
    for (; i < 6; i++) {
        pMacBuf[i] = pMacStr ? strtoul (pMacStr, &pMacTmp, 16) : 0;
        if (pMacStr) {
            pMacStr = (*pMacTmp) ? pMacTmp + 1 : pMacTmp;
        }
    }

    return 0;
}

/* Check the legality of the IP address */
int CheckIpLegal(char* pIpStr)
{
    int iCheckRes;
    int iNum[4];
    char cDot[3];
    char *pIpToken = NULL;
    char cTmpArray[50];

    // The legitimacy of the detection with ":" separated IP address 
    if (strchr(pIpStr, ':') != NULL) { // eg: -s 1.1.1.1:2.2.2.2
        memset(cTmpArray, 0, sizeof(cTmpArray));
        memcpy(cTmpArray, pIpStr, strlen(pIpStr));
        if ((pIpToken = strtok(cTmpArray, ":")) != NULL) { // First IP
            iCheckRes = CheckIpLegal(pIpToken);
            if (iCheckRes == SUCCESS) { // Second IP
                pIpToken = strtok(NULL, ":"); 
                iCheckRes = CheckIpLegal(pIpToken);
                if (iCheckRes == SUCCESS) return 2;
                else return FALSE;
            } else {
                return FALSE;
            }
        }
    } 
    
    // IP address detection 
    if (sscanf(pIpStr, "%d%c%d%c%d%c%d", 
            &iNum[0], &cDot[0], &iNum[1], &cDot[1],
            &iNum[2], &cDot[2], &iNum[3]) == 7) {
        int i;
        for (i = 0; i < 3; ++i)
            if (cDot[i] != '.')
                return ERROR;
        for (i = 0; i < 4; ++i)
            if (iNum[i] > 255 || iNum[i] < 0)
                return ERROR;
        return SUCCESS;
    }

    return ERROR;
}

/* Get random IP address */
char* GetRandIp4Addr(int iSOrDIp)
{
    sprintf(cIpAddress[iSOrDIp], "%d.%d.%d.%d", 
            GetRandomNumber() % 255 + 1,
            GetRandomNumber() % 256,
            GetRandomNumber() % 256,
            GetRandomNumber() % 255 + 1
           );
    return cIpAddress[iSOrDIp];
}

/* Get increased IP address */
char* GetIncrIp4Addr(int iSOrDIp)
{
    if (++iIpArray[iSOrDIp][3] > 255) { 
        iIpArray[iSOrDIp][3] = 1;
        iIpArray[iSOrDIp][2]++;
    } else if (iIpArray[iSOrDIp][2] > 255) { 
        iIpArray[iSOrDIp][2] = 0;
        iIpArray[iSOrDIp][1]++;
    } else if (iIpArray[iSOrDIp][1] > 255) { 
        iIpArray[iSOrDIp][1] = 0;
        iIpArray[iSOrDIp][0]++;
    }

    sprintf(cIpAddress[iSOrDIp], "%d.%d.%d.%d",
            iIpArray[iSOrDIp][0],
            iIpArray[iSOrDIp][1],
            iIpArray[iSOrDIp][2],
            iIpArray[iSOrDIp][3]
           );

    return cIpAddress[iSOrDIp];
}

/* Get increased port */
int GetIncreasePort(int iSoD)
{
    static int siPortArray[] = {0, 0};
    if (siPortArray[iSoD]++ > 65535) {
        siPortArray[iSoD] = 0;
    }
    return siPortArray[iSoD];
}

/* Get random port */
int GetRandomPort()
{
    return (1 + GetRandomNumber() % (65535 - 1));
}

/* Get random packet length */
int GetRandomPacketLength()
{
    return (64 + GetRandomNumber() % (1518 - 64));
}

/* Get increase packet length */
int GetIncreasePacketLength()
{
    static int iLength=64;
    if (iLength > 1518) {
        iLength = 64;
    }

    return iLength++;
}

/* Get random VLAN ID */
int GetRandVlan()
{
    return (2 + GetRandomNumber() % (4096 - 2));
}

/* Get increased VLAN ID */
int GetIncrVlan(int flag)
{
    int res = -1;
    static int vlan = 0;
    static int qinq = 0;
    if (!flag) {
        if (vlan++ > 4094) {
            vlan = 1;
        }
        res = vlan;
    } else {
        if (qinq++ > 4094) {
            qinq = 1;
        }
        res = qinq;
    }

    return res;
}

/* Get random protocol */
uint8_t GetRandomLayer4Pro()
{
    int iRandomNum = random() % 3;
    if (iRandomNum == 0) {
        return UDP;
    } else if (iRandomNum == 1) {
        return TCP;
    } else {
        return ICMPv4;
    }
}

/* Get random protocol with string format */
char* ChangeLayer4HexToString(uint16_t pro)
{
    switch(pro) {
        case ARP:    return "ARP";  
        case VLAN:   return "VLAN";  
        case ICMPv4: return "ICMPv4";  
        case IPv4:   return "IPv4";  
        case UDP:    return "UDP";  
        case TCP:    return "TCP";  
        default:     return "Unknown"; 
    }
}

/* Get layer three protocol number*/
uint16_t GetL3Hex(char* pro)
{
    uint16_t tmp = 0;
    if (strcmp(pro, "ARP") == 0) {
        tmp = ARP;
    } else if (strcmp(pro, "VLAN") == 0) { 
        tmp = VLAN;
    } else if (strcmp(pro, "IPv4") == 0) { 
        tmp = IPv4;
    }

    return tmp;
}

/* Get layer four protocol number*/
uint8_t GetL4Hex(char* pro)
{
    uint8_t tmp = 0;
    if (strcmp(pro, "ICMPv4") == 0) {
        tmp = ICMPv4;
    } else if (strcmp(pro, "TCP") == 0) {
        tmp = TCP;
    } else if (strcmp(pro, "UDP") == 0) {
        tmp = UDP;
    }

    return tmp;
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

    int i, j, k;
    if (iProgressPercent != iLastPercent) {
        if (iCounter != 1) {
            // back to init state
            for (i=0; i<iProgressBarLength+iProgressPercentLength; i++) {
                putchar('\b');
            }
        }

        // Progress display
        for (j=0; j<iProgressPercent; j++) {
            putchar('>');
        }
        for (k=iProgressBarLength-1; k>=iProgressPercent; k--) {
            putchar('=');
        }
        printf("%d%%", iProgressPercent * (100 / iProgressBarLength)); // true percentage

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
void DisplayPacketData(char* pcPacket, int iPacketLength)
{
    int iNum;
    for (iNum=0; iNum<iPacketLength; iNum+=2) {
        printf("%02hhx%02hhx ", pcPacket[iNum], pcPacket[iNum+1]);
        if (iNum%16 == 14) {
            printf("\n");
        }
    }
    printf("\n");
}

/* Copy function */
void BufferCopy(char* dst, int pos, char* src, int len)
{
    int i;
    for (i=0; i<len; i++)
        dst[pos+i] = src[i];
}

/* Compare IPv6 address */
int CompareIpv6Address(unsigned char* src,unsigned char* dst)
{
    int len = sizeof(struct in6_addr), i;
    for (i=0; i<len; i++) {
        if (src[8+i] != dst[i])
            return -1 ;
    }

    return 0;
}

/* Get hexadecimal protocol number */
int ProtocolConversion(char* cpProtocol)
{
    if (strcmp(cpProtocol, "ip") == 0) {
        return IPv4;
    } else if (strcmp(cpProtocol, "arp") == 0) {
        return ARP;
    } else if (strcmp(cpProtocol, "vlan") == 0) {
        return VLAN; 
    } else if (strcmp(cpProtocol, "icmp") == 0) {
        return ICMPv4; 
    } else if (strcmp(cpProtocol, "tcp") == 0) {
        return TCP; 
    } else if (strcmp(cpProtocol, "udp") == 0) {
        return UDP; 
    }

    return 0;
}

/* Packet format conversion to *.pcap */
void SwitchPcapFormat()
{
    char* pReadFile = GetcValue("pReadFile");
    char* pSaveFile = GetcValue("pSaveFile");

    char cCmdBuf[32] = "tcpdump -r ";
    strcat(cCmdBuf, pReadFile);
    strcat(cCmdBuf, " -w ");
    strcat(cCmdBuf, pSaveFile);
    if (system(cCmdBuf) > 0) {
        LOGRECORD(ERROR, "Command \"tcpdump\" execution failed!");
    }
}

/* Gets the descriptor of the file being written */
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

/* Gets the descriptor of the file being read */
int OpenReadFile(char* pFileName)
{
    int iReadFd = 0;
    if (pFileName == NULL) {
        LOGRECORD(ERROR, "Filename is NULL");
    }
    if ((iReadFd = open(pFileName, O_RDONLY)) < 0 ) {
        LOGRECORD(ERROR, "Pcap file does not exist");
    }

    return iReadFd;
}

