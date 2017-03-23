#include    <string.h>
#include    "common.h"
#include    "runlog.h"
#include    "storage.h"

#define SRC 0 
#define DST 1

/* packet structure */
static stPktStrc stPkt;


/* Replace input based on regular expressions */
void RegularExpress()
{
    char  cExpBuf[SIZE_1K];
    char* pExpStr = GetcValue("expression");
    memcpy(cExpBuf, pExpStr, strlen(pExpStr));

    char* pPosStr = NULL;
    char* pRepStr[2];
    if (cExpBuf != NULL) {
        pPosStr = strtok(cExpBuf, ",");
        pRepStr[0] = strtok(NULL, ",");
        pRepStr[1] = strtok(NULL, ",");
    }

    if (pPosStr && pRepStr[0] && pRepStr[1]) {
        int iNumI = 0;
        int iNumJ = 0;
        if (strcmp(pPosStr, "IP") == 0) {
            U32* pIpPos[] = {
                (U32 *)&stPkt.pIp4Hdr->sip, 
                (U32 *)&stPkt.pIp4Hdr->dip
            };

            for (iNumI = 0; iNumI < 2; iNumI ++) {
                for (iNumJ = 0; iNumJ < 2; iNumJ ++) {
                    if (*pIpPos[iNumI] == inet_addr(pRepStr[0])) {
                        *pIpPos[iNumI] =  inet_addr(pRepStr[1]);
                    }
                }
            } // End of for
        } else if (strcmp(pPosStr, "PORT") == 0) {
            U16* pPortPos[][2] = {
                {(U16 *)&stPkt.pUdpHdr->sport, (U16 *)&stPkt.pUdpHdr->dport},
                {(U16 *)&stPkt.pTcpHdr->sport, (U16 *)&stPkt.pTcpHdr->dport}
            }; 

            int iPro = -1;
            U8  iL4Pro = stPkt.pIp4Hdr->protocol;
            if (iL4Pro == UDP) {
                iPro = 0;
                printf("--------------------udp\n");
            } else if (iL4Pro == TCP) {
                iPro = 1;
            }

            if (iPro != -1) {
                for (iNumI = 0; iNumI < 2; iNumI ++) {
                    for (iNumJ = 0; iNumJ < 2; iNumJ ++) {
                        if (*pPortPos[iPro][iNumI] == htons(atoi(pRepStr[0]))) {
                            *pPortPos[iPro][iNumI] =  htons(atoi(pRepStr[1]));
                        }
                    }
                } // End of for
            }
        } // End of PORT 
    } // End of if
}

/* Determine whether the parameters need to be modified */
int IsNeedModify(char* title)
{    
    int iResNum = 0;
    if (GetFlag(title) > 1) { // need modify
        iResNum = 1;
    }

    return iResNum;
}

/* To determine whether the source or destination */
int JudgeSourceOrDestination(char* title)
{
    char* pSrc[] = {"smac", "sip", "sport", "vlan"};
    char* pDst[] = {"dmac", "dip", "dport", "qinq"};

    int iNum;
    int iLength = sizeof(pSrc) / sizeof(char*);
    for (iNum = 0; iNum < iLength; iNum ++) {
        if (strcmp(title, pSrc[iNum]) == 0) {
            return SRC;
        } 
    }

    iLength = sizeof(pDst) / sizeof(char*);
    for (iNum = 0; iNum < iLength; iNum ++) {
        if (strcmp(title, pDst[iNum]) == 0) {
            return DST;
        } 
    }

    // False
    LOGRECORD(DEBUG, "Neither the source nor the destination");
    return -1;
}

/* Modify port number */
void ModifyPortNumber(char* title, U8 iPro) //sport:0,dport:1
{
    U16* pPortPos[] = {
        (U16 *)&stPkt.pUdpHdr->sport, 
        (U16 *)&stPkt.pUdpHdr->dport,
        (U16 *)&stPkt.pTcpHdr->sport, 
        (U16 *)&stPkt.pTcpHdr->dport
    }; 

    int iSoD = JudgeSourceOrDestination(title);
    int iPos = iSoD * ((iPro == UDP) ? 1 : 2);

    switch(GetFlag(title)) {
        case FG_FIXD : *pPortPos[iPos] = htons(GetiValue(title)); break;
        case FG_RAND : *pPortPos[iPos] = htons(GetRandPort()); break;
        case FG_INCR : *pPortPos[iPos] = htons(GetIncrPort(iSoD)); break;
    }
}

/* Modify VLAN ID number */
void ModifyVlanId(char* title)
{
    U16* pVlanPos[] = {
        (U16 *)&stPkt.pVlanHdr->id, 
        (U16 *)&stPkt.pQinQHdr->id
    }; 

    // iVoQ: vlan or qinq 
    int iVoQ = JudgeSourceOrDestination(title);

    switch(GetFlag(title)) {
        case FG_FIXD : *pVlanPos[iVoQ] = htons(GetiValue(title)); break;
        case FG_RAND : *pVlanPos[iVoQ] = htons(GetRandVlan(iVoQ)); break;
        case FG_INCR : *pVlanPos[iVoQ] = htons(GetIncrVlan(iVoQ)); break;
    }
}

/* Add multilayer VLAN Tags */
void InsertVlanInfo(int iHasVlanLayer)
{
    _vlanhdr* pVlanInfo[] = {
        stPkt.pVlanHdr,
        stPkt.pQinQHdr
    }; 

    int iVlanId = iHasVlanLayer ? GetiValue("qinq") : GetiValue("vlan");
    int iPktLen = stPkt.pPktHdr->len;
    int iCursor = MAC_HDR_LEN + iHasVlanLayer * VLAN_TAG_LEN;

    // Move packet
    int iNum;
    int iLength = iPktLen - iCursor;
    for (iNum = 0; iNum < iLength; iNum ++) {
        stPkt.pPacket[iPktLen+VLAN_TAG_LEN-1-iNum] \
            = stPkt.pPacket[iPktLen-1-iNum]; 
    }

    // Insert VLAN ID
    pVlanInfo[iHasVlanLayer] = (_vlanhdr*) (stPkt.pPacket + iCursor);
    pVlanInfo[iHasVlanLayer]->id = htons(iVlanId);
    stPkt.pPktHdr->caplen = stPkt.pPktHdr->len += VLAN_TAG_LEN;

    if (iHasVlanLayer == 0) {
        stPkt.pVlanHdr = pVlanInfo[iHasVlanLayer];
        pVlanInfo[iHasVlanLayer]->pro = stPkt.pMacHdr->pro;    
        stPkt.pMacHdr->pro = htons(VLAN);
    } else if (iHasVlanLayer == 1) {
        pVlanInfo[iHasVlanLayer]->pro = stPkt.pVlanHdr->pro;    
        pVlanInfo[iHasVlanLayer-1]->pro = htons(VLAN);   
    }
}

/* Delete multilayer VLAN Tags */
void DeleteVlanInfo(int iHasVlanLayer, int iDirect)
{
    int iCursor = 0;
    if (iHasVlanLayer > 0) {
        if (iDirect == 0) { // Delete a VLAN ID from the front 
            iCursor = MAC_HDR_LEN;
            stPkt.pMacHdr->pro = stPkt.pVlanHdr->pro;
        } else if (iDirect == 1) { // Delete a VLAN ID from the rear
            iCursor = MAC_HDR_LEN + (iHasVlanLayer - 1) * VLAN_TAG_LEN;
            if (iHasVlanLayer == 1) {
                stPkt.pMacHdr->pro = stPkt.pVlanHdr->pro;
            } else if (iHasVlanLayer == 2) {
                stPkt.pVlanHdr->pro = stPkt.pQinQHdr->pro;
            }
        }

        // Move the packet
        int iNum;
        int iLength = stPkt.pPktHdr->len - iCursor;
        for (iNum = 0; iNum < iLength; iNum ++) {
            stPkt.pPacket[iCursor+iNum-1] = \
                                            stPkt.pPacket[iCursor+VLAN_TAG_LEN+iNum-1];
        }

        stPkt.pPktHdr->caplen = stPkt.pPktHdr->len -= VLAN_TAG_LEN;
    } // End of if
}

/* Modify IP address */
void ModifyIpAddress(char* title) //sip:0,dip:1
{
    U32* pIpPos[] = {
        (U32 *)&stPkt.pIp4Hdr->sip, 
        (U32 *)&stPkt.pIp4Hdr->dip
    }; 

    // iSoD: sip or dip
    int iSoD = JudgeSourceOrDestination(title);
    switch(GetFlag(title)) {
        case FG_FIXD : *pIpPos[iSoD] = inet_addr(GetcValue(title)); break;
        case FG_RAND : *pIpPos[iSoD] = inet_addr(GetRandIp4Addr()); break;
        case FG_INCR : *pIpPos[iSoD] = inet_addr(GetIncrIp4Addr(iSoD)); break;
    }
}

/* Modify UDP header information */
void ModifyUdpHdr() 
{
    char* pParaList[] = {"sport", "dport"};
    int iLength = sizeof(pParaList) / sizeof(char*);

    int iNum;
    for (iNum = 0; iNum < iLength; iNum ++) {
        if (IsNeedModify(pParaList[iNum])) {
            ModifyPortNumber(pParaList[iNum], UDP);
        }
    }
}

/* Modify TCP header information */
void ModifyTcpHdr() 
{
    char* pParaList[] = {"sport", "dport"};
    int iLength = sizeof(pParaList) / sizeof(char*);

    int iNum;
    for (iNum = 0; iNum < iLength; iNum ++) {
        if (IsNeedModify(pParaList[iNum])) {
            ModifyPortNumber(pParaList[iNum], TCP);
        }
    }
}

/* Modify IPv4 header information */
void ModifyIPv4Hdr()
{
    char* pParaList[] = {"sip", "dip"};
    int iLength = sizeof(pParaList) / sizeof(char*);

    int iNum;
    for (iNum = 0; iNum < iLength; iNum ++) {
        if (IsNeedModify(pParaList[iNum])) {
            ModifyIpAddress(pParaList[iNum]);
        }
    }
}

/* Modify VLAN information */
void ModifyVlanHdr()
{
    char* pParaList[] = {"vlan", "qinq"};
    int iLength = sizeof(pParaList) / sizeof(char*);

    // Get current VLAN layer number
    int iCurVlanNum = 0;   
    if (stPkt.pQinQHdr != NULL) {
        iCurVlanNum = 2;
    } else if (stPkt.pVlanHdr != NULL) {
        iCurVlanNum = 1;
    }

    // Get input VLAN layer number
    int iNum;
    int iVlanId = 0;
    int iInputVlanNum = 0;   

    for (iNum = 0; iNum < iLength; iNum ++) {
        iVlanId = GetiValue(pParaList[iNum]);

        if (iVlanId > 0) {
            iInputVlanNum ++;   
            if (iCurVlanNum == iNum) {
                InsertVlanInfo(iCurVlanNum);
                iCurVlanNum ++;
            } else if (iCurVlanNum > iNum) {
                ModifyVlanId(pParaList[iNum]);
            }
        } else if (iVlanId < 0) { // Delete VLAN tag
            if (iCurVlanNum >= iNum) {
                DeleteVlanInfo(iCurVlanNum, iNum);
                iCurVlanNum--;
            }
        }
    } // End of for
}

/* Modify IPv6 header information */
void ModifyIPv6Hdr()
{
    /*
       unsigned char buf1[sizeof(struct in6_addr)];
       unsigned char buf2[sizeof(struct in6_addr)];
       if (sip_tag) {
       pIp4Hdr->sip = inet_pton(AF_INET6, sip, buf1);
       BufferCopy(packetbuf, 32, buf1, sizeof(struct in6_addr));
       }
       if (dip_tag) {
       pIp4Hdr->dip = inet_pton(AF_INET6, dip, buf2);
       BufferCopy(packetbuf, 48, buf2, sizeof(struct in6_addr));
       }
       */
}

/* Modify the MAC address */
void ModifyMacHdr(char* title) //smac:0,dmac:1
{
    char* pMacPos[] = {
        (char *)stPkt.pMacHdr->smac, 
        (char *)stPkt.pMacHdr->dmac
    }; 

    // iSoD: smac or dmac
    int iSoD = JudgeSourceOrDestination(title);

    char* pMacAddr = GetcValue(title);
    switch(GetFlag(title)) {
        case FG_FIXD : FillInMacAddr(pMacAddr, pMacPos[iSoD]); break;
        case FG_RAND : FillInMacAddr(GetRandMacAddr(iSoD), pMacPos[iSoD]); break;
        case FG_INCR : FillInMacAddr(GetIncrMacAddr(iSoD), pMacPos[iSoD]); break;
    }
}

/* Modify Layer 4 protocol information */
void ModifyLayer4()
{
    U8 iPro = stPkt.pIp4Hdr->protocol;
    switch (iPro) {
        case UDP : ModifyUdpHdr(); break;
        case TCP : ModifyTcpHdr(); break;
        case ICMP4 : break;
    }
}

/* Modify Layer 3 protocol information */
void ModifyLayer3()
{
    int iL3Pro = ((GetiValue("vlan") != 0 
                || GetiValue("qinq") != 0)) ? VLAN : stPkt.pMacHdr->pro; 

    switch (iL3Pro) {
        case IPv4 : ModifyIPv4Hdr(); break;
        case VLAN : ModifyVlanHdr(); break;
        case IPv6 : ModifyIPv6Hdr(); break;
        case ARP  : break;
    }
}

/* Modify Layer 2 protocol information */
void ModifyLayer2()
{
    char* pParaList[] = {"smac", "dmac"};
    int iLength = sizeof(pParaList) / sizeof(char*);

    int iNum;
    for (iNum = 0; iNum < iLength; iNum ++) {
        if (IsNeedModify(pParaList[iNum])) {
            ModifyMacHdr(pParaList[iNum]);
        }
    }
}

/* Message modification program entry */
void ModifyPacket(stPktStrc stOriginPktStrc)
{
    stPkt = stOriginPktStrc;
    ModifyLayer2();
    ModifyLayer3();
    ModifyLayer4();
    RegularExpress();
}

