/*******************************************************
 *
 *  Author        : Mr.Gao
 *  Email         : 729272771@qq.com
 *  Filename      : modify.c
 *  Last modified : 2017-04-25 14:11
 *  Description   : Modify packet
 *
 * *****************************************************/


#include    <string.h>
#include    "func.h"
#include    "common.h"
#include    "runlog.h"
#include    "storage.h"
#include    "modify.h"


stPktStrc stPkt;
stChgList stChg;
stCndList stCon;

void ChangeListInit()
{
    stChg.mac[0]  = NULL;
    stChg.mac[1]  = NULL;
    stChg.ip4[0]  = 0;
    stChg.ip4[1]  = 0;
    stChg.port[0] = -1;
    stChg.port[1] = -1;
    stChg.vlan[0] = -1;
    stChg.vlan[1] = -1;
}

void GenerateMacAddr(char* pTitle, int iSoD) //smac:0,dmac:1
{
    switch(GetState(pTitle)) {
        case FG_FIXD : stChg.mac[iSoD] = GetStr(pTitle); break;
        case FG_RAND : stChg.mac[iSoD] = GetRandMacAddr(iSoD); break;
        case FG_INCR : stChg.mac[iSoD] = GetIncrMacAddr(iSoD); break;
    }
}

void GenerateVlanTag(char* pTitle, int iVoQ)
{
    switch(GetState(pTitle)) {
        case FG_FIXD : stChg.vlan[iVoQ] = GetNum(pTitle); break;
        case FG_RAND : stChg.vlan[iVoQ] = GetRandVlan(iVoQ); break;
    }
}

void GenerateIp4Addr(char* pTitle, int iSoD)
{
    int* stConBakIp[] = {
        (int*)&stCon.ip1[1],
        (int*)&stCon.ip2[1]
    };

    switch(GetState(pTitle)) {
        case FG_FIXD : stChg.ip4[iSoD] = inet_addr(GetStr(pTitle)); break;
        case FG_RAND : stChg.ip4[iSoD] = inet_addr(GetRandIp4Addr(iSoD)); break;
        case FG_INCR : stChg.ip4[iSoD] = inet_addr(GetIncrIp4Addr(iSoD)); break;
    }

    *stConBakIp[iSoD] = stChg.ip4[iSoD];
}

void GeneratePortNum(char* pTitle, int iSoD)
{
    switch(GetState(pTitle)) {
        case FG_FIXD : stChg.port[iSoD] = htons(GetNum(pTitle)); break;
        case FG_RAND : stChg.port[iSoD] = htons(GetRandPort(iSoD)); break;
        case FG_INCR : stChg.port[iSoD] = htons(GetIncrPort(iSoD)); break;
    }
}

int JudgeSoD(int iSoD)
{ 
    int iResNum = -1;
    if (stPkt.pIp4Hdr->sip == stCon.ip1[0] 
            || stPkt.pIp4Hdr->dip == stCon.ip2[0]) {
        if (iSoD == M_SRC) {
            iResNum = M_SRC;
        } else if (iSoD == M_DST) {
            iResNum = M_DST;
        }
    } else if (stPkt.pIp4Hdr->sip == stCon.ip2[0] 
            || stPkt.pIp4Hdr->dip == stCon.ip1[0]) {
        if (iSoD == M_SRC) {
            iResNum = M_DST;
        } else if (iSoD == M_DST) {
            iResNum = M_SRC;
        }
    } else {
        if (stPkt.pIp4Hdr->sip == stCon.ip1[1] 
                || stPkt.pIp4Hdr->dip == stCon.ip2[1]) {
            if (iSoD == M_SRC) {
                iResNum = M_SRC;
            } else if (iSoD == M_DST) {
                iResNum = M_DST;
            }
        } else if (stPkt.pIp4Hdr->sip == stCon.ip2[1] 
                || stPkt.pIp4Hdr->dip == stCon.ip1[1]) {
            if (iSoD == M_SRC) {
                iResNum = M_DST;
            } else if (iSoD == M_DST) {
                iResNum = M_SRC;
            }
        } else {
            LOGRECORD(ERROR, "Packet matching failure");
        }
    }

    return iResNum;
}

void ModifyMacAddr(int iSoD)
{
    char* pMacPos[] = {
        (char *)stPkt.pMacHdr->smac, 
        (char *)stPkt.pMacHdr->dmac
    }; 

    FillInMacAddr(pMacPos[JudgeSoD(iSoD)], stChg.mac[iSoD]); 
}

/* Modify IPv4 head into IPv6 header */
void ChangeIp4ToIp6()
{
    int iVlanNum = 0;
    // Determine the premise of data modification
    if (stPkt.pMacHdr->pro == htons(IPv4)) {
        stPkt.pMacHdr->pro = htons(IPv6);
    } else if (stPkt.pQinQHdr != NULL) {
        iVlanNum = 2;
        stPkt.pQinQHdr->pro = htons(IPv6);
    } else if (stPkt.pVlanHdr != NULL) {
        iVlanNum = 1;
        stPkt.pVlanHdr->pro = htons(IPv6);
    } else {
        return;
    }

    // Record the valid information in the IPv4 header
    U16 iL4Pro = stPkt.pIp4Hdr->pro;
    int iPktLen = stPkt.pPktHdr->len;
    int iIp4Len = iPktLen - MAC_HDR_LEN  - iVlanNum * VLAN_TAG_LEN;
    int iIp4HdrLen = stPkt.pIp4Hdr->hdlen;
    int iAddLen = IP6_HDR_LEN - iIp4HdrLen;
    int iPaddingLen = stPkt.pPktHdr->len - MAC_HDR_LEN 
        - iVlanNum * VLAN_TAG_LEN - htons(stPkt.pIp4Hdr->ttlen);
    U32 iSip = stPkt.pIp4Hdr->sip;
    U32 iDip = stPkt.pIp4Hdr->dip;

    // Move backward IPv4 data part
    int iNum;
    for (iNum = 0; iNum < iIp4Len; iNum ++) {
        stPkt.pPacket[iPktLen + iAddLen - 1 - iNum] 
            = stPkt.pPacket[iPktLen - 1 - iNum]; 
    }

    // Modify packet length
    stPkt.pPktHdr->caplen += (iAddLen - iPaddingLen);
    stPkt.pPktHdr->len += (iAddLen - iPaddingLen);

    // IPv6 initialize and build header information
    int iCursor = MAC_HDR_LEN + iVlanNum * VLAN_TAG_LEN;
    stPkt.pIp6Hdr = (_ip6hdr *) (stPkt.pPacket + iCursor);
    stPkt.pIp6Hdr->version = htons(24576);
    stPkt.pIp6Hdr->payload = htons(iIp4Len - iIp4HdrLen - iPaddingLen);
    stPkt.pIp6Hdr->pro = iL4Pro;
    stPkt.pIp6Hdr->nextHop = 0xff;

    // Switch IPv4 address to IPv6 address
    char cIp6SipBuf[SIZE_1K];
    char cIp6DipBuf[SIZE_1K];
    sprintf(cIp6SipBuf, "::%u.%u.%u.%u", 
            ((unsigned char *)&iSip)[0],
            ((unsigned char *)&iSip)[1],
            ((unsigned char *)&iSip)[2],
            ((unsigned char *)&iSip)[3]);
    sprintf(cIp6DipBuf, "::%u.%u.%u.%u", 
            ((unsigned char *)&iDip)[0],
            ((unsigned char *)&iDip)[1],
            ((unsigned char *)&iDip)[2],
            ((unsigned char *)&iDip)[3]);
    inet_pton(AF_INET6, cIp6SipBuf, stPkt.pIp6Hdr->sip);
    inet_pton(AF_INET6, cIp6DipBuf, stPkt.pIp6Hdr->dip);
}

/* Add multilayer VLAN Tags */
void InsertVlanInfo(int iHasVlanLayer)
{
    _vlanhdr* pVlanInfo[] = {
        stPkt.pVlanHdr,
        stPkt.pQinQHdr
    }; 

    int iVlanId = iHasVlanLayer ? stChg.vlan[1] : stChg.vlan[0];
    int iPktLen = stPkt.pPktHdr->len;
    int iCursor = MAC_HDR_LEN + iHasVlanLayer * VLAN_TAG_LEN;

    // Move packet
    int iNum;
    int iLength = iPktLen - iCursor;
    for (iNum = 0; iNum < iLength; iNum ++) {
        stPkt.pPacket[iPktLen + VLAN_TAG_LEN - 1 - iNum] 
            = stPkt.pPacket[iPktLen - 1 - iNum]; 
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
            stPkt.pPacket[iCursor + iNum - 1] = 
                stPkt.pPacket[iCursor+VLAN_TAG_LEN+iNum-1];
        }

        stPkt.pPktHdr->caplen = stPkt.pPktHdr->len -= VLAN_TAG_LEN;
    } // End of if
}

void ModifyVlanTag(int iVoQ)
{
    U16* pVlanPos[] = {
        (U16 *)&stPkt.pVlanHdr->id, 
        (U16 *)&stPkt.pQinQHdr->id
    }; 

    int iHasVlanNum = 0;
    if (iVoQ == M_VLAN) { // VLAN
        if (stPkt.pVlanHdr != NULL) {
            iHasVlanNum = 1;
            if (stChg.vlan[iVoQ] > 0) {
                *pVlanPos[iVoQ] = stChg.vlan[iVoQ];
            } else {
                DeleteVlanInfo(iHasVlanNum, M_HEAD);
            }
        } else {
            InsertVlanInfo(iHasVlanNum);
        }
    } else if (iVoQ == M_QinQ) { // QinQ
        if (stPkt.pQinQHdr != NULL) {
            iHasVlanNum = 2;
            if (stChg.vlan[iVoQ] > 0) {
                *pVlanPos[iVoQ] = stChg.vlan[iVoQ];
            } else {
                DeleteVlanInfo(iHasVlanNum, M_REAR);
            }
        } else if (stPkt.pVlanHdr != NULL) {
            iHasVlanNum = 1;
            InsertVlanInfo(iHasVlanNum);
        } else {
            while (iHasVlanNum < 2) {
                InsertVlanInfo(iHasVlanNum);
                iHasVlanNum ++;
            }
        } 
    }
}

void ModifyIp4Addr(int iSoD)
{
    U32* pIpPos[] = {
        (U32 *)&stPkt.pIp4Hdr->sip, 
        (U32 *)&stPkt.pIp4Hdr->dip
    }; 

    *pIpPos[JudgeSoD(iSoD)] = stChg.ip4[iSoD];
}

void ModifyPortNum(int iSoD)
{
    U16* pPortPos[] = {
        (U16 *)&stPkt.pUdpHdr->sport, 
        (U16 *)&stPkt.pUdpHdr->dport,
        (U16 *)&stPkt.pTcpHdr->sport, 
        (U16 *)&stPkt.pTcpHdr->dport
    }; 

    U8 iL4Pro = 0;
    if (stPkt.pMacHdr->pro == htons(IPv4)) {
        iL4Pro = stPkt.pIp4Hdr->pro;
    } else if (stPkt.pMacHdr->pro == htons(IPv6)) {
        iL4Pro = stPkt.pIp6Hdr->pro;
    }

    int iPos = ((iL4Pro == UDP) ? 0 : 2);
    *pPortPos[JudgeSoD(iSoD) + iPos] = stChg.port[iSoD];
}

void DetectAndProcess(int iGoM)
{
    if (!iGoM) {
        ChangeListInit();
    }
    char* pParaList[] = {
        "smac" , "dmac", 
        "sip"  , "dip", 
        "sport", "dport", 
        "vlan" , "qinq",
    };
    int iLength = sizeof(pParaList) / sizeof(char*);

    int iNum;
    for (iNum = 0; iNum < iLength; iNum ++) {
        int iSoD = iNum % 2;
        if (GetState(pParaList[iNum]) > 0) {
            if (iNum == 0 || iNum == 1) {
                if (!iGoM) GenerateMacAddr(pParaList[iNum], iSoD);
                else ModifyMacAddr(iSoD);
            } else if (iNum == 2 || iNum == 3) {
                if (!iGoM) GenerateIp4Addr(pParaList[iNum], iSoD);
                else ModifyIp4Addr(iSoD);
            } else if (iNum == 4 || iNum == 5) {
                if (!iGoM) GeneratePortNum(pParaList[iNum], iSoD);
                else ModifyPortNum(iSoD);
            } else if (iNum == 6 || iNum == 7) {
                if (!iGoM) GenerateVlanTag(pParaList[iNum], iSoD);
                else ModifyVlanTag(iSoD); 
            }
        }
    } // End of for

    // Change IPv4 to IPv6
    if (iGoM && (strcmp(GetStr("l3pro"), "IPV6") == 0)) {
        ChangeIp4ToIp6();
    }
}

U32 GetHashValue(const char* pKeyStr)  
{  
    const signed char* pKey = (const signed char*)pKeyStr;  
    unsigned int iPos = *pKey;  
    if (iPos) {  
        for (pKey += 1; *pKey != '\0';  ++pKey) { 
            iPos = (iPos << 5) - iPos + *pKey;  
        }
    }  

    return iPos;  
}  

U32 RuleInitialization()
{
    char  cExpBuf[SIZE_1K];
    memset(cExpBuf, 0, sizeof(cExpBuf));

    char* pExpStr = GetStr("express");
    if (pExpStr == NULL) {
        LOGRECORD(DEBUG, "The parameter -E is missing");
        return 0;
    } else {
        memcpy(cExpBuf, pExpStr, strlen(pExpStr));
    }

    char* pPosStr = NULL;
    char* pRepStr[2];
    if (cExpBuf != NULL) {
        pPosStr = strtok(cExpBuf, ",");
        pRepStr[0] = strtok(NULL, ",");
        pRepStr[1] = strtok(NULL, ",");
    }

    // Determine the integrity of parameter -E
    if (pPosStr == NULL || pRepStr[0] == NULL || pRepStr[1] == NULL) {
        LOGRECORD(ERROR, "The parameter -E is Incomplete");
    } else {
        stCon.ip1[0] = inet_addr(pRepStr[0]);
        stCon.ip2[0] = inet_addr(pRepStr[1]);
    }

    char cTargetRuleBuf[SIZE_1K];
    if (strcmp(pPosStr, "IP") == 0) {
        sprintf(cTargetRuleBuf, "%u", (stCon.ip1[0] + stCon.ip2[0]));
    } else {
        LOGRECORD(ERROR, "Parameter format error\nEg: -E IP,1.1.1.1,2.2.2.2");
    }

    return GetHashValue(cTargetRuleBuf);
}

int IsSameFlow(U32 iTargetValue)
{
    stPkt = GetPktStrc();
    U32 iHashValue = 0;
    char cMatchRuleBuf[SIZE_1K];
    sprintf(cMatchRuleBuf, "%u", 
            (stPkt.pIp4Hdr->sip + stPkt.pIp4Hdr->dip));
    iHashValue = GetHashValue(cMatchRuleBuf);

    int iResNum = 0;
    if (iTargetValue == 0) {
        stCon.ip1[0] = stPkt.pIp4Hdr->sip;
        stCon.ip2[0] = stPkt.pIp4Hdr->dip;
        iResNum = iHashValue;
    } else if (iHashValue == iTargetValue) {
        iResNum = iHashValue;
    }

    return iResNum;
}

/* Message modification program entry */
void ModifyProcessEntrance()
{
    int iMatchFlag = 0;
    int iGenerateFlag = 0;
    int iModifyFlag = 1;

    DetectAndProcess(iGenerateFlag);
    U32 iRuleCode = RuleInitialization();
    while (DeepPacketInspection() > 0) {
        iRuleCode = IsSameFlow(iRuleCode);
        if (iRuleCode > 0) {
            DetectAndProcess(iModifyFlag);
            PacketProcessing(stPkt);
            iMatchFlag ++;
        }
    }
}

void ModifyPacket()
{
    if (GetNum("debug")) {
        ShowParameter();
    }

    int iCount = GetNum("count");
    while (iCount --) {
        ModifyProcessEntrance();
    }
}

