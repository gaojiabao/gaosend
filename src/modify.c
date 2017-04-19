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
    switch(GetFlag(pTitle)) {
        case FG_FIXD : stChg.mac[iSoD] = GetcValue(pTitle); break;
        case FG_RAND : stChg.mac[iSoD] = GetRandMacAddr(iSoD); break;
        case FG_INCR : stChg.mac[iSoD] = GetIncrMacAddr(iSoD); break;
    }
}

void GenerateVlanTag(char* pTitle, int iVoQ)
{
    switch(GetFlag(pTitle)) {
        case FG_FIXD : stChg.vlan[iVoQ] = GetiValue(pTitle); break;
        case FG_RAND : stChg.vlan[iVoQ] = GetRandVlan(iVoQ); break;
        case FG_INCR : stChg.vlan[iVoQ] = GetIncrVlan(iVoQ); break;
    }
}

void GenerateIp4Addr(char* pTitle, int iSoD)
{
    switch(GetFlag(pTitle)) {
        case FG_FIXD : stChg.ip4[iSoD] = inet_addr(GetcValue(pTitle)); break;
        case FG_RAND : stChg.ip4[iSoD] = inet_addr(GetRandIp4Addr(iSoD)); break;
        case FG_INCR : stChg.ip4[iSoD] = inet_addr(GetIncrIp4Addr(iSoD)); break;
    }
}

void GeneratePortNum(char* pTitle, int iSoD)
{
    switch(GetFlag(pTitle)) {
        case FG_FIXD : stChg.port[iSoD] = htons(GetiValue(pTitle)); break;
        case FG_RAND : stChg.port[iSoD] = htons(GetRandPort(iSoD)); break;
        case FG_INCR : stChg.port[iSoD] = htons(GetIncrPort(iSoD)); break;
    }
}

int JudgeSoD(int iSoD)
{
    int iResNum = -1;
    if (stPkt.pIp4Hdr->sip == stCon.ip1 
            || stPkt.pIp4Hdr->dip == stCon.ip2) {
        if (iSoD == M_SRC) {
            iResNum = M_SRC;
        } else if (iSoD == M_DST) {
            iResNum = M_DST;
        }
    } else if (stPkt.pIp4Hdr->sip == stCon.ip2 
            || stPkt.pIp4Hdr->dip == stCon.ip1) {
        if (iSoD == M_SRC) {
            iResNum = M_DST;
        } else if (iSoD == M_DST) {
            iResNum = M_SRC;
        }
    } else {
        LOGRECORD(DEBUG, "Packet matching failure");
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
        iL4Pro = stPkt.pIp4Hdr->protocol;
    } else if (stPkt.pMacHdr->pro == htons(IPv6)) {
        iL4Pro = stPkt.pIp6Hdr->protocol;
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
        "vlan" , "qinq",
        "sip"  , "dip", 
        "sport", "dport" 
    };
    int iLength = sizeof(pParaList) / sizeof(char*);

    int iNum;
    for (iNum = 0; iNum < iLength; iNum ++) {
        int iSoD = iNum % 2;
        if (GetFlag(pParaList[iNum]) > 1) {
            if (iNum == 0 || iNum == 1) {
                if (!iGoM) GenerateMacAddr(pParaList[iNum], iSoD);
                else ModifyMacAddr(iSoD);
            } else if (iNum == 2 || iNum == 3) {
                if (!iGoM) GenerateVlanTag(pParaList[iNum], iSoD);
                else ModifyVlanTag(iSoD); 
            } else if (iNum == 4 || iNum == 5) {
                if (!iGoM) GenerateIp4Addr(pParaList[iNum], iSoD);
                else ModifyIp4Addr(iSoD);
            } else if (iNum == 6 || iNum == 7) {
                if (!iGoM) GeneratePortNum(pParaList[iNum], iSoD);
                else ModifyPortNum(iSoD);
            }
        }
    } // End of for
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

    char* pExpStr = GetcValue("express");
    memcpy(cExpBuf, pExpStr, strlen(pExpStr));

    char* pPosStr = NULL;
    char* pRepStr[2];
    if (cExpBuf != NULL) {
        pPosStr = strtok(cExpBuf, ",");
        pRepStr[0] = strtok(NULL, ",");
        pRepStr[1] = strtok(NULL, ",");
    }

    stCon.ip1 = inet_addr(pRepStr[0]);
    stCon.ip2 = inet_addr(pRepStr[1]);

    char cTargetRuleBuf[SIZE_1K];
    if (strcmp(pPosStr, "IP") == 0) {
        sprintf(cTargetRuleBuf, "%u", (stCon.ip1 + stCon.ip2));
    } else {
        return -1;
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
    if (iHashValue == iTargetValue) {
        iResNum = 1;
    } 

    return iResNum;
}

/* Message modification program entry */
void ModifyProcessEntrance()
{
    int iMatchFlag = 0;
    DetectAndProcess(0);
    U32 iRuleCode = RuleInitialization();
    while (DeepPacketInspection() > 0) {
        if (IsSameFlow(iRuleCode)) {
            DetectAndProcess(1);
            PacketProcessing(stPkt);
            iMatchFlag ++;
        }
    }
}

void ModifyPacket()
{
    int iCount = GetiValue("count");
    while (iCount --) {
        ModifyProcessEntrance();
    }
}

