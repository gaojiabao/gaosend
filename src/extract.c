/*******************************************************
 *
 *  Author        : Mr.Gao
 *  Email         : 729272771@qq.com
 *  Filename      : extract.c
 *  Last modified : 2018-01-26 10:29
 *  Description   : 
 *
 * *****************************************************/

 
#include    <string.h>
#include    "func.h"
#include    "flow.h"
#include    "common.h"
#include    "runlog.h"
#include    "storage.h"
#include    "statistic.h"


void ExtractPrefectStream(stPktStrc stPkt)
{
    if (stPkt.pIp4Hdr && stPkt.pIp4Hdr->pro == TCP) {
        // TCP flow check
        char iFiveTupleSum[32];
        sprintf(iFiveTupleSum, "%d", stPkt.pIp4Hdr->sip 
                + stPkt.pIp4Hdr->dip + stPkt.pTcpHdr->sport 
                + stPkt.pTcpHdr->dport + stPkt.pIp4Hdr->pro);
        if (JudgePerfectStream(iFiveTupleSum) > 0) {
            PacketProcessing(stPkt);
        }
    }
}

char** AnalyseExpress()
{
    char  cExpBuf[SIZE_1K];
    memset(cExpBuf, 0, sizeof(cExpBuf));

    char* pExpStr = GetStr("express");
    if (pExpStr == NULL) {
        LOGRECORD(DEBUG, "The parameter -e is missing");
        return 0;
    } else {
        memcpy(cExpBuf, pExpStr, strlen(pExpStr));
    }

    char* pPosStr = NULL;
    static char* pRepStr[2];
    if (cExpBuf != NULL) {
        pPosStr = strtok(cExpBuf, ",");
        if (strcmp(pPosStr, "RANGE") == 0) {
            pRepStr[0] = strtok(NULL, ",");
            pRepStr[1] = strtok(NULL, ",");
        } 
        // Check Legality
        if (pRepStr[0] == NULL) {
            return NULL;
        } else if (pRepStr[1] == NULL) {
            pRepStr[1] = pRepStr[0];
        }
    }

    return pRepStr;
}

void ExtractPacket()
{
    int iFlowSwitch = GetNum("flow");
    int iRangeLow = 0;
    int iRangeHigh = 0;
    if (GetStr("express")) {
        char** pRes = AnalyseExpress();
        if (pRes == NULL) {
            LOGRECORD(ERROR, "Parameter format error\neg: -E RANGE,1,100");
        }
        iRangeLow = atoi(pRes[0]);
        iRangeHigh = atoi(pRes[1]);
    }

    int iCounter = 1;
    while (DeepPacketInspection() > 0) {
        if (iFlowSwitch) {
            BuildFMT(GetPktStrc());
        } else {
            if (iCounter > iRangeHigh) {
                break;
            } else {
                if (iCounter >= iRangeLow) {
                    PacketProcessing(GetPktStrc());
                }
            }
            iCounter ++;
        }
    }

    DisplayStreamStorage();
    if (iFlowSwitch && GetNum("exec") == 1) {
        LOGRECORD(INFO, "Extract perfect stream start...");
        while (DeepPacketInspection() > 0) {
            ExtractPrefectStream(GetPktStrc());
        }
    }
}

