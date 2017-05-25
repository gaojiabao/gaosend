/*******************************************************
 *
 *  Author        : Mr.Gao
 *  Email         : 729272771@qq.com
 *  Filename      : storage.c
 *  Last modified : 2017-04-27 16:16
 *  Description   : Used to parameter storage
 *
 * *****************************************************/


#include <ctype.h>
#include <assert.h>
#include <string.h>
#include "common.h"
#include "runlog.h"
#include "storage.h"


static pNode pHead;

/* Create parameter storage container */
void CreateStorage(void)
{
    pHead = calloc(1, sizeof(st_node));
    assert(pHead != NULL);
    pHead->pTitle = NULL;
    pHead->pStr = NULL;
    pHead->iNum = -1;
    pHead->iState = 0;
    pHead->pNext = NULL;
}

/* Add storage node and store data */
void InsertNode(char* pTitle, char* pStr, int iNum, int iState)
{
    assert(pHead != NULL);
    pNode pCur = pHead;
    pNode pPre = NULL;
    pNode pNew = (pNode)malloc(sizeof(st_node));
    pNew->pTitle = pTitle;
    pNew->pStr = pStr;
    pNew->iNum = iNum;
    pNew->iState = iState;
    pNew->pNext = NULL;

    assert(pNew != NULL);
    while (pCur != NULL) {
        pPre = pCur;
        pCur = pCur->pNext;
    }

    pPre->pNext = pNew;
}

/* Query parameter storage node */
static pNode FindNode(char* pTitle)
{
    pNode pRes = NULL;
    pNode pCur = pHead->pNext;

    while (pCur != NULL) {
        if (strcmp(pCur->pTitle, pTitle) == 0) {
            pRes = pCur;
            break;
        } else {
            pCur = pCur->pNext;
        }
    }

    return pRes;
}

/* Update storage node data */
static void UpdateNode(char* pTitle, char* pStr, int iNum, int iState)
{
    pNode pCur = FindNode(pTitle);

    if (pCur == NULL) {
        InsertNode(pTitle, pStr, iNum, iState);
    } else {
        pCur->pStr = pStr;
        pCur->iNum = iNum;
        pCur->iState = iState;
    }
}

/* Updating the data content of a string type */
static void UpdateStr(char* pTitle, char* pStr)
{
    pNode pCur = FindNode(pTitle);

    if (NULL != pCur) {
        UpdateNode(pTitle, pStr, pCur->iNum, pCur->iState);
    } else {
        LOGRECORD(ERROR, "Update string error\n");
    }
}

/* Updating the data content of an integral type */
static void UpdateNum(char* pTitle, int iNum)
{
    pNode pCur = FindNode(pTitle);

    if (pCur != NULL) {
        UpdateNode(pTitle, pCur->pStr, iNum, pCur->iState);
    } else {
        LOGRECORD(ERROR, "Update number error");
    }
}

/* Gets the data content of the string type */
char* GetStr(char* pTitle)
{
    pNode pCur = FindNode(pTitle);

    if (pCur == NULL) {
        return NULL;
    }

    return pCur->pStr;
}

/* Gets the data content of an integral type */
int GetNum(char* pTitle)
{
    pNode pCur = FindNode(pTitle);

    if (pCur == NULL) {
        return 0;
    }

    return pCur->iNum;
}

/* Gets the contents of the storage state bit data */
int GetState(char* pTitle)
{
    pNode pCur = FindNode(pTitle);

    if (!pCur) {
        return -1;
    }

    return pCur->iState;
}

/* Calculate storage container size */ 
static int CalcStorageSize()
{
    int iCounter = 0;
    pNode pCur = pHead->pNext;

    while (pCur != NULL) {
        iCounter ++;
        pCur = pCur->pNext;
    }

    return iCounter;
}

/* Destroy storage container */
void DestoryStorage()
{
    pNode pCur = pHead;
    pNode pNext = pHead->pNext;

    while (pNext != NULL) {
        pCur = pNext;
        pNext = pNext->pNext;
        free(pCur);
    }

    free(pHead);
}

/* Display input parameters */
void ShowParameter()
{
    int iCounter = 0;
    int iLength = 0;

    iLength = CalcStorageSize();
    pNode pCur =  pHead->pNext;

    for (iCounter = 0; iCounter < iLength; iCounter ++) {
        printf("%-15s:%32s,%10d[%d]\n", 
                pCur->pTitle, pCur->pStr, pCur->iNum, pCur->iState);    
        pCur = pCur->pNext;
    }
    printf("\n");
}

/* Refresh the value of the parameter based on the input parameters */
void RefreshParameter()
{
    int iParaMode;
    int iCounter;
    int iLength = 0;
    char* pParaName = NULL;

    iLength = CalcStorageSize();
    pNode pCur =  pHead->pNext;

    for (iCounter = 0; iCounter < iLength; iCounter ++) {
        pParaName = pCur->pTitle;
        iParaMode = pCur->iState;
        if (iParaMode == FG_RAND) { // random 
            if (strcmp(pParaName, "smac") == 0) {
                UpdateStr(pParaName, GetRandMacAddr(0));
            } else if (strcmp(pParaName, "dmac") == 0) {
                UpdateStr(pParaName, GetRandMacAddr(1));
            } else if (strcmp(pParaName, "sip") == 0) {
                UpdateStr(pParaName, GetRandIp4Addr(0));
            } else if (strcmp(pParaName, "dip") == 0) {
                UpdateStr(pParaName, GetRandIp4Addr(1));
            } else if (strcmp(pParaName, "sport") == 0) {
                UpdateNum(pParaName, GetRandPort(0));
            } else if (strcmp(pParaName, "dport") == 0) {
                UpdateNum(pParaName, GetRandPort(1));
            } else if (strcmp(pParaName, "vlan") == 0) {
                UpdateNum(pParaName, GetRandVlan(0));
            } else if (strcmp(pParaName, "qinq") == 0) {
                UpdateNum(pParaName, GetRandVlan(1));
            } else if (strcmp(pParaName, "pktlen") == 0) {
                UpdateNum(pParaName, GetRandPktLen());
            }
        } else if (iParaMode == FG_INCR) { // increase
            if (strcmp(pParaName, "smac") == 0) {
                UpdateStr(pParaName, GetIncrMacAddr(0));
            } else if (strcmp(pParaName, "dmac") == 0) {
                UpdateStr(pParaName, GetIncrMacAddr(1));
            } else if (strcmp(pParaName, "sip") == 0) {
                UpdateStr(pParaName, GetIncrIp4Addr(0));
            } else if (strcmp(pParaName, "dip") == 0) {
                UpdateStr(pParaName, GetIncrIp4Addr(1));
            } else if (strcmp(pParaName, "sport") == 0) {
                UpdateNum(pParaName, GetIncrPort(0));
            } else if (strcmp(pParaName, "dport") == 0) {
                UpdateNum(pParaName, GetIncrPort(1));
            } else if (strcmp(pParaName, "pktlen") == 0) {
                UpdateNum(pParaName, GetIncrPktLen());
            }
        } else if (iParaMode == FG_DECR) { // decrease
            LOGRECORD(INFO, "This function isn't develop");
        }

        pCur = pCur->pNext;
    }
}

/* Analysis of layer two, three, seven protocol */
char** ProtocolAnalyse(char* pProStr)
{
    static char* pProArray[3];

    if (strcmp(pProStr, "ARP") == 0) {
        pProArray[0] = pProStr;
    } else if ((strcmp(pProStr, "ICMP") == 0) 
            || (strcmp(pProStr, "UDP") == 0) 
            || (strcmp(pProStr, "TCP") == 0)) {
        pProArray[0] = "IPv4";
        pProArray[1] = pProStr;
    } else if ((strcmp(pProStr, "HTTP-GET") == 0)
            || (strcmp(pProStr, "HTTP-POST") == 0)
            || (strcmp(pProStr, "HTTP") == 0)) {
        pProArray[0] = "IPv4";
        pProArray[1] = "TCP";
        pProArray[2] = pProStr;
    } else if (strcmp(pProStr, "DNS") == 0) {
        pProArray[0] = "IPv4";
        pProArray[1] = "UDP";
        pProArray[2] = pProStr;
    } else if ((strcmp(pProStr, "ICMP6") == 0) 
            || (strcmp(pProStr, "UDP6") == 0) 
            || (strcmp(pProStr, "TCP6") == 0)) {
        pProArray[0] = "IPv6";
        pProArray[1] = pProStr;
    } else if ((strcmp(pProStr, "HTTP-GET6") == 0)
            || (strcmp(pProStr, "HTTP-POST6") == 0)
            || (strcmp(pProStr, "HTTP6") == 0)) {
        pProArray[0] = "IPv6";
        pProArray[1] = "TCP";
        pProArray[2] = pProStr;
    } else if (strcmp(pProStr, "DNS6") == 0) {
        pProArray[0] = "IPv6";
        pProArray[1] = "UDP";
        pProArray[2] = pProStr;
    } else if ((strcmp(pProStr, "IPV4") == 0)
            || (strcmp(pProStr, "IPV6") == 0)) {
        pProArray[0] = pProStr;
        pProArray[1] = NULL;
        pProArray[2] = NULL;
    } else {
        LOGRECORD(ERROR, "Unrecognized protocol");
    }

    return pProArray;
}

/* Parameter storage processor */
void StorageInput(char* pTitle, char* pValue, char cType)
{
    // Protocol analysis in parameters
    if (strcmp(pTitle, "protocol") == 0) {
        unsigned int iCounter;
        static char cProtocal[16];
        memset(cProtocal, 0, sizeof(cProtocal));

        // Converting arguments to uppercase characters
        int iStrLength = strlen(pValue);
        for (iCounter = 0; iCounter < iStrLength; iCounter ++) {
            cProtocal[iCounter] = toupper(pValue[iCounter]);
        }

        char** pProArray = ProtocolAnalyse(cProtocal);
        UpdateNode("l3pro", pProArray[0], -1, 0);
        UpdateNode("l4pro", pProArray[1], -1, 0);
        UpdateNode("l7pro", pProArray[2], -1, 0);
    } else {
        // Marking parameters are variable 
        int iParaMode;
        if (strcmp(pValue, "rand") == 0) {
            iParaMode = FG_RAND;
        } else if (strcmp(pValue, "incr") == 0) {
            iParaMode = FG_INCR;
        } else if (strcmp(pValue, "decr") == 0) {
            iParaMode = FG_DECR;
        } else if (pValue != NULL) {
            iParaMode = FG_FIXD;
        }

        // Data stored according to identification 
        if (cType == 'c') {
            UpdateNode(pTitle, pValue, -1, iParaMode);
        } else if (cType == 'i') {
            UpdateNode(pTitle, NULL, atoi(pValue), iParaMode);
        }
    }
}

