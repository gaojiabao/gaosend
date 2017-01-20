#include "storage.h"
#include "common.h"
#include <stdio.h>
#include "default.h"
#include "runlog.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>

static pNode pHead;

/* create storage to store input parameters */
void CreateStorage(void)
{
    pHead = calloc(1, sizeof(st_node));
    assert(pHead != NULL);
    pHead->title = NULL;
    pHead->cValue = NULL;
    pHead->iValue = -1;
    pHead->flag = 0;
    pHead->next = NULL;
}

/* remove node from storage */
pNode RemoveNode(char* title)
{
    assert(pHead != NULL);
    pNode pPre = pHead;
    pNode pCur = pHead->next;
    pNode pNext;

    while (pCur != NULL) {
        if (strcmp(pCur->title, title) == 0) {
            break;
        } else {
            pPre = pCur;
            pCur = pCur->next;
        }
    }

    assert(pCur != NULL);
    pNext = pPre->next->next;
    if (pNext != NULL) {
        pPre->next = pNext;
        free(pCur);
    } else {
        pPre->next = NULL;
        free(pCur);
    }

    return pCur;
}

/* add input parameter to storage */
pNode InsertNode(char* title, char* cValue, int iValue, int flag)
{
    assert(pHead != NULL);
    pNode pCur = pHead;
    pNode pPre = NULL;
    pNode pNew = (pNode)malloc(sizeof(st_node));
    pNew->title = title;
    pNew->cValue = cValue;
    pNew->iValue = iValue;
    pNew->flag = flag;
    pNew->next = NULL;

    assert(pNew != NULL);
    while (pCur != NULL) {
        pPre = pCur;
        pCur = pCur->next;
    }
    pPre->next = pNew;

    return pNew;
}

/* search element position */
static pNode FindNode(char* title)
{
    pNode pRes = NULL;
    pNode pCur = pHead->next;

    while (pCur != NULL) {
        if (strcmp(pCur->title, title) == 0) {
            pRes = pCur;
            break;
        } else {
            pCur = pCur->next;
        }
    }

    return pRes;
}

/* UpdateNode element value */
static void UpdateNode(char* title, char* cValue, int iValue, int flag)
{
    pNode pCur = FindNode(title);

    if (pCur == NULL) {
        pCur = InsertNode(title, cValue, iValue, flag);
    }

    pCur->cValue = cValue;
    pCur->iValue = iValue;
    pCur->flag = flag;
}

/* update charactor value */
static void UpdatecValue(char* title, char* cValue)
{
    pNode pCur = FindNode(title);

    if (NULL != pCur) {
        UpdateNode(title, cValue, pCur->iValue, pCur->flag);
    } else {
        printf("UpdateNodecValue error[%s:%s]\n", title, cValue);
        exit(0);
    }
}

/* update digital value */
static void UpdateiValue(char* title, int iValue)
{
    pNode pCur = FindNode(title);

    if (pCur != NULL) {
        UpdateNode(title, pCur->cValue, iValue, pCur->flag);
    } else {
        printf("UpdateNodeiValue error\n");
        exit(0);
    }
}

/* get charactor value */
char* GetcValue(char* title)
{
    pNode pCur = FindNode(title);

    if (pCur == NULL) 
        return NULL;
    else 
        return pCur->cValue;
}

/* get digital value */
int GetiValue(char* title)
{
    pNode pCur = FindNode(title);

    return pCur->iValue;
}

int GetFlag(char* title)
{
    pNode pCur = FindNode(title);

    if (!pCur) return -1;
    return pCur->flag;
}

/* calculate storage size */ 
static int CalcStorageSize()
{
    int iCounter = 0;
    pNode pCur = pHead->next;

    while (pCur != NULL) {
        iCounter++;
        pCur = pCur->next;
    }
    return iCounter;
}

/* delete every node and destory storage*/
void DestoryStorage()
{
    pNode pCur = pHead;
    pNode pNext = pHead->next;

    while (pNext != NULL) {
        pCur = pNext;
        pNext = pNext->next;
        free(pCur);
    }

    free(pHead);
}

/* show input parameters*/
void ShowParameter()
{
    int iCounter = 0;
    int iLength = 0;

    iLength = CalcStorageSize();
    pNode pCur =  pHead->next;

    for (iCounter=0; iCounter<iLength; iCounter++) {
        printf("%s:%s,%d[%d]\n", pCur->title, pCur->cValue, pCur->iValue, pCur->flag);    
        pCur = pCur->next;
    }
}

/* update some parameter */
void RefreshParameter()
{
    char* pParaName = NULL;
    int iParaMode;
    int iCounter = 0;
    int iLength = 0;

    iLength = CalcStorageSize();
    pNode pCur =  pHead->next;

    for (; iCounter<iLength; iCounter++) {
        pParaName = pCur->title;
        iParaMode = pCur->flag;
        if (iParaMode == FG_RANDOM) { // random 
            if (strcmp(pParaName, "smac") == 0) {
                UpdatecValue(pParaName, GetRandomMacAddress(0));
            } else if (strcmp(pParaName, "dmac") == 0) {
                UpdatecValue(pParaName, GetRandomMacAddress(1));
            } else if (strcmp(pParaName, "sip") == 0) {
                UpdatecValue(pParaName, GetRandomIpAddress(0));
            } else if (strcmp(pParaName, "dip") == 0) {
                UpdatecValue(pParaName, GetRandomIpAddress(1));
            } else if (strcmp(pParaName, "sport") == 0) {
                UpdateiValue(pParaName, GetRandomPort(0));
            } else if (strcmp(pParaName, "dport") == 0) {
                UpdateiValue(pParaName, GetRandomPort(1));
            } else if (strcmp(pParaName, "vlan1") == 0) {
                UpdateiValue(pParaName, GetRandomVlan());
            } else if (strcmp(pParaName, "vlan2") == 0) {
                UpdateiValue(pParaName, GetRandomVlan());
            } else if (strcmp(pParaName, "pktlen") == 0) {
                UpdateiValue(pParaName, GetRandomPacketLength());
            }
        } else if (iParaMode == FG_INCR) { // increase
            if (strcmp(pParaName, "smac") == 0) {
                UpdatecValue(pParaName, GetIncreaseMacAddress(0));
            } else if (strcmp(pParaName, "dmac") == 0) {
                UpdatecValue(pParaName, GetIncreaseMacAddress(1));
            } else if (strcmp(pParaName, "sip") == 0) {
                UpdatecValue(pParaName, GetIncreaseIpAddress(0));
            } else if (strcmp(pParaName, "dip") == 0) {
                UpdatecValue(pParaName, GetIncreaseIpAddress(1));
            } else if (strcmp(pParaName, "sport") == 0) {
                UpdateiValue(pParaName, GetIncreasePort(0));
            } else if (strcmp(pParaName, "dport") == 0) {
                UpdateiValue(pParaName, GetIncreasePort(1));
            } else if (strcmp(pParaName, "vlan1") == 0) {
                UpdateiValue(pParaName, GetIncreaseVlan(0));
            } else if (strcmp(pParaName, "vlan2") == 0) {
                UpdateiValue(pParaName, GetIncreaseVlan(1));
            } else if (strcmp(pParaName, "pktlen") == 0) {
                UpdateiValue(pParaName, GetIncreasePacketLength());
            }
        } else if (iParaMode == FG_DECR) { // decrease
            LOGRECORD(INFO, "This function isn't develop");
        }

        pCur = pCur->next;
    }
}

/* entrance for input parameters */
void StorageInput(char* title, char* value, char mode)
{
    // deal with all layer protocol
    if (strcmp(title, "protocol") == 0) {
        unsigned int iCounter = 0;
        char cProtocal[8];
        memset(cProtocal, 0, sizeof(cProtocal));

        // switch charactor parameter to upper
        int iStrLength = strlen(value);
        for (; iCounter<iStrLength; iCounter++) {
            cProtocal[iCounter] = toupper(value[iCounter]);
        }

        // deal with association protocol
        if (strcmp(cProtocal, "ARP") == 0) {
            UpdateNode("l3pro", "ARP", -1, 0);
            UpdateNode("l4pro", NULL, -1, 0);
        } else if (strcmp(cProtocal, "ICMP") == 0) {
            UpdateNode("l3pro", "IPv4", -1, 0);
            UpdateNode("l4pro", "ICMPv4", -1, 0);
        } else if (strcmp(cProtocal, "UDP") == 0) {
            UpdateNode("l3pro", "IPv4", -1, 0);
            UpdateNode("l4pro", "UDP", -1, 0);
        } else if (strcmp(cProtocal, "TCP") == 0) {
            UpdateNode("l3pro", "IPv4", -1, 0);
            UpdateNode("l4pro", "TCP", -1, 0);
        } else if (strcmp(cProtocal, "HTTP-GET") == 0) {
            if (GetiValue("pktlen") < 360) {
                UpdateNode("pktlen", NULL, 360, 0);
            }
            UpdateNode("dport", NULL, 80, 0);
            UpdateNode("l3pro", "IPv4", -1, 0);
            UpdateNode("l4pro", "TCP", -1, 0);
            UpdateNode("l7pro", "HTTP-GET", -1, 0);
        } else if (strcmp(cProtocal, "HTTP-POST") == 0) {
            if (GetiValue("pktlen") < 360) {
                UpdateNode("pktlen", NULL, 360, 0);
            }
            UpdateNode("dport", NULL, 80, 0);
            UpdateNode("l3pro", "IPv4", -1, 0);
            UpdateNode("l4pro", "TCP", -1, 0);
            UpdateNode("l7pro", "HTTP-POST", -1, 0);
        } else if (strcmp(cProtocal, "DNS") == 0) {
            if (GetcValue("url") == NULL) {
                int pktlen = MACHDRLEN+IP4HDRLEN+UDPHDRLEN+DNSHDRLEN+13+6;
                UpdateNode("pktlen", NULL, pktlen, 0);
            } else {
                char* url = GetcValue("url");
                char* host = strtok(url, "/");
                UpdateNode("host", host, -1, 0);
                int pktlen = MACHDRLEN+IP4HDRLEN+UDPHDRLEN \
                    +DNSHDRLEN+strlen(url)+6;
                UpdateNode("pktlen", NULL, pktlen, 0);
            }
            UpdateNode("dport", NULL, 53, 0);
            UpdateNode("l3pro", "IPv4", -1, 0);
            UpdateNode("l4pro", "UDP", -1, 0);
            UpdateNode("l7pro", "DNS", -1, 0);
        }
    }

    // deal with variable parameter
    int iParaMode;
    if (strcmp(value, "random") == 0) {
        iParaMode = FG_RANDOM;
    } else if (strcmp(value, "increase") == 0) {
        iParaMode = FG_INCR;
    } else if (strcmp(value, "decrease") == 0) {
        iParaMode = FG_DECR;
    } else if (value != NULL) {
        iParaMode = FG_FIXDATA;
    } else {
        iParaMode = FG_NOINPUT;
    }

    // deal with charactor or number parameter
    if (mode == 'c') {
        UpdateNode(title, value, -1, iParaMode);
    } else if (mode == 'i') {
        UpdateNode(title, NULL, atoi(value), iParaMode);
    }
}

static pStreamInfo pStreamHead;

void CreateStreamStorage(void)
{
    pStreamHead = calloc(1, sizeof(stream_info));
    assert(pStreamHead != NULL);
    int iCounter;
    for (iCounter=0; iCounter<MD5LEN; iCounter++) {
        pStreamHead->value[iCounter] = 0;
    }
    pStreamHead->next = NULL;
}

pStreamInfo InsertStreamInfo(unsigned char* pMD5)
{
    assert(pStreamHead != NULL);
    pStreamInfo pCur = pStreamHead;
    pStreamInfo pPre = NULL;
    pStreamInfo pNew = (pStreamInfo)malloc(sizeof(stream_info));

    int iCounter;
    for (iCounter=0; iCounter<MD5LEN; iCounter++) {
        pNew->value[iCounter] = pMD5[iCounter];
    }
    pNew->next = NULL;

    assert(pNew != NULL);
    while (pCur != NULL) {
        pPre = pCur;
        pCur = pCur->next;
    }
    pPre->next = pNew;

    return pNew;
}

static int JudgeEqual(unsigned char* pOriginMD5, unsigned char* pNewMD5)
{
    int iCounter;
    for (iCounter=0; iCounter<MD5LEN; iCounter++) {
        if (pOriginMD5[iCounter] != pNewMD5[iCounter]) {
            return FALSE;
        }
    }
    return SUCCESS;
}

void StoreStreamInfo(unsigned char* pMD5)
{
    pStreamInfo pCur = pStreamHead->next;

    int iIsFindMD5 = FALSE;

    while (pCur != NULL) {
        if(JudgeEqual(pCur->value, pMD5) == 1) {
            iIsFindMD5 = SUCCESS;
            break;
        } else {
            pCur = pCur->next;
        }
    }

    if (iIsFindMD5 == FALSE) {
        InsertStreamInfo(pMD5);
    }
}

void DisplayAllStreamMD5()
{
    pStreamInfo pCur = pStreamHead->next;
    int iCounter;
    while (pCur != NULL) {
        for (iCounter=0; iCounter<MD5LEN; iCounter++) {
            printf("%02X", pCur->value[iCounter]);
        }
        printf("\n");
        pCur = pCur->next;
    }
}

