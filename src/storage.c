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
    pHead->title = NULL;
    pHead->cValue = NULL;
    pHead->iValue = -1;
    pHead->flag = 0;
    pHead->next = NULL;
}

/* Add storage node and store data */
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

/* Query parameter storage node */
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

/* Update storage node data */
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

/* Updating the data content of a string type */
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

/* Updating the data content of an integral type */
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

/* Gets the data content of the string type */
char* GetcValue(char* title)
{
    pNode pCur = FindNode(title);

    if (pCur == NULL) 
        return NULL;
    else 
        return pCur->cValue;
}

/* Gets the data content of an integral type */
int GetiValue(char* title)
{
    pNode pCur = FindNode(title);

    if (pCur == NULL) {
        return 0;
    }

    return pCur->iValue;
}

/* Gets the contents of the storage flag bit data */
int GetFlag(char* title)
{
    pNode pCur = FindNode(title);

    if (!pCur) return -1;
    return pCur->flag;
}

/* Calculate storage container size */ 
static int CalcStorageSize()
{
    int iCounter = 0;
    pNode pCur = pHead->next;

    while (pCur != NULL) {
        iCounter ++;
        pCur = pCur->next;
    }
    return iCounter;
}

/* Destroy storage container */
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

/* Display input parameters */
void ShowParameter()
{
    int iCounter = 0;
    int iLength = 0;

    iLength = CalcStorageSize();
    pNode pCur =  pHead->next;

    for (iCounter = 0; iCounter < iLength; iCounter ++) {
        printf("%s:%s,%d[%d]\n", pCur->title, pCur->cValue, pCur->iValue, pCur->flag);    
        pCur = pCur->next;
    }
}

/* Refresh the value of the parameter based on the input parameters */
void RefreshParameter()
{
    int iParaMode;
    int iCounter;
    int iLength = 0;
    char* pParaName = NULL;

    iLength = CalcStorageSize();
    pNode pCur =  pHead->next;

    for (iCounter = 0; iCounter < iLength; iCounter ++) {
        pParaName = pCur->title;
        iParaMode = pCur->flag;
        if (iParaMode == FG_RAND) { // random 
            if (strcmp(pParaName, "smac") == 0) {
                UpdatecValue(pParaName, GetRandMacAddr(0));
            } else if (strcmp(pParaName, "dmac") == 0) {
                UpdatecValue(pParaName, GetRandMacAddr(1));
            } else if (strcmp(pParaName, "sip") == 0) {
                UpdatecValue(pParaName, GetRandIp4Addr());
            } else if (strcmp(pParaName, "dip") == 0) {
                UpdatecValue(pParaName, GetRandIp4Addr());
            } else if (strcmp(pParaName, "sport") == 0) {
                UpdateiValue(pParaName, GetRandPort(0));
            } else if (strcmp(pParaName, "dport") == 0) {
                UpdateiValue(pParaName, GetRandPort(1));
            } else if (strcmp(pParaName, "vlan") == 0) {
                UpdateiValue(pParaName, GetRandVlan());
            } else if (strcmp(pParaName, "qinq") == 0) {
                UpdateiValue(pParaName, GetRandVlan());
            } else if (strcmp(pParaName, "pktlen") == 0) {
                UpdateiValue(pParaName, GetRandPktLen());
            }
        } else if (iParaMode == FG_INCR) { // increase
            if (strcmp(pParaName, "smac") == 0) {
                UpdatecValue(pParaName, GetIncrMacAddr(0));
            } else if (strcmp(pParaName, "dmac") == 0) {
                UpdatecValue(pParaName, GetIncrMacAddr(1));
            } else if (strcmp(pParaName, "sip") == 0) {
                UpdatecValue(pParaName, GetIncrIp4Addr(0));
            } else if (strcmp(pParaName, "dip") == 0) {
                UpdatecValue(pParaName, GetIncrIp4Addr(1));
            } else if (strcmp(pParaName, "sport") == 0) {
                UpdateiValue(pParaName, GetIncrPort(0));
            } else if (strcmp(pParaName, "dport") == 0) {
                UpdateiValue(pParaName, GetIncrPort(1));
            } else if (strcmp(pParaName, "vlan") == 0) {
                UpdateiValue(pParaName, GetIncrVlan(0));
            } else if (strcmp(pParaName, "qinq") == 0) {
                UpdateiValue(pParaName, GetIncrVlan(1));
            } else if (strcmp(pParaName, "pktlen") == 0) {
                UpdateiValue(pParaName, GetIncrPktLen());
            }
        } else if (iParaMode == FG_DECR) { // decrease
            LOGRECORD(INFO, "This function isn't develop");
        }

        pCur = pCur->next;
    }
}

/* Parameter storage processor */
void StorageInput(char* title, char* value, char mode)
{
    // Protocol analysis in parameters
    if (strcmp(title, "protocol") == 0) {
        unsigned int iCounter;
        static char cProtocal[16];
        memset(cProtocal, 0, sizeof(cProtocal));

        // Converting arguments to uppercase characters
        int iStrLength = strlen(value);
        for (iCounter = 0; iCounter < iStrLength; iCounter ++) {
            cProtocal[iCounter] = toupper(value[iCounter]);
        }

        char* pL3Pro = NULL;
        char* pL4Pro = NULL;
        char* pL7Pro = NULL;
        if (strcmp(cProtocal, "ARP") == 0) {
            pL3Pro = cProtocal;
        } else if ((strcmp(cProtocal, "ICMP") == 0) 
            || (strcmp(cProtocal, "UDP") == 0) 
            || (strcmp(cProtocal, "TCP") == 0)) {
            pL3Pro = "IPv4";
            pL4Pro = cProtocal;
        } else if ((strcmp(cProtocal, "HTTP-GET") == 0)
            || (strcmp(cProtocal, "HTTP-POST") == 0)) {
            pL3Pro = "IPv4";
            pL4Pro = "TCP";
            pL7Pro = cProtocal;
        } else if (strcmp(cProtocal, "DNS") == 0) {
            pL3Pro = "IPv4";
            pL4Pro = "UDP";
            pL7Pro = cProtocal;
        } else if ((strcmp(cProtocal, "ICMP6") == 0) 
            || (strcmp(cProtocal, "UDP6") == 0) 
            || (strcmp(cProtocal, "TCP6") == 0)) {
            pL3Pro = "IPv6";
            pL4Pro = cProtocal;
        } else if ((strcmp(cProtocal, "HTTP-GET6") == 0)
            || (strcmp(cProtocal, "HTTP-POST6") == 0)) {
            pL3Pro = "IPv6";
            pL4Pro = "TCP";
            pL7Pro = cProtocal;
        } else if (strcmp(cProtocal, "DNS6") == 0) {
            pL3Pro = "IPv6";
            pL4Pro = "UDP";
            pL7Pro = cProtocal;
        }

        UpdateNode("l3pro", pL3Pro, -1, 0);
        UpdateNode("l4pro", pL4Pro, -1, 0);
        UpdateNode("l7pro", pL7Pro, -1, 0);
    }

    // Test IPv6
    //UpdateNode("l3pro", "IPv6", -1, 0);

    // Marking parameters are variable 
    int iParaMode;
    if (strcmp(value, "random") == 0) {
        iParaMode = FG_RAND;
    } else if (strcmp(value, "increase") == 0) {
        iParaMode = FG_INCR;
    } else if (strcmp(value, "decrease") == 0) {
        iParaMode = FG_DECR;
    } else if (value != NULL) {
        iParaMode = FG_FIXD;
    } else {
        iParaMode = FG_NOINPUT;
    }

    // Data stored according to identification 
    if (mode == 'c') {
        UpdateNode(title, value, -1, iParaMode);
    } else if (mode == 'i') {
        UpdateNode(title, NULL, atoi(value), iParaMode);
    }
}

