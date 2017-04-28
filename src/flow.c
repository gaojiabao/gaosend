/*******************************************************
 *
 *  Author        : Mr.Gao
 *  Email         : 729272771@qq.com
 *  Filename      : flow.c
 *  Last modified : 2017-04-25 14:13
 *  Description   : Store TCP data flow information
 *
 * *****************************************************/


#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <time.h>  
#include "packet.h"


#define HASH_TABLE_MAX_SIZE 10000000  
typedef struct HashNode_Struct stHashNode;  

struct HashNode_Struct {  
    char* sKey;  
    int iSSeq;
    int iDSeq;
    int iDLen;  // The length of forward packet data part
    U8  iFFlag; // The flag of forward packet
    U8  iState; // The flag of stream.  0111 three handshake. 1111 four wave
    int iHit;  
    stHashNode* pNext;  
};  

stHashNode* pcHashTable[HASH_TABLE_MAX_SIZE]; 
int iHashTableSize;  

/* Initialize hash table */  
void StreamStorageInit()  
{  
    iHashTableSize = 0;  
    memset(pcHashTable, 0, sizeof(stHashNode*) * HASH_TABLE_MAX_SIZE);  
}  

/* Calculate the position in the hash table based on the hash value of key */
unsigned int CalcPosWithKey(const char* pKeyStr)  
{  
    const signed char* pKey = (const signed char*)pKeyStr;  
    unsigned int iPos = *pKey;  
    if (iPos) {  
        for (pKey += 1; *pKey != '\0';  ++pKey)  
            iPos = (iPos << 5) - iPos + *pKey;  
    }  

    return iPos;  
}  

/* Insert key-value into hash table */ 
void StreamStorage(const char* pKey, _tcphdr* pTcpHdr, int iDataLen)  
{  
    if (iHashTableSize >= HASH_TABLE_MAX_SIZE) {  
        printf("out of hash table memory!\n");  
        return;  
    }

    unsigned int iPos = CalcPosWithKey(pKey) % HASH_TABLE_MAX_SIZE;  

    stHashNode* pHead = pcHashTable[iPos];  
    int iAmendNum = 0;
    while (pHead) {  
        // Check ack and seq
        if (strcmp(pHead->sKey, pKey) == 0) {
            if (htonl(pTcpHdr->seq) != pHead->iSSeq 
                    && htonl(pTcpHdr->seq) != pHead->iDSeq) {
                if (iDataLen > 0 || pHead->iDLen > 0) {
                    iAmendNum = pHead->iDLen;
                } else {
                    iAmendNum = 1;
                }
                if (htonl(pTcpHdr->ack) - iAmendNum == pHead->iSSeq) {
                    pHead->iDSeq = htonl(pTcpHdr->seq);
                } else if (htonl(pTcpHdr->ack) - iAmendNum == pHead->iDSeq) {
                    pHead->iSSeq = htonl(pTcpHdr->seq);
                }
            } 

            if (pTcpHdr->flag & 0x04) { // RST
                pHead->iState |= (1 << 7);
            } else if (pTcpHdr->flag == 0x012) { // SYN + ACK
                pHead->iState |= (1 << 5);
            } else if (pHead->iFFlag == 0x012 
                    && pTcpHdr->flag == 0x010) { // ACK
                pHead->iState |= (1 << 4);
            } else if ((pTcpHdr->flag & 0x001) && (pTcpHdr->flag & 0x010)) {
                pHead->iState |= 
                    (pHead->iState & (1 << 3)) ? (1 << 1) : (1 << 3);
            } else if (((pHead->iFFlag & 0x001) && (pHead->iFFlag & 0x010))
                    && (pTcpHdr->flag == 0x010)) {
                pHead->iState |= 
                    (pHead->iState & (1 << 2)) ? (1 << 0) : (1 << 2);
            }

            pHead->iFFlag = pTcpHdr->flag;
            pHead->iDLen = iDataLen;
            pHead->iHit ++;
            return;  
        }

        pHead = pHead->pNext;  
    } // End of while  

    if (pTcpHdr->flag != 0x002) { // Flag:syn
        return;
    }
    stHashNode* pNewNode = (stHashNode*)malloc(sizeof(stHashNode));  
    memset(pNewNode, 0, sizeof(stHashNode));  
    pNewNode->sKey = (char*)malloc(sizeof(char) * (strlen(pKey) + 1));  
    strcpy(pNewNode->sKey, pKey);  
    pNewNode->iSSeq = htonl(pTcpHdr->seq);  
    pNewNode->iDSeq = 0;  
    pNewNode->iDLen = iDataLen;  
    pNewNode->iFFlag = pTcpHdr->flag;  
    pNewNode->iState = (1 << 6); // SYN
    pNewNode->iHit = 1;

    pNewNode->pNext = pcHashTable[iPos];  
    pcHashTable[iPos] = pNewNode;  

    iHashTableSize ++;  
}  

/* Delete key-value from hash table */
void DeleteStreamStorage(const char* pkey)  
{  
    unsigned int iPos = CalcPosWithKey(pkey) % HASH_TABLE_MAX_SIZE;  
    if (pcHashTable[iPos]) {  
        stHashNode* pHead = pcHashTable[iPos];  
        stHashNode* pLast = NULL;  
        stHashNode* pRemove = NULL;  
        while (pHead) {  
            if (strcmp(pkey, pHead->sKey) == 0) {  
                pRemove = pHead;  
                break;  
            }  
            pLast = pHead;  
            pHead = pHead->pNext;  
        }  
        if (pRemove) {  
            if (pLast) {
                pLast->pNext = pRemove->pNext;  
            } else {  
                pcHashTable[iPos] = NULL;  
            }

            free(pRemove->sKey);  
            free(pRemove);  
        }  
    }  
}  

/* Find hash node based on key */
stHashNode* QueryStreamStorage(const char* pkey)  
{  
    unsigned int iPos = CalcPosWithKey(pkey) % HASH_TABLE_MAX_SIZE;  
    if (pcHashTable[iPos]) {  
        stHashNode* pHead = pcHashTable[iPos];  
        while (pHead) {  
            if (strcmp(pkey, pHead->sKey) == 0) {
                return pHead;  
            }
            pHead = pHead->pNext;  
        }  
    } // End of if

    return NULL;  
}  

/* Display the contents of the hash table */
void DisplayStreamStorage()  
{  
    int iNum;  
    int iAllFlowNum = 0;
    int iPerfectNum = 0;
    printf("================The content of Hash table================\n");
    for (iNum = 0; iNum < HASH_TABLE_MAX_SIZE;  ++iNum) {
        if (pcHashTable[iNum]) {  
            iAllFlowNum ++;
            stHashNode* pHead = pcHashTable[iNum];  
            if (pHead->iState < 0x7e) { // At least one ACK
                continue;
            }
            while (pHead) {  
                printf("Node[%7d] => %s:0x%x,0x%x,0x%x,%d  ", 
                        iNum, pHead->sKey, pHead->iState, 
                        pHead->iSSeq, pHead->iDSeq, pHead->iHit);  
                iPerfectNum ++;
                pHead = pHead->pNext;  
            }  
            printf("\n");  
        }  
    }
    printf("Total flow num:%d\n", iAllFlowNum);
    printf("Perfect flow num:%d\n", iPerfectNum);
    printf("===========================END===========================\n");
}  

/* Free the memory of the hash table */ 
void ReleaseStreamStorage()  
{  
    int iNum;  
    for (iNum = 0; iNum < HASH_TABLE_MAX_SIZE;  ++iNum) {  
        if (pcHashTable[iNum]) {  
            stHashNode* pHead = pcHashTable[iNum];  
            while (pHead) {  
                stHashNode* pTemp = pHead;  
                pHead = pHead->pNext;  
                if (pTemp) {  
                    free(pTemp->sKey);  
                    free(pTemp);  
                }  
            } // End of while  
        }  
    } // End of for  
}  

