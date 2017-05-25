#ifndef __STORAGE_H__
#define __STORAGE_H__

#include    "default.h"

/* Parameter storage structure */
typedef struct Node{
    char* pTitle;
    char* pStr;
    int   iNum;
    int   iState; //0:init,1:fixed,2:random,3:increase,4:decrease
    struct Node* pNext;
}st_node, *pNode;

enum Node_flag{
    FG_INIT,
    FG_FIXD,
    FG_RAND,
    FG_INCR,
    FG_DECR,
};

void  CreateStorage(void);
void  InsertNode(char* , char*, int, int);
char* GetStr(char* );
int   GetNum(char* );
int   GetState(char* );
void  DestoryStorage();
void  ShowParameter();
void  RefreshParameter();
void  StorageInput(char* , char* ,char );

#endif

