/*
 *  Author   : Mr. Gao
 *
 *  Function : To statement functions.
 */ 

#ifndef __FUNCTION_H__
#define __FUNCTION_H__

#include    <stdio.h>
#include    "packet.h"

/* Define buffer size */
#define SIZE_16B       16
#define SIZE_128B      128
#define SIZE_1K        1024

U16         GetCheckSum(U16*, int);
char        GetHexChar(int);
char*       GetRandURL();
int         GetRandNum();
char*       GetRandStr(int);
int         FillInMacAddr(char *, char *);

char*       GetIncrMacAddr(int);
char*       GetIncrIp4Addr(int);
int         GetIncrPort(int);
int         GetIncrPktLen();
int         GetIncrVlan(int);

char*       GetRandMacAddr(int);
char*       GetRandIp4Addr();
int         GetRandPort();
int         GetRandVlan();
int         GetRandPktLen();
U8          GetRandL4HexPro();

char*       GetStrPro(U16);
U16         GetL3HexPro(char*);
U8          GetL4HexPro(char*);
void        ProgramProgress(int, int);
void        DisplayPacketData(char*, int);
int         GetDataLen(int);

int         CheckIpAddrLegal(char* );
void        BufferCopy(char*, int, char*, int);

int         OpenReadFile(char* );
int         OpenSaveFile(char* );


#define     FALSE 0
#define     SUCCESS 1

#endif

