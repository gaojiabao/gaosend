/*
 *  author   : Mr. Gao
 *
 *  function : To statement functions.
 */ 

#ifndef __FUNCTION_H__
#define __FUNCTION_H__

#include    <stdio.h>
#include    "packet.h"

/* Define buffer size */
#define SIZE_16B       16
#define SIZE_128B      128
#define SIZE_1K        1024

uint16_t    GetCheckSum(uint16_t *, int);
char        ChangeHexToString(int);
char*       GetUrlString();
int         GetRandomNumber();
char*       GetRandomString(int);
int         mac_type_change (char *, char *);

char*       GetIncreaseMacAddress(int);
char*       GetIncreaseIpAddress(int);
int         GetIncreasePort(int);
int         GetIncreasePacketLength();
int         GetIncreaseVlan(int);

char*       GetRandomMacAddress(int);
char*       GetRandomIpAddress(int);
int         GetRandomPort();
int         GetRandomVlan();
int         GetRandomPacketLength();
uint8_t     GetRandomLayer4Pro();

char*       ChangeLayer4HexToString(uint16_t);
uint16_t    GetL3Hex(char*);
uint8_t     GetL4Hex(char*);
void        ProgramProgress(int, int);
char*       subs(char*, int, int);
void        DisplayPacketData(char*, int);
int         ProtocolConversion(char* );

int         CheckIpLegal(char* );
void        BufferCopy(char*, int, char*, int);

int         OpenReadFile(char* );
int         OpenSaveFile(char* );


#define     FALSE 0
#define     SUCCESS 1

#endif

