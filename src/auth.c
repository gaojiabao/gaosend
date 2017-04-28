/*******************************************************
 *
 *  Author        : Mr.Gao
 *  Email         : 729272771@qq.com
 *  Filename      : auth.c
 *  Last modified : 2017-04-25 14:10
 *  Description   : Check software usage rights 
 *
 * *****************************************************/
 

#include    <stdio.h> 
#include    <fcntl.h>
#include    <stdlib.h>
#include    <unistd.h>
#include    <string.h>
#include    "runlog.h"
#include    "storage.h"


#define     MAXUSETIMES 500

char*    pLogName = "/etc/.send";

typedef unsigned char  *POINTER;   
typedef unsigned short int UINT2;   
typedef unsigned long  int UINT4;   

typedef struct     
{   
    UINT4 state[4];   
    UINT4 count[2];   
    unsigned char buffer[64];   
}   MD5_CTX;   

#define S11 7   
#define S12 12   
#define S13 17   
#define S14 22   
#define S21 5   
#define S22 9   
#define S23 14   
#define S24 20   
#define S31 4   
#define S32 11   
#define S33 16   
#define S34 23   
#define S41 6   
#define S42 10   
#define S43 15   
#define S44 21   

static unsigned char PADDING[64] = {   
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   
};   

static unsigned char ACTIVEPASSWD[16] = {
    0x2D, 0xDE, 0x07, 0xF5, 0x9C, 0x85, 0x6E, 0x3D, 
    0x29, 0x6B, 0x6D, 0xF6, 0x2C, 0x0E, 0xE5, 0x9D
};

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))   
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))   
#define H(x, y, z) ((x) ^ (y) ^ (z))   
#define I(x, y, z) ((y) ^ ((x) | (~z)))   

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))   

#define FF(a, b, c, d, x, s, ac) {(a) += F((b), (c), (d)) + (x) + (UINT4)(ac); (a) = ROTATE_LEFT((a), (s)); (a) += (b);}   
#define GG(a, b, c, d, x, s, ac) {(a) += G((b), (c), (d)) + (x) + (UINT4)(ac); (a) = ROTATE_LEFT((a), (s)); (a) += (b);}   
#define HH(a, b, c, d, x, s, ac) {(a) += H((b), (c), (d)) + (x) + (UINT4)(ac); (a) = ROTATE_LEFT((a), (s)); (a) += (b);}   
#define II(a, b, c, d, x, s, ac) {(a) += I((b), (c), (d)) + (x) + (UINT4)(ac); (a) = ROTATE_LEFT((a), (s)); (a) += (b);}   


static void Encode(unsigned char* pOutPut, UINT4* pInput, unsigned int iLength)   
{   
    unsigned int iNumI, iNumJ;   

    for (iNumI = 0, iNumJ = 0; iNumJ < iLength; iNumI ++, iNumJ += 4) {   
        pOutPut[iNumJ] = (unsigned char)(pInput[iNumI] & 0xff);   
        pOutPut[iNumJ+1] = (unsigned char)((pInput[iNumI] >> 8) & 0xff);   
        pOutPut[iNumJ+2] = (unsigned char)((pInput[iNumI] >> 16) & 0xff);   
        pOutPut[iNumJ+3] = (unsigned char)((pInput[iNumI] >> 24) & 0xff);   
    }   
}   

static void Decode(UINT4 *pOutPut, unsigned char *pInput, unsigned int iLength)   
{   
    unsigned int iNumI, iNumJ;   

    for (iNumI = 0, iNumJ = 0; iNumJ < iLength; iNumI ++, iNumJ += 4) {  
        pOutPut[iNumI] = ((UINT4)pInput[iNumJ]) 
            | (((UINT4)pInput[iNumJ+1]) << 8) 
            | (((UINT4)pInput[iNumJ+2]) << 16) 
            | (((UINT4)pInput[iNumJ+3]) << 24);   
    }
}   

static void MD5Transform(UINT4 cState[4], unsigned char cBlock[64])   
{   
    UINT4 a = cState[0], b = cState[1], c = cState[2], d = cState[3], x[16];   
    Decode   (x,   cBlock,   64);   
    FF(a, b, c, d, x[0],  S11, 0xd76aa478);   /*   1   */   
    FF(d, a, b, c, x[1],  S12, 0xe8c7b756);   /*   2   */   
    FF(c, d, a, b, x[2],  S13, 0x242070db);   /*   3   */   
    FF(b, c, d, a, x[3],  S14, 0xc1bdceee);   /*   4   */   
    FF(a, b, c, d, x[4],  S11, 0xf57c0faf);   /*   5   */   
    FF(d, a, b, c, x[5],  S12, 0x4787c62a);   /*   6   */   
    FF(c, d, a, b, x[6],  S13, 0xa8304613);   /*   7   */   
    FF(b, c, d, a, x[7],  S14, 0xfd469501);   /*   8   */   
    FF(a, b, c, d, x[8],  S11, 0x698098d8);   /*   9   */   
    FF(d, a, b, c, x[9],  S12, 0x8b44f7af);   /*   10   */   
    FF(c, d, a, b, x[10], S13, 0xffff5bb1);   /*   11   */   
    FF(b, c, d, a, x[11], S14, 0x895cd7be);   /*   12   */   
    FF(a, b, c, d, x[12], S11, 0x6b901122);   /*   13   */   
    FF(d, a, b, c, x[13], S12, 0xfd987193);   /*   14   */   
    FF(c, d, a, b, x[14], S13, 0xa679438e);   /*   15   */   
    FF(b, c, d, a, x[15], S14, 0x49b40821);   /*   16   */   
    GG(a, b, c, d, x[1],  S21, 0xf61e2562);   /*   17   */   
    GG(d, a, b, c, x[6],  S22, 0xc040b340);   /*   18   */   
    GG(c, d, a, b, x[11], S23, 0x265e5a51);   /*   19   */   
    GG(b, c, d, a, x[0],  S24, 0xe9b6c7aa);   /*   20   */   
    GG(a, b, c, d, x[5],  S21, 0xd62f105d);   /*   21   */   
    GG(d, a, b, c, x[10], S22, 0x2441453);    /*   22   */   
    GG(c, d, a, b, x[15], S23, 0xd8a1e681);   /*   23   */   
    GG(b, c, d, a, x[4],  S24, 0xe7d3fbc8);   /*   24   */   
    GG(a, b, c, d, x[9],  S21, 0x21e1cde6);   /*   25   */   
    GG(d, a, b, c, x[14], S22, 0xc33707d6);   /*   26   */   
    GG(c, d, a, b, x[3],  S23, 0xf4d50d87);   /*   27   */   
    GG(b, c, d, a, x[8],  S24, 0x455a14ed);   /*   28   */   
    GG(a, b, c, d, x[13], S21, 0xa9e3e905);   /*   29   */   
    GG(d, a, b, c, x[2],  S22, 0xfcefa3f8);   /*   30   */   
    GG(c, d, a, b, x[7],  S23, 0x676f02d9);   /*   31   */   
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);   /*   32   */   
    HH(a, b, c, d, x[5],  S31, 0xfffa3942);   /*   33   */   
    HH(d, a, b, c, x[8],  S32, 0x8771f681);   /*   34   */   
    HH(c, d, a, b, x[11], S33, 0x6d9d6122);   /*   35   */   
    HH(b, c, d, a, x[14], S34, 0xfde5380c);   /*   36   */   
    HH(a, b, c, d, x[1],  S31, 0xa4beea44);   /*   37   */   
    HH(d, a, b, c, x[4],  S32, 0x4bdecfa9);   /*   38   */   
    HH(c, d, a, b, x[7],  S33, 0xf6bb4b60);   /*   39   */   
    HH(b, c, d, a, x[10], S34, 0xbebfbc70);   /*   40   */   
    HH(a, b, c, d, x[13], S31, 0x289b7ec6);   /*   41   */   
    HH(d, a, b, c, x[0],  S32, 0xeaa127fa);   /*   42   */   
    HH(c, d, a, b, x[3],  S33, 0xd4ef3085);   /*   43   */   
    HH(b, c, d, a, x[6],  S34, 0x4881d05);    /*   44   */   
    HH(a, b, c, d, x[9],  S31, 0xd9d4d039);   /*   45   */   
    HH(d, a, b, c, x[12], S32, 0xe6db99e5);   /*   46   */   
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8);   /*   47   */   
    HH(b, c, d, a, x[2],  S34, 0xc4ac5665);   /*   48   */   
    II(a, b, c, d, x[0],  S41, 0xf4292244);   /*   49   */   
    II(d, a, b, c, x[7],  S42, 0x432aff97);   /*   50   */   
    II(c, d, a, b, x[14], S43, 0xab9423a7);   /*   51   */   
    II(b, c, d, a, x[5],  S44, 0xfc93a039);   /*   52   */   
    II(a, b, c, d, x[12], S41, 0x655b59c3);   /*   53   */   
    II(d, a, b, c, x[3],  S42, 0x8f0ccc92);   /*   54   */   
    II(c, d, a, b, x[10], S43, 0xffeff47d);   /*   55   */   
    II(b, c, d, a, x[1],  S44, 0x85845dd1);   /*   56   */   
    II(a, b, c, d, x[8],  S41, 0x6fa87e4f);   /*   57   */   
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0);   /*   58   */   
    II(c, d, a, b, x[6],  S43, 0xa3014314);   /*   59   */   
    II(b, c, d, a, x[13], S44, 0x4e0811a1);   /*   60   */   
    II(a, b, c, d, x[4],  S41, 0xf7537e82);   /*   61   */   
    II(d, a, b, c, x[11], S42, 0xbd3af235);   /*   62   */   
    II(c, d, a, b, x[2],  S43, 0x2ad7d2bb);   /*   63   */   
    II(b, c, d, a, x[9],  S44, 0xeb86d391);   /*   64   */   
    cState[0] += a;   
    cState[1] += b;   
    cState[2] += c;   
    cState[3] += d;   
    memset((POINTER)x, 0, sizeof(x));   
}   

// Echo MD5 value 
static char* MD5DigestDisplay(unsigned char* pMD5Value) 
{
    static char cMd5Buf[100];

    int iNum;
    for (iNum = 0; iNum < MD5LEN; iNum ++) {
        sprintf(&cMd5Buf[iNum], "%02X", pMD5Value[iNum]);
    }

    return cMd5Buf;
}

static void MD5Init(MD5_CTX *pContext)   
{   
    pContext->count[0] = pContext->count[1] = 0;   
    pContext->state[0] = 0x67452301;   
    pContext->state[1] = 0xefcdab89;   
    pContext->state[2] = 0x98badcfe;   
    pContext->state[3] = 0x10325476;   
}   

static void MD5Update(MD5_CTX *pContext, 
        unsigned char *pInput,unsigned int iInputLen)   
{   
    unsigned int iNum, iIndex, iPartLen;   

    iIndex = (unsigned int)((pContext->count[0] >> 3) & 0x3F);   
    if ((pContext->count[0] += ((UINT4)iInputLen << 3)) 
            < ((UINT4)iInputLen << 3)) {   
        pContext->count[1] ++;   
    }
    pContext->count[1] += ((UINT4)iInputLen >> 29);   

    iPartLen = 64 - iIndex;   

    if (iInputLen >= iPartLen) {   
        memcpy((POINTER)&pContext->buffer[iIndex], (POINTER)pInput, iPartLen);   
        MD5Transform(pContext->state, pContext->buffer);   

        for (iNum = iPartLen; iNum + 63 < iInputLen; iNum += 64) {
            MD5Transform(pContext->state, &pInput[iNum]);   
        }
        iIndex = 0;   
    } else {   
        iNum = 0;   
    }

    memcpy((POINTER)&pContext->buffer[iIndex], (POINTER)&pInput[iNum], iInputLen-iNum);   
}   

static void MD5Final(unsigned char cDigest[16], MD5_CTX *pContext)   
{   
    unsigned char cBits[8];   
    unsigned int iIndex, iPadLen;   

    Encode(cBits, pContext->count, 8);   
    iIndex = (unsigned int)((pContext->count[0] >> 3) & 0x3f);   
    iPadLen = (iIndex < 56) ? (56 - iIndex) : (120 - iIndex);   
    MD5Update(pContext, PADDING, iPadLen);   
    MD5Update(pContext, cBits, 8);   
    Encode(cDigest, pContext->state, 16);   
    memset((POINTER)pContext, 0, sizeof(*pContext));   
}   

/* Verify password */
static int IsPasswdOK(unsigned char* pPasswdMD5)
{
    int iNum;
    for (iNum = 0; iNum < MD5LEN; iNum ++) {
        if (pPasswdMD5[iNum] != ACTIVEPASSWD[iNum]) {
            return 0;
        }
    }

    return 1;
}

/* MD5 abstract algorithm portal */
unsigned char* MD5Digest(char* pszInput) 
{   
    static unsigned char pszOutPut[MD5LEN];   
    unsigned int len = strlen(pszInput); 

    MD5_CTX context;   

    MD5Init(&context);   
    MD5Update(&context, (unsigned char *)pszInput, len);
    MD5Final(pszOutPut, &context);   
    if (GetNum("debug")) {
        LOGRECORD(DEBUG, "User Input MD5: %s", MD5DigestDisplay(pszOutPut));
    }

    return pszOutPut;
}   

/* Superman user login authentication */
void SuperManUser()
{
    char    cInputPasswd[32];

    LOGRECORD(DEBUG, "User login authentication start");
    LOGRECORD(INFO, "Please input password:");

    if (scanf("%s", cInputPasswd) < 0) {
        LOGRECORD(ERROR, "Input error");
    }

    if (IsPasswdOK(MD5Digest(cInputPasswd))) {
        remove(pLogName);
        LOGRECORD(INFO, "Execute successfully and please run the software again");
    } else {
        LOGRECORD(ERROR, "Password input error");
    }

    LOGRECORD(DEBUG, "User login authentication success");
}

/* Software use counter */
static void UseTimesFunction(int iUseNumber, int iNum)
{
    int     iUseFd;
    char    cUseNumber[10];

    if ((iUseFd = open(pLogName, O_WRONLY | O_CREAT, PERM)) < 0) {
        LOGRECORD(ERROR, "License file open failed");
    }

    memset(cUseNumber, 0, sizeof(cUseNumber));
    iUseNumber += iNum;
    sprintf(cUseNumber, "%d", iUseNumber);

    if (write(iUseFd, cUseNumber, strlen(cUseNumber)) < 0) {
        LOGRECORD(ERROR, "License file write failed");
    }

    close(iUseFd);
    LOGRECORD(DEBUG, "Use Times: [%d/%d]", iUseNumber, MAXUSETIMES);
} 

/* Verify user permissions */
void CertificationAuthority()
{
    int     iUseFd;
    int     iUseNumber;
    char    cUseNumber[10];

    if (GetNum("entrance") == 111) {
        SuperManUser();
        PROGRAMEND();
    }
    if ((iUseFd = open(pLogName, O_RDONLY | O_CREAT, PERM)) < 0) {
        LOGRECORD(ERROR, "License file open error");
    }

    memset(cUseNumber, 0, sizeof(cUseNumber));
    if (read(iUseFd, cUseNumber, sizeof(cUseNumber)) < 0) {
        LOGRECORD(ERROR, "License file read error");
    }

    iUseNumber = atoi(cUseNumber);
    if (iUseNumber > MAXUSETIMES) {
        LOGRECORD(ERROR, "The number of users has reached the upper limit");
    }

    close(iUseFd);
    UseTimesFunction(iUseNumber, 1);
}

