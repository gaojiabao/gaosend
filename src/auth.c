#include    <time.h>   
#include    <stdio.h> 
#include    <fcntl.h>
#include    <stdlib.h>
#include    <unistd.h>
#include    <string.h>
#include    <stdlib.h>  
#include    <arpa/inet.h>
#include    "default.h"
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
  
  
static void Encode(unsigned char *output, UINT4 *input, unsigned int len)   
{   
    unsigned int i, j;   
      
    for (i = 0, j = 0; j < len; i++, j += 4) {   
        output[j] = (unsigned char)(input[i] & 0xff);   
        output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);   
        output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);   
        output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);   
    }   
}   
  
static void Decode(UINT4 *output, unsigned char *input, unsigned int len)   
{   
    unsigned int i, j;   
     
    for (i = 0, j = 0; j < len; i++, j += 4)   
        output[i] = ((UINT4)input[j]) | (((UINT4)input[j+1]) << 8) |   
        (((UINT4)input[j+2]) << 16) | (((UINT4)input[j+3]) << 24);   
}   
  
static void MD5Transform(UINT4 state[4], unsigned char block[64])   
{   
    UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];   
    Decode   (x,   block,   64);   
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
    state[0] += a;   
    state[1] += b;   
    state[2] += c;   
    state[3] += d;   
    memset((POINTER)x, 0, sizeof(x));   
}   

static char* MD5DigestDisplay(unsigned char* array) 
{
    static char cMd5Buf[100];

    int i;
    for (i=0; i<MD5LEN; i++) {
        sprintf(&cMd5Buf[i], "%02X", array[i]);
    }

    return cMd5Buf;
}

static void MD5Init(MD5_CTX *context)   
{   
    context->count[0] = context->count[1] = 0;   
    context->state[0] = 0x67452301;   
    context->state[1] = 0xefcdab89;   
    context->state[2] = 0x98badcfe;   
    context->state[3] = 0x10325476;   
}   
  
static void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputLen)   
{   
    unsigned int i, index, partLen;   
      
    index = (unsigned int)((context->count[0] >> 3) & 0x3F);   
    if ((context->count[0] += ((UINT4)inputLen << 3)) < ((UINT4)inputLen << 3))   
        context->count[1]++;   
    context->count[1] += ((UINT4)inputLen >> 29);   
      
    partLen = 64 - index;   
      
    if (inputLen >= partLen) {   
        memcpy((POINTER)&context->buffer[index], (POINTER)input, partLen);   
        MD5Transform(context->state, context->buffer);   
      
        for (i = partLen; i + 63 < inputLen; i += 64)   
            MD5Transform(context->state, &input[i]);   
        index = 0;   
    }   
    else   
        i = 0;   
      
    memcpy((POINTER)&context->buffer[index], (POINTER)&input[i], inputLen-i);   
}   
  
static void MD5Final(unsigned char digest[16], MD5_CTX *context)   
{   
    unsigned char bits[8];   
    unsigned int index, padLen;   
      
    Encode(bits, context->count, 8);   
    index = (unsigned int)((context->count[0] >> 3) & 0x3f);   
    padLen = (index < 56) ? (56 - index) : (120 - index);   
    MD5Update(context, PADDING, padLen);   
    MD5Update(context, bits, 8);   
    Encode(digest, context->state, 16);   
    memset((POINTER)context, 0, sizeof(*context));   
}   
  
static int IsPasswdOK(unsigned char* pPasswdMD5)
{
    int iCounter;
    for (iCounter=0; iCounter<MD5LEN; iCounter++) {
        if (pPasswdMD5[iCounter] != ACTIVEPASSWD[iCounter]) {
            return 0;
        }
    }
    return 1;
}

unsigned char* MD5Digest(char* pszInput) 
{   
    static unsigned char pszOutPut[MD5LEN];   
    unsigned int len = strlen(pszInput); 

    MD5_CTX context;   
      
    MD5Init(&context);   
    MD5Update(&context, (unsigned char *)pszInput, len);
    MD5Final(pszOutPut, &context);   
    if (GetiValue("debug")) {
        LOGRECORD(DEBUG, "User Input MD5: %s", MD5DigestDisplay(pszOutPut));
    }

    return pszOutPut;
}   

void SuperManUser()
{
    char    passwd[32];

    LOGRECORD(DEBUG, "SuperMan Mode start...");
    LOGRECORD(INFO, "please input password:");

    if (scanf("%s", passwd) < 0) {
        LOGRECORD(ERROR, "scanf error");
    }

    if (IsPasswdOK(MD5Digest(passwd))) {
        remove(pLogName);
        LOGRECORD(INFO, "Perform success and please running again.");
    } else {
        LOGRECORD(ERROR, "Password input error");
    }

    LOGRECORD(DEBUG, "SuperMan Mode finished...");
}

static void UseTimesFunction(int iUseNumber, int iNum)
{
    int     iUseFd;
    char    cUseNumber[10];

    if ((iUseFd = open(pLogName, O_WRONLY | O_CREAT, PERM)) < 0) {
        LOGRECORD(ERROR, "License file open error");
    }

    memset(cUseNumber, 0, sizeof(cUseNumber));
    iUseNumber += iNum;
    sprintf(cUseNumber, "%d", iUseNumber);

    if (write(iUseFd, cUseNumber, strlen(cUseNumber)) < 0) {
        LOGRECORD(ERROR, "License file write error");
    }
    
    close(iUseFd);
    LOGRECORD(DEBUG, "Use Times: [%d/%d]", iUseNumber, MAXUSETIMES);
} 

/* judge authority */
void CertificationAuthority()
{
    int     iUseFd;
    int     iUseNumber;
    char    cUseNumber[10];

    if (GetiValue("entrance") == 111) {
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
        LOGRECORD(ERROR, "The number of use is over limited[%d]", iUseNumber);
    }
    
    close(iUseFd);
    UseTimesFunction(iUseNumber, 1);
}

