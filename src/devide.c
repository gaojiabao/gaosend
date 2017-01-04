#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "packet.h"
#include "default.h"
#include "runlog.h"
#include "storage.h"
#include "common.h"


void DevidePacket()
{
    int  iFdIn;
    int  iFdOut;
    int  iNewPktLen;
    int  iNameSuffix = 1;
    char cSaveFileName[20];
    char cPcapHdrBuf[PCAPHDRLEN];
    char cPktHdrBuf[PKTHDRLEN];
    char cDataBuf[PKTMAXLEN];
    char cPacket[PKTMAXLEN];
    char* pReadFileName = GetcValue("readfile");
    _pkthdr* pPktHdr = (_pkthdr*)cPktHdrBuf;

    LOGRECORD(DEBUG, "Devide cPacket start...");
    if ((iFdIn = open(pReadFileName, O_RDWR)) < 0) {
        LOGRECORD(ERROR, "open file error");
    }

    if (read(iFdIn, cPcapHdrBuf, PCAPHDRLEN) < 0) {
        LOGRECORD(ERROR, "read cPcapHdrBuf error");
    }

    char *pNamePrefix = strtok(pReadFileName, ".");

    while (read(iFdIn, cPktHdrBuf, PKTHDRLEN)) {
        DisplayPacketData(cPktHdrBuf, PKTHDRLEN);
        sprintf(cSaveFileName, "%s-%d.pcap", pNamePrefix,iNameSuffix++);
        BufferCopy(cPacket, 0, cPcapHdrBuf, PCAPHDRLEN);
        BufferCopy(cPacket, PCAPHDRLEN, cPktHdrBuf, PKTHDRLEN);

        if (read(iFdIn, cDataBuf, pPktHdr->len) < 0) {
            LOGRECORD(ERROR, "read cDataBuf error");
        }

        BufferCopy(cPacket, PCAPHDRLEN+PKTHDRLEN, cDataBuf, pPktHdr->len);
        iNewPktLen = PCAPHDRLEN + PKTHDRLEN + pPktHdr->len;
        
        if ((iFdOut = open(cSaveFileName, O_RDWR | O_APPEND | O_CREAT, PERM)) < 0) {
            LOGRECORD(ERROR, "open file error");
        }

        if (write(iFdOut, cPacket, iNewPktLen) < 0) {
            LOGRECORD(ERROR, "write file error");
        }
        memset(cPacket, 0, sizeof(cPacket));
        memset(cPktHdrBuf, 0, sizeof(cPktHdrBuf));
        memset(cDataBuf, 0, sizeof(cDataBuf));

        close(iFdOut);
    } // end of while

    close(iFdIn);
    LOGRECORD(DEBUG, "Devide cPacket finished...");
}

