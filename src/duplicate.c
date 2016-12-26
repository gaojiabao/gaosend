#include    <stdio.h>
#include    <fcntl.h>
#include    <unistd.h>
#include    <stdlib.h>
#include    "default.h"
#include    "runlog.h"
#include    "storage.h"

/* to duplicate a *.pcap file for N times */
void DuplicatePacket()
{
    int iFd;

    LOGRECORD(DEBUG, "Duplicat Packet iInitPosition...");
    if ((iFd = open(GetcValue("readfile"), O_RDWR | O_APPEND)) < 0 ) {
        LOGRECORD(ERROR, "Duplication open error");
    }
    int iEndPosition = lseek(iFd, 0, SEEK_END);
    int iInitPosition = lseek(iFd, PCAPHDRLEN, SEEK_SET);
    int iAllDataLen = iEndPosition - iInitPosition;
    char* pTmpBuf = malloc(iAllDataLen);
    if (read(iFd, pTmpBuf, iAllDataLen) < 0) {
        LOGRECORD(ERROR, "Duplication read error");
    }

    lseek(iFd, 0, SEEK_END);
    int iCopyCount = GetiValue("count");
    int iCounter = 1;
    for (; iCounter<iCopyCount; iCounter++) {
        if (write(iFd, pTmpBuf, iAllDataLen) < 0) {
            LOGRECORD(ERROR, "Duplication write error");
        }
    }

    free(pTmpBuf);
    close(iFd);

    LOGRECORD(DEBUG, "Duplication finished...");
}

