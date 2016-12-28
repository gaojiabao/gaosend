#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "packet.h"
#include "default.h"
#include "runlog.h"
#include "storage.h"
#include "common.h"

void BufferCopy(char*, int, char*, int);

void DevidePacket()
{
    int  iFdIn,iFdOut;
    int  totle_len;
    int  iFileNameSuffix = 1;
    char name[20];
    char pcaphdr[PCAPHDRLEN];
    char pkthdr[PKTHDRLEN];
    char data[PKTMAXLEN];
    char packet[PKTMAXLEN];
    char* file = GetcValue("readfile");
    _pkthdr *p = (_pkthdr*)pkthdr;

    LOGRECORD(DEBUG, "Devide Packet start...");
    if ((iFdIn = open(file, O_RDWR)) < 0) {
        LOGRECORD(ERROR, "open file error");
    }

    if (read(iFdIn, pcaphdr, PCAPHDRLEN) < 0) {
        LOGRECORD(ERROR, "read pcaphdr error");
    }

    char *fileName = strtok(file, ".");
    while (read(iFdIn, pkthdr, PKTHDRLEN)) {
        DisplayPacketData(pkthdr, 16);
        sprintf(name, "%s-%d.pcap", fileName,iFileNameSuffix++);
        BufferCopy(packet, 0, pcaphdr, PCAPHDRLEN);
        BufferCopy(packet, PCAPHDRLEN, pkthdr, PKTHDRLEN);

        if (read(iFdIn, data, p->len) < 0) {
            LOGRECORD(ERROR, "read data error");
        }
        BufferCopy(packet, PCAPHDRLEN+PKTHDRLEN, data, p->len);
        totle_len = PCAPHDRLEN + PKTHDRLEN + p->len;
        
        if ((iFdOut = open(name, O_RDWR | O_APPEND | O_CREAT, PERM)) < 0) {
            LOGRECORD(ERROR, "open file error");
        }

        if (write(iFdOut, packet, totle_len) < 0) {
            LOGRECORD(ERROR, "write file error");
        }
        memset(packet, 0, sizeof(packet));
        memset(pkthdr, 0, sizeof(pkthdr));
        memset(data, 0, sizeof(data));

        close(iFdOut);
    }// end of while

    close(iFdIn);
    LOGRECORD(DEBUG, "Devide Packet finished...");
}

