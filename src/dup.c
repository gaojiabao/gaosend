#include    <stdio.h>
#include    <fcntl.h>
#include    <unistd.h>
#include    <stdlib.h>
#include    "default.h"
#include    "runlog.h"
#include    "storage.h"

#include    <string.h>
#include    "packet.h"

#include    "common.h"

/* Gets the descriptor of the file being written */
int OpenSaveFile(char* pFileName)
{
    int iSaveFd = 0;
    if (pFileName == NULL) {
        LOGRECORD(ERROR, "Filename is NULL");
    }
    if ((iSaveFd = open(pFileName, \
        O_WRONLY | O_CREAT | O_APPEND, PERM)) < 0 ) {
        LOGRECORD(ERROR, "Open save-file failed");
    }

    return iSaveFd;
}

/* gets the descriptor of the file being read */
int OpenReadFile(char* pFileName)
{
    int iReadFd = 0;
    if (pFileName == NULL) {
        LOGRECORD(ERROR, "Filename is NULL");
    }
    if ((iReadFd = open(pFileName, O_RDONLY)) < 0 ) {
        LOGRECORD(ERROR, "Pcap file does not exist");
    }

    return iReadFd;
}

void PcapHeadProcessing(int iReadFd, int iSaveFd)
{
    char cPcapHdrBuf[PCAPHDRLEN];
    if (read(iReadFd, cPcapHdrBuf, PCAPHDRLEN) < 0) {
        LOGRECORD(ERROR, "Duplication read error");
    }

    // file type checking
    _pcaphdr* pPcapHdr = (_pcaphdr* )cPcapHdrBuf;
    if (pPcapHdr->magic != htonl(0xd4c3b2a1)) {
        LOGRECORD(ERROR, "File type does not recognize");
    }

    if (write(iSaveFd, cPcapHdrBuf, PCAPHDRLEN) < 0) {
        LOGRECORD(ERROR, "Duplication write error");
    }
}

int PcapDataProcessing(int iReadFd)
{
    int iEndPosition = lseek(iReadFd, 0, SEEK_END);
    int iInitPosition = lseek(iReadFd, PCAPHDRLEN, SEEK_SET);
    return (iEndPosition - iInitPosition);
}

/* duplicate pcap-file to N times */
void DuplicatePacket()
{
    LOGRECORD(DEBUG, "Duplicat Packet Init...");

    int iReadFd = OpenReadFile(GetcValue("readfile"));
    int iSaveFd = OpenSaveFile(GetcValue("savefile"));

    PcapHeadProcessing(iReadFd, iSaveFd);

    int iPcapDataLen = PcapDataProcessing(iReadFd);
    char* pPcapData = malloc(iPcapDataLen);

    if (read(iReadFd, pPcapData, iPcapDataLen) < 0) {
        LOGRECORD(ERROR, "Duplication read error");
    }

    int iCopyCount = GetiValue("count");
    int iCounter = 1;
    
    // append data
    for (; iCounter<=iCopyCount; iCounter++) {
        if (write(iSaveFd, pPcapData, iPcapDataLen) < 0) {
            LOGRECORD(ERROR, "Duplication write error");
        }
    }

    free(pPcapData);
    close(iReadFd);
    close(iSaveFd);

    LOGRECORD(DEBUG, "Duplication finished...");
}

/* extract data and save */
void ExtractMessage(char* pDataBuf, int iDataLen)
{
    int iFd;
    if ((iFd = open(GetcValue("savefile"), \
        O_WRONLY | O_APPEND | O_CREAT, PERM)) < 0 ) {
        LOGRECORD(DEBUG, "No input save-file name");
    } else if (write(iFd, pDataBuf, iDataLen) < 0) {
        LOGRECORD(ERROR, "Dup packet write error");
    } else {
        close(iFd);
    }
}

/* parse file list */
char* ParseReadList(char* pCmd)
{
    static char mopt[1000];
    char* var = strtok(pCmd, "-");
    while(1 == 1) {
        var = strtok(NULL, "-");
        if (var[0] == 'r') {
            strcat(mopt,var);
            break;
        }
    }

    return mopt;
}
    
/* merge packets into one pcap file */
void MergePacket(int argc, char* argv[])
{
    LOGRECORD(DEBUG, "Merge Packet start...");

    int iReadFd = 0;
    int iSaveFd = 0;
    int iParsePcapSwitch = 1;

    char* filelist = GetcValue("filelist");
    char* file = strtok(filelist, " "); // get rid of 'r'

    while (1 == 1) {
        if ((file = strtok(NULL, " ")) == NULL) {
            break;
        }

        iReadFd = OpenReadFile(file);
        if (iParsePcapSwitch == 1) {
            iSaveFd = OpenSaveFile(GetcValue("savefile"));
            PcapHeadProcessing(iReadFd, iSaveFd);
            iParsePcapSwitch = 0;
        }

        int   iPcapDataLen = PcapDataProcessing(iReadFd);
        char* pPcapData = malloc(iPcapDataLen);

        if (read(iReadFd, pPcapData, iPcapDataLen) < 0) {
            LOGRECORD(ERROR, "Duplication read error");
        }

        if (write(iSaveFd, pPcapData, iPcapDataLen) < 0) {
            LOGRECORD(ERROR, "Duplication write error");
        }

        close(iReadFd);
        free(pPcapData);
    } // end of while

    close(iSaveFd);
    LOGRECORD(DEBUG, "Merge Packet finished...");
}

/* create a new file name based on the original file name */
char* GenerateFileName(char* pFileName)
{
    static char cNewFileName[32];
    static int  iNameSuffix = 0;
    char *pNamePrefix = strtok(pFileName, ".");
    sprintf(cNewFileName, "%s-%d.pcap", pNamePrefix, iNameSuffix++);

    return cNewFileName;
}

/* split data into multiple pcap files */
void SplitPacket()
{
    int  iSaveFd;
    char cPcapHdrBuf[PCAPHDRLEN];
    char cPktHdrBuf[PKTHDRLEN];
    char cDataBuf[PKTMAXLEN];
    char* pNewFileName = NULL; 
    _pkthdr* pPktHdr = (_pkthdr*)cPktHdrBuf;

    LOGRECORD(DEBUG, "Devide cPacket start...");

    char* pReadFileName = GetcValue("readfile");
    int   iReadFd = OpenReadFile(pReadFileName);

    if (read(iReadFd, cPcapHdrBuf, PCAPHDRLEN) < 0) {
        LOGRECORD(ERROR, "read cPcapHdrBuf error");
    }

    // split function
    while (read(iReadFd, cPktHdrBuf, PKTHDRLEN)) {
        pNewFileName = GenerateFileName(pReadFileName);
        iSaveFd = OpenSaveFile(pNewFileName);

        if (read(iReadFd, cDataBuf, pPktHdr->len) < 0) {
            LOGRECORD(ERROR, "read cDataBuf error");
        }
        if (write(iSaveFd, cPcapHdrBuf, PCAPHDRLEN) < 0) {
            LOGRECORD(ERROR, "write file error1");
        }
        if (write(iSaveFd, cPktHdrBuf, PKTHDRLEN) < 0) {
            LOGRECORD(ERROR, "write file error2");
        }
        if (write(iSaveFd, cDataBuf, pPktHdr->len) < 0) {
            LOGRECORD(ERROR, "write file error3");
        }

        memset(cDataBuf, 0, sizeof(cDataBuf));

        close(iSaveFd);
    } // end of while

    close(iReadFd);
    LOGRECORD(DEBUG, "Devide cPacket finished...");
}

