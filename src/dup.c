#include    <stdio.h>
#include    <unistd.h>
#include    <string.h>
#include    "runlog.h"
#include    "packet.h"
#include    "storage.h"
#include    "common.h"


/* Pcap header processing entry */
void PcapHeadProcessing(int iReadFd, int iSaveFd)
{
    char cPcapHdrBuf[PCAPHDRLEN];
    if (read(iReadFd, cPcapHdrBuf, PCAPHDRLEN) < 0) {
        LOGRECORD(ERROR, "Pcap header read failed");
    }

    // File type checking
    _pcaphdr* pPcapHdr = (_pcaphdr* )cPcapHdrBuf;
    if (pPcapHdr->magic != htonl(0xd4c3b2a1)) {
        LOGRECORD(ERROR, "File type does not recognize");
    }

    if (write(iSaveFd, cPcapHdrBuf, PCAPHDRLEN) < 0) {
        LOGRECORD(ERROR, "Pcap header duplicate failed");
    }
}

/* Pcap file data processing entry */
int PcapDataProcessing(int iReadFd)
{
    int iEndPosition = lseek(iReadFd, 0, SEEK_END);
    int iInitPosition = lseek(iReadFd, PCAPHDRLEN, SEEK_SET);
    return (iEndPosition - iInitPosition);
}

/* Duplicate pcap-file to N times */
void DuplicatePacket()
{
    LOGRECORD(DEBUG, "Packet duplicat start");

    int iReadFd = OpenReadFile(GetcValue("readfile"));
    int iSaveFd = OpenSaveFile(GetcValue("savefile"));

    PcapHeadProcessing(iReadFd, iSaveFd);

    int iPcapDataLen = PcapDataProcessing(iReadFd);
    char* pPcapData = malloc(iPcapDataLen);

    if (read(iReadFd, pPcapData, iPcapDataLen) < 0) {
        LOGRECORD(ERROR, "Data partial read failed");
    }

    int iCopyCount = GetiValue("count");
    int iCounter = 1;
    
    // Append data
    for (; iCounter<=iCopyCount; iCounter++) {
        if (write(iSaveFd, pPcapData, iPcapDataLen) < 0) {
            LOGRECORD(ERROR, "Duplication write error");
        }
    }

    free(pPcapData);
    close(iReadFd);
    close(iSaveFd);

    LOGRECORD(DEBUG, "Packet duplication finished");
}

/* Extract data and save */
void ExtractMessage(char* pDataBuf, int iDataLen)
{
    int iSaveFd = OpenSaveFile(GetcValue("savefile"));

    if (iSaveFd < 0) {
        LOGRECORD(DEBUG, "No input save-file name");
    } else if (write(iSaveFd, pDataBuf, iDataLen) < 0) {
        LOGRECORD(ERROR, "Data extraction failed");
    } else {
        close(iSaveFd);
    }
}

/* Parse file list */
char* ParseReadList(char* pCmd)
{
    static char cCmdBuf[1000];
    char* pVar = strtok(pCmd, "-");
    while(1 == 1) {
        pVar = strtok(NULL, "-");
        if (pVar[0] == 'r') {
            strcat(cCmdBuf, pVar);
            break;
        }
    }

    return cCmdBuf;
}
    
/* Merge packets into one pcap file */
void MergePacket(int argc, char* argv[])
{
    LOGRECORD(DEBUG, "Packet merge start");

    int iReadFd = 0;
    int iSaveFd = 0;
    int iParsePcapSwitch = 1;

    char* filelist = GetcValue("filelist");
    char* file = strtok(filelist, " "); // Get rid of 'r'

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
            LOGRECORD(ERROR, "Data partial read failed");
        }

        if (write(iSaveFd, pPcapData, iPcapDataLen) < 0) {
            LOGRECORD(ERROR, "Data partial copy failed");
        }

        close(iReadFd);
        free(pPcapData);
    } // End of while

    close(iSaveFd);
    LOGRECORD(DEBUG, "Message merge complete");
}

/* Create a new file name based on the original file name */
char* GenerateFileName(char* pFileName)
{
    static char cNewFileName[32];
    static int  iNameSuffix = 0;
    char *pNamePrefix = strtok(pFileName, ".");
    sprintf(cNewFileName, "%s-%d.pcap", pNamePrefix, iNameSuffix++);

    return cNewFileName;
}

/* Split data into multiple pcap files */
void SplitPacket()
{
    int  iSaveFd;
    char cPcapHdrBuf[PCAPHDRLEN];
    char cPktHdrBuf[PKTHDRLEN];
    char cDataBuf[PKTMAXLEN];
    char* pNewFileName = NULL; 
    _pkthdr* pPktHdr = (_pkthdr*)cPktHdrBuf;

    LOGRECORD(DEBUG, "Packet split start");

    char* pReadFileName = GetcValue("readfile");
    int   iReadFd = OpenReadFile(pReadFileName);

    if (read(iReadFd, cPcapHdrBuf, PCAPHDRLEN) < 0) {
        LOGRECORD(ERROR, "Pcap Header read failed");
    }

    // Split function
    while (read(iReadFd, cPktHdrBuf, PKTHDRLEN)) {
        pNewFileName = GenerateFileName(pReadFileName);
        iSaveFd = OpenSaveFile(pNewFileName);

        if (read(iReadFd, cDataBuf, pPktHdr->len) < 0) {
            LOGRECORD(ERROR, "Pcap file data read failed");
        }
        if (write(iSaveFd, cPcapHdrBuf, PCAPHDRLEN) < 0) {
            LOGRECORD(ERROR, "Pcap header write failed");
        }
        if (write(iSaveFd, cPktHdrBuf, PKTHDRLEN) < 0) {
            LOGRECORD(ERROR, "Packet header write failed");
        }
        if (write(iSaveFd, cDataBuf, pPktHdr->len) < 0) {
            LOGRECORD(ERROR, "Data write failed");
        }

        memset(cDataBuf, 0, sizeof(cDataBuf));

        close(iSaveFd);
    } // End of while

    close(iReadFd);
    LOGRECORD(DEBUG, "Data packet split finished");
}

