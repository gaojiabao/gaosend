#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	"packet.h"
#include	"default.h"
#include	"runlog.h"
#include	"list.h"


char mopt[100];

char* GetFileList(int argc, char* argv[])
{
	int nvar=1;
	char vbuf[100];

	while(nvar < argc){
		strcat(vbuf, " ");
		strcat(vbuf, argv[nvar]);
		nvar++;
	}

	char* var = strtok(vbuf, "-");
	while(1) {
		var = strtok(NULL, "-");
		if(var[0] == 'r'){
			strcat(mopt,var);
			return mopt;
		}
	}
}

void MergePacket(int argc, char* argv[])
{
	int		iReadFd, iWriteFd;
	int		iEndPosion, iCurrentPosion;
	int		iIsReadPcapHeader = 0;
	int		iPacketLengthWithHeader;
	char	cPacket[PKTMAXLEN];
	char	cPcapBuf[PCAPHDRLEN];
	char*	cpSaveFileName = GetcValue("savefile");
	char*   filelist = GetFileList(argc, argv);
	_pcaphdr *p = (_pcaphdr*)cPcapBuf;

	LOGRECORD(DEBUG, "Merge Packet start...");

	if((iWriteFd = open(cpSaveFileName, O_RDWR | O_APPEND 
						| O_EXCL | O_CREAT, PERM)) < 0) {
		LOGRECORD(ERROR, "open savefile error");
	}

	char* file = strtok(filelist, " ");

	while(1) {
		if((file = strtok(NULL, " ")) == NULL){
			break;
		}

		if((iReadFd = open(file, O_RDWR)) < 0){
			LOGRECORD(ERROR, "open readfile error");
		}

		// judge legal 
		if(read(iReadFd, cPcapBuf, PCAPHDRLEN) < 0){
			LOGRECORD(ERROR, "read cPacket error");
		}
		if(p->magic != htonl(0xD4C3B2A1)){
			LOGRECORD(ERROR, "file parten error");
		}

		// calculate cPacket length 
		iEndPosion = lseek(iReadFd, 0, SEEK_END);
		if(iIsReadPcapHeader == 0) {
			iCurrentPosion = lseek(iReadFd, 0, SEEK_SET);
			iIsReadPcapHeader = -1;
		} else {
			iCurrentPosion = lseek(iReadFd, PCAPHDRLEN, SEEK_SET);
		}
		iPacketLengthWithHeader = iEndPosion - iCurrentPosion;

		memset(cPacket, 0, sizeof(cPacket));
		if(read(iReadFd, cPacket, iPacketLengthWithHeader) < 0){
			LOGRECORD(ERROR, "read cPacket error");
		}

		if(write(iWriteFd, cPacket, iPacketLengthWithHeader) < 0){
			LOGRECORD(ERROR, "write cPacket error");
		}
		close(iReadFd);
	}// end of while

	close(iWriteFd);
	LOGRECORD(DEBUG, "Merge Packet finished...");
}

