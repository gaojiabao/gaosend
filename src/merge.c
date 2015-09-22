#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	"packet.h"
#include	"default.h"
#include	"runlog.h"

void UseTimesFunction(int);
void merge(char* filelist)
{
	int		iReadFd;
	int		iWriteFd;
	int		iEndPosion;
	int		iCurrentPosion;
	int		iIsReadPcapHeader = 0;
	int		iPacketLengthWithHeader;
	char	cPacket[PKTMAXLEN];
	char	cPcapBuf[PCAPHDRLEN];
	char*	cpSaveFileName = "resule.pcap";

	UseTimesFunction(+1);

	_pcaphdr *p = (_pcaphdr*)cPcapBuf;

	if((iWriteFd = open(cpSaveFileName, O_RDWR | O_APPEND 
		| O_EXCL | O_CREAT, PERM)) < 0) {
		LOGRECORD(ERROR, "open file error");
	}

	char* file = strtok(filelist," ");

	while(1) {
		if((file = strtok(NULL," ")) == NULL){
			break;
		}

		if((iReadFd = open(file,O_RDWR)) < 0){
			LOGRECORD(ERROR, "open file error");
		}

		/* judge legal */
		if(read(iReadFd, cPcapBuf, PCAPHDRLEN) < 0){
			LOGRECORD(ERROR, "read cPacket error");
		}
		if(p->magic != htonl(0xD4C3B2A1)){
			LOGRECORD(ERROR, "file parten error");
		}

		/* calculate cPacket length */
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
	PROGRAMEND();
}

