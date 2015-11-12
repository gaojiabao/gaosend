#include	<stdio.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	"runlog.h"
#include	"list.h"

/* to duplicate a *.pcap file for N times */
void DuplicatePacket()
{
	int fd, i;

	LOGRECORD(DEBUG, "Duplicat Packet start...");
	if((fd = open(GetcValue("readfile"), O_RDWR | O_APPEND)) < 0 ) {
		LOGRECORD(ERROR, "Duplication open error");
	}
	int end = lseek(fd, 0, SEEK_END);
	int start = lseek(fd, 24, SEEK_SET);
	int len = end - start;
	char* temp = malloc(len);
	if(read(fd, temp, len) < 0) {
		LOGRECORD(ERROR, "Duplication read error");
	}

	lseek(fd, 0, SEEK_END);
	int num = GetiValue("counter");
	for (i=1; i<num; i++) {
		if (write(fd, temp, len) < 0) {
			LOGRECORD(ERROR, "Duplication write error");
		}
	}

	free(temp);
	close(fd);

	LOGRECORD(DEBUG, "Duplication finished...");
}

