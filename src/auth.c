#include    <stdio.h> 
#include    <fcntl.h>
#include    <stdlib.h>
#include    <unistd.h>
#include	<string.h>

#include    "default.h"
#include    "runlog.h"
#define     MAXUSETIMES 500

int		iUseNumber;
char*	pcFile = "/etc/.send";

void SuperMan()
{
    char    passwd[1024];
	LOGRECORD(INFO, "please input password:");
    if(scanf("%s", passwd) < 0){
        LOGRECORD(ERROR, "scanf error");
	}
    if(strcmp(passwd, "15210519236") == 0) {
        remove(pcFile);
        LOGRECORD(INFO, "Perform success! Please running again");
        exit(0);
    } else {
        LOGRECORD(ERROR, "Password input error");
    }
}

extern void UseTimesFunction(int iNum)
{
	int		iUseFd;
	char	cUseNumber[10];

    if((iUseFd = open(pcFile, O_WRONLY | O_CREAT, PERM)) < 0) {
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
	int		iUseFd;
	char	cUseNumber[10];

    if((iUseFd = open(pcFile, O_RDONLY | O_CREAT, PERM)) < 0) {
        LOGRECORD(ERROR, "License file open error");
    }

    if(read(iUseFd, cUseNumber, sizeof(cUseNumber)) < 0) {
        LOGRECORD(ERROR, "License file read error");
    }

    iUseNumber = atoi(cUseNumber);
    if(iUseNumber > MAXUSETIMES){
        LOGRECORD(INFO, "The frequency of use is over limited");
    }
    
    close(iUseFd);
}

