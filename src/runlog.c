#include    <stdio.h>
#include    <stdlib.h>
#include    <stdarg.h>
#include    <fcntl.h>
#include    <unistd.h>
#include    <string.h>
#include	<libgen.h>
#include	<time.h>
#include	<sys/time.h>
#include    "default.h"
#include    "runlog.h"

static char cTimeBuf[256];

void RecordRunningLog(char* pcLog)
{
    int      iLogFd;
    char*    cLogFileName = "/etc/.sendlog";

    /* open log */
    if ((iLogFd = open(cLogFileName, O_RDWR 
		| O_APPEND | O_CREAT, PERM)) < 0) {
		LOGRECORD(ERROR, "log open error! [fd]:%d", iLogFd);
    }

    /* write log */
    if (write(iLogFd, pcLog, strlen(pcLog)) < 0) {
		LOGRECORD(ERROR, "log write error");
    }

    /* close log */
    close(iLogFd);
}

void ErrorProcessingEntrance(char* pcLog, char* pcInfo)
{
    RecordRunningLog(pcLog);
    printf("Error:%s\n",pcInfo);
    PROGRAMEND();

    exit(0);
}

void WarningProcessingEntrance(char* pcLog, char* pcInfo)
{
    RecordRunningLog(pcLog);
    printf("WARNING:%s\n",pcInfo);
}

void DebugProcessingEntrance(char* pcLog)
{
    RecordRunningLog(pcLog);
}

void InfoProcessingEntrance(char* pcLog, char* pcInfo)
{
    RecordRunningLog(pcLog);
    printf("%s\n",pcInfo);
}

void GetCurrentTime()
{
	char	cTimeTmp[128];
	time_t	tRawTime;
	struct	tm*		stTimeInfo;
    struct	timeval tp;

    gettimeofday(&tp, NULL);

	time(&tRawTime);
	stTimeInfo = localtime(&tRawTime);
	memset(cTimeBuf, 0, sizeof(cTimeBuf));
	strftime(cTimeBuf, 20,"%x %X", stTimeInfo);

	sprintf(cTimeTmp, ".%ld", tp.tv_usec);
	strcat(cTimeBuf, cTimeTmp);
}

void LogProcessingEntrance(char* filename, int line, int level, char* fmt,...)
{
    char       cLogBuf[256];
    char       cTmpBuf[256];
    va_list    vaArgPtr;

    va_start(vaArgPtr, fmt);
    vsprintf(cTmpBuf, fmt, vaArgPtr);
    va_end(vaArgPtr);

	GetCurrentTime();
	
    sprintf(cLogBuf, "[%11s][%4d][%-24s][====>][%d][%s]\n", 
                (char*)(basename(filename)), line, cTimeBuf, level, cTmpBuf);

    switch(level)
    {
        case ERROR   : ErrorProcessingEntrance(cLogBuf, cTmpBuf); 
                       break;
        case WARNING : WarningProcessingEntrance(cLogBuf, cTmpBuf); 
                       break;
        case DEBUG   : DebugProcessingEntrance(cLogBuf); 
                       break;
        case INFO    : InfoProcessingEntrance(cLogBuf, cTmpBuf);
                       break;
        default      : break;
    }
}

