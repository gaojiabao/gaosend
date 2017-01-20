#include    <time.h>
#include    <fcntl.h>
#include    <stdio.h>
#include    <stdlib.h>
#include    <stdarg.h>
#include    <unistd.h>
#include    <string.h>
#include    <libgen.h>
#include    <sys/time.h>
#include    "runlog.h"
#include    "common.h"
#include    "default.h"


static char cTimeBuf[SIZE_128B*2];

static void RecordRunningLog(char* pcLog)
{
    int iLogFd = 0;

    if ((iLogFd = open("/etc/.sendlog", \
        O_WRONLY | O_CREAT | O_APPEND, PERM)) < 0 ) {
        LOGRECORD(ERROR, "Open log failed");
    }

    /* Record running log */
    if (write(iLogFd, pcLog, strlen(pcLog)) < 0) {
        LOGRECORD(ERROR, "Record log failed");
    }

    close(iLogFd);
}

static void ErrorProcessingEntrance(char* pcLog, char* pcInfo)
{
    RecordRunningLog(pcLog);
    printf("Error:%s\n", pcInfo);

    PROGRAMEND();
}

static void WarningProcessingEntrance(char* pcLog, char* pcInfo)
{
    RecordRunningLog(pcLog);
    printf("WARNING:%s\n", pcInfo);
}

static void DebugProcessingEntrance(char* pcLog)
{
    RecordRunningLog(pcLog);
}

static void InfoProcessingEntrance(char* pcLog, char* pcInfo)
{
    RecordRunningLog(pcLog);
    printf("%s\n", pcInfo);
}

static void GetCurrentTime()
{
    char    cTimeTmp[SIZE_128B];
    time_t  tRawTime;
    struct  tm* stTimeInfo;
    struct  timeval tp;

    gettimeofday(&tp, NULL);

    time(&tRawTime);
    stTimeInfo = localtime(&tRawTime);
    memset(cTimeBuf, 0, sizeof(cTimeBuf));
    strftime(cTimeBuf, 20, "%x %X", stTimeInfo);

    sprintf(cTimeTmp, ".%ld", tp.tv_usec);
    strcat(cTimeBuf, cTimeTmp);
}

void LogProcessingEntrance(char* filename, int line, int level, char* fmt,...)
{
    char       cLogBuf[SIZE_1K*4];
    char       cTmpBuf[SIZE_1K*4];
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

