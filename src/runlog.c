/*******************************************************
 *
 *  Author        : Mr.Gao
 *  Email         : 729272771@qq.com
 *  Filename      : runlog.c
 *  Last modified : 2017-04-25 14:10
 *  Description   : Log handler for software
 *
 * *****************************************************/


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
#include    "default.h"

#define     SIZE_128B   128
#define     SIZE_1K     1024

/* Get the current time */
static char* GetCurrentTime()
{
    char    cTimeTmp[SIZE_128B];
    time_t  tRawTime;
    struct  timeval tp;
    struct  tm* stTimeInfo;
    static char cTimeBuf[SIZE_128B];

    gettimeofday(&tp, NULL);

    time(&tRawTime);
    stTimeInfo = localtime(&tRawTime);
    memset(cTimeBuf, 0, sizeof(cTimeBuf));
    strftime(cTimeBuf, 20, "%x %X", stTimeInfo);

    sprintf(cTimeTmp, ".%ld", tp.tv_usec);
    strcat(cTimeBuf, cTimeTmp);

    return cTimeBuf;
}

/* Record program running log */
static void RecordRunningLog(char* pLog)
{
    int iLogFd = 0;

    if ((iLogFd = open("/etc/.sendlog", \
                    O_WRONLY | O_CREAT | O_APPEND, PERM)) < 0 ) {
        LOGRECORD(ERROR, "Open log failed");
    }

    /* Record running log */
    if (write(iLogFd, pLog, strlen(pLog)) < 0) {
        LOGRECORD(ERROR, "Record log failed");
    }

    close(iLogFd);
}

/* Program info handling */
static void InfoProcessing(char* pLog, char* pInfo)
{
    RecordRunningLog(pLog);
    printf("%s\n", pInfo);
}

/* Program debug handling */
static void DebugProcessing(char* pLog)
{
    RecordRunningLog(pLog);
}

/* Program warning handling */
static void WarningProcessing(char* pLog, char* pInfo)
{
    RecordRunningLog(pLog);
    printf("WARNING:%s\n", pInfo);
}

/* Program error handling */
static void ErrorProcessing(char* pLog, char* pInfo)
{
    RecordRunningLog(pLog);
    printf("Error:%s\n", pInfo);

    PROGRAMEND();
}

/* Log handler entry */
void LogProcessingEntrance(char* pFileName, 
        int iLineNum, int iLevel, char* pFmt, ...)
{
    char       cLogMessage[SIZE_1K*4];
    char       cInfoMessage[SIZE_1K*4];
    va_list    vaArgPtr;

    va_start(vaArgPtr, pFmt);
    vsprintf(cInfoMessage, pFmt, vaArgPtr);
    va_end(vaArgPtr);

    sprintf(cLogMessage, "[%11s][%4d][%-24s][====>][%d][%s]\n", 
            (char*)(basename(pFileName)), iLineNum, 
            GetCurrentTime(), iLevel, cInfoMessage);

    switch(iLevel) {
        case ERROR   : ErrorProcessing(cLogMessage, cInfoMessage); break;
        case WARNING : WarningProcessing(cLogMessage, cInfoMessage); break;
        case DEBUG   : DebugProcessing(cLogMessage); break;
        case INFO    : InfoProcessing(cLogMessage, cInfoMessage); break;
        default      : break;
    }
}

