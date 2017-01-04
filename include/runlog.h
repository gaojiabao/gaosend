#ifndef __RUNLOG_H__
#define __RUNLOG_H__

enum {
    ERROR,
    WARNING,
    DEBUG,
    INFO
};

void LogProcessingEntrance(char* , int , int , char* ,...);

#define LOGRECORD(level, msg...) \
    LogProcessingEntrance(__FILE__, __LINE__, level, msg)
#define PROGRAMSTART()  \
    LOGRECORD(DEBUG, "========Program Start========")
#define PROGRAMEND() \
    LOGRECORD(DEBUG, "=========Program End========="); exit(0);

#endif

