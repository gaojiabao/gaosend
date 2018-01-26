#ifndef __FLOW_H__
#define __FLOW_H__

void StreamStorageInit();
void StreamStorage(const char*, _tcphdr*, int);
int JudgePerfectStream(const char*);
void DisplayStreamStorage();
void BuildFMT(stPktStrc);

#endif
