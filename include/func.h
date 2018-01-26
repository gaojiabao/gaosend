#ifndef __FUNC_H__
#define __FUNC_H__

#include    "packet.h"

// Functions
void  BuildPacket();
void  SplitPacket(); 
void  DuplicatePacket();
void  MergePacket(int, char**); 
void  SwitchPcapFormat();  
void  ReplayPacket();
int   DeepPacketInspection();
void  SuperManUser();
void  ModifyPacket();
void  StatisticPacket();
void  ExtractPacket();

// Parse file name list
char* ParseReadList(char* pCmd);

// Rules
void RulesGenerationEntrance(stPktStrc, int);

// Socket
void SendPacketProcess(char* , int);
void CloseSendConnect();

// Authority
void CertificationAuthority();

#endif

