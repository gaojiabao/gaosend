#ifndef __FUNC_H__
#define __FUNC_H__

#include    "packet.h"

void BuildPacket();
void SplitPacket(); 
void DuplicatePacket();
void MergePacket(int, char**); 
void SwitchPcapFormat();  
void ReplayPacket();
void DeepPacketInspection();
void SuperManUser();
char* ParseReadList(char* pCmd);

// Rules
void RulesGenerationEntrance(stPktStrc, int);

// Socket
void SendPacketProcess(char* , int);
void CloseSendConnect();

// Authority
void CertificationAuthority();

#endif

