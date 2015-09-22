#ifndef __SEND_H__
#define __SEND_H__

void SendModeInitialization(char*);
void SendPacketProcess(char* packet,int pkt_len);
void CloseSendConnect();

#endif
