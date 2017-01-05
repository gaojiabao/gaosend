/*
 *  Author: Mr.Gao
 *
 *  Function:deal with socket connect.
 *
 */

#include    <stdio.h>
#include    <string.h>
#include    <arpa/inet.h>
#include    <linux/if.h>
#include    <sys/ioctl.h>
#include    <linux/if_ether.h>
#include    <netpacket/packet.h>
#include    <unistd.h>
#include    <fcntl.h>

#include    "runlog.h"
#include    "default.h"
#include    "packet.h"
#include    "storage.h"
#include    "common.h"

/* global variable*/
static    int            iSockFd;

/* network struct */
struct    ifreq             ifr;
struct    sockaddr_ll    sockAddr;

/* create socket connection */
void SendModeInitialization(char* interface)
{
    /* get a socket fd */
    if ((iSockFd=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        LOGRECORD(ERROR, "get iSockFd error! iSockFd:%d", iSockFd);
    }

    /* set interface interface */
    bzero(&ifr, sizeof(ifr));
    strcpy(ifr.ifr_name, interface);
    ioctl(iSockFd, SIOCGIFINDEX, &ifr);

    /* set socket */
    bzero(&sockAddr, sizeof(sockAddr));
    sockAddr.sll_family=PF_PACKET;
    sockAddr.sll_protocol=htons(ETH_P_ALL);
    sockAddr.sll_ifindex=ifr.ifr_ifindex;
    
    /* bind socket interface */
    if (bind(iSockFd, (struct sockaddr *)&sockAddr, \
        sizeof(sockAddr)) < 0) {
        LOGRECORD(ERROR, "bind socket error");
    }
}

/* send data to interface */
void SendPacketProcess(char* packet,int len)
{
    //DisplayPacketData(packet, len);
    if ((sendto(iSockFd, (const void*)packet, len, 0, \
        (struct sockaddr*)&sockAddr, sizeof(sockAddr)))<0) {
        LOGRECORD(ERROR, "send packet error");
    }
}

/* close socket connection */
void CloseSendConnect()
{
    close(iSockFd);
    LOGRECORD(DEBUG, "Send packets finished");
}

/* send packet directly */
void SendProcess()
{
    char packet[2000];
    int  iFdRead = 0; 
    extern _pcaphdr*    pPcapHdr;
    extern _pkthdr*     pPktHdr;

    pPcapHdr    = (_pcaphdr*) packet;
    pPktHdr     = (_pkthdr*) packet;
    
    memset(packet, 0 , sizeof(packet));
    if ((iFdRead = open(GetcValue("readfile"), O_RDWR)) < 0) {
        LOGRECORD(ERROR, "open pcap file error");
    }
    if (read(iFdRead, packet, PCAPHDRLEN) < 0) {
        LOGRECORD(ERROR, "read pcaphdr error");
    }
    if (htonl(pPcapHdr->magic) != 0xd4c3b2a1) {
        LOGRECORD(ERROR, "file paratarn error");
    }

    while(read(iFdRead, packet, PKTHDRLEN) > 1 ) {
        if (read(iFdRead, packet+PKTHDRLEN, pPktHdr->len) < 0) {
            LOGRECORD(ERROR, "read packethdr error");
        }
        SendPacketProcess(packet+PKTHDRLEN, pPktHdr->len);
    }

    close(iFdRead);
}

/* send packet entrance*/
void ReplayPacket()
{
    unsigned int iCounter = GetiValue("count");
    unsigned int iSum = iCounter;
    SendModeInitialization(GetcValue("interface"));
    if (iCounter <= 0) {
        while (1 == 1) {
            SendProcess();
        }
    } else {
        while (iCounter--) {
            SendProcess();
            ProgramProgress((iSum - iCounter), iSum);
        }
        printf("\n");
    }
    CloseSendConnect();
}

