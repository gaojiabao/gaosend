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

#include    "runlog.h"
#include    "default.h"

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

