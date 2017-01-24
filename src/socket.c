/*
 *  Author: Mr.Gao
 *
 *  Function:deal with socket connect.
 *
 */

#include    <unistd.h>
#include    <string.h>
#include    <sys/ioctl.h>
#include    <linux/if_ether.h>
#include    <netpacket/packet.h>
#include    "runlog.h"
#include    "common.h"
#include    "storage.h"


/* Global variable*/
static int iSockFd;

/* Network struct */
struct ifreq  ifr;
struct sockaddr_ll sockAddr;

/* Create socket connection */
void SendModeInitialization(char* interface)
{
    if ((iSockFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        LOGRECORD(ERROR, "Sock descriptor acquisition failed[%d]", iSockFd);
    }

    // Set interface
    bzero(&ifr, sizeof(ifr));
    strcpy(ifr.ifr_name, interface);
    ioctl(iSockFd, SIOCGIFINDEX, &ifr);

    // Set socket protocol
    bzero(&sockAddr, sizeof(sockAddr));
    sockAddr.sll_family=PF_PACKET;
    sockAddr.sll_protocol=htons(ETH_P_ALL);
    sockAddr.sll_ifindex=ifr.ifr_ifindex;
    
    // Bind socket interface
    if (bind(iSockFd, (struct sockaddr *)&sockAddr, \
        sizeof(sockAddr)) < 0) {
        LOGRECORD(ERROR, "Socket bind failed");
    }
}

/* Send data to interface */
void SendPacketProcess(char* packet,int len)
{
    if (GetiValue("debug") == 1) {
        DisplayPacketData(packet, len);
    }

    if ((sendto(iSockFd, (const void*)packet, len, 0, \
        (struct sockaddr*)&sockAddr, sizeof(sockAddr)))<0) {
        LOGRECORD(ERROR, "Packet send failed");
    }
}

/* Close socket connection */
void CloseSendConnect()
{
    close(iSockFd);
    LOGRECORD(DEBUG, "The packet has been sent");
}

/* Send packet directly */
void SendProcess()
{
    char cPacketBuf[SIZE_1K*2];
    static _pcaphdr* pPcapHdr = NULL;
    static _pkthdr*  pPktHdr = NULL;

    pPcapHdr = (_pcaphdr*) cPacketBuf;
    pPktHdr  = (_pkthdr*) cPacketBuf;
    
    int  iReadFd = OpenReadFile(GetcValue("read")); 
    memset(cPacketBuf, 0 , sizeof(cPacketBuf));

    if (read(iReadFd, cPacketBuf, PCAPHDRLEN) < 0) {
        LOGRECORD(ERROR, "Pcap header read failed");
    }
    if (htonl(pPcapHdr->magic) != 0xd4c3b2a1) {
        LOGRECORD(ERROR, "File format is not recognized");
    }

    while(read(iReadFd, cPacketBuf, PKTHDRLEN) > 1 ) {
        if (read(iReadFd, cPacketBuf+PKTHDRLEN, pPktHdr->len) < 0) {
            LOGRECORD(ERROR, "Packet read failed");
        }
        SendPacketProcess(cPacketBuf+PKTHDRLEN, pPktHdr->len);
    }

    close(iReadFd);
}

/* Send packet entrance*/
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
        LOGRECORD(INFO, NULL);
    }

    CloseSendConnect();
}

