/*******************************************************
 *
 *  Author        : Mr.Gao
 *  Email         : 729272771@qq.com
 *  Filename      : socket.c
 *  Last modified : 2017-04-25 14:12
 *  Description   : Send packets 
 *
 * *****************************************************/


#include    <unistd.h>
#include    <string.h>
#include    <sys/ioctl.h>
#include    <linux/if_ether.h>
#include    <netpacket/packet.h>
#include    "runlog.h"
#include    "common.h"
#include    "storage.h"

stPktStrc GetPktStrc();

/* Global variable*/
static int iSockFd = -1;

/* Network struct */
struct ifreq  ifr;
struct sockaddr_ll sockAddr;

void DeepPacketInspection();

/* Create socket connection */
void SendModeInitialization()
{
    char* pInterface = GetStr("interface");
    if (pInterface == NULL) {
        LOGRECORD(ERROR, "Interface input error");
    }

    if ((iSockFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        LOGRECORD(ERROR, "Socket descriptor acquisition failed[%d]", iSockFd);
    }

    // Set interface
    bzero(&ifr, sizeof(ifr));
    strcpy(ifr.ifr_name, pInterface);
    if (ioctl(iSockFd, SIOCGIFINDEX, &ifr) < 0) {
        LOGRECORD(ERROR, "Interface [%s] is not exist", pInterface);
    }

    // Set socket protocol
    bzero(&sockAddr, sizeof(sockAddr));
    sockAddr.sll_family=PF_PACKET;
    sockAddr.sll_protocol=htons(ETH_P_ALL);
    sockAddr.sll_ifindex=ifr.ifr_ifindex;

    // Bind socket interface
    if (bind(iSockFd, (struct sockaddr *)&sockAddr, sizeof(sockAddr)) < 0) {
        LOGRECORD(ERROR, "Socket bind failed");
    }
}

/* Send data to interface */
void SendPacketProcess(char* pPacket,int iLength)
{
    int iIntervalTime = GetNum("interval") * 1000;
    static int iCount = 1;

    if (pPacket == NULL || iLength < 0) {
        LOGRECORD(ERROR, "Packet data is NULL");
    }

    if (iSockFd < 0) {
        SendModeInitialization();
    } else {
        if ((sendto(iSockFd, (const void*)pPacket, iLength, 0,
                        (struct sockaddr*)&sockAddr, sizeof(sockAddr))) < 0) {
            LOGRECORD(ERROR, "Packet send failed");
        }
    }

    if (GetNum("debug")) {
        LOGRECORD(INFO, "NO.%d", iCount ++);
        DisplayPacketData(pPacket, iLength);
    }

    usleep(iIntervalTime);
}

/* Close socket connection */
void CloseSendConnect()
{
    close(iSockFd);
    LOGRECORD(DEBUG, "The packet has been sent");
}

/* Send packet entrance*/
void ReplayPacket()
{
    unsigned int iCounter = GetNum("count");
    unsigned int iSum = iCounter;

    if (iCounter == 0) { // Always send
        while (1 == 1) {
            DeepPacketInspection();
            stPktStrc stPkt = GetPktStrc();
            SendPacketProcess(stPkt.pPacket + PCAP_HDR_LEN, stPkt.pPktHdr->len);
        }
    } else if (iCounter > 0) {
        while (iCounter--) {
            DeepPacketInspection();
            stPktStrc stPkt = GetPktStrc();
            SendPacketProcess(stPkt.pPacket , stPkt.pPktHdr->len);
            ProgramProgress((iSum - iCounter), iSum);
        }
    } else {
        LOGRECORD(DEBUG, "Count input invalid");
    }

    CloseSendConnect();
}

