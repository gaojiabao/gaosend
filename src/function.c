/*
 *  author   : Mr. Gao
 *
 *  function : This file include some extracted informations 
 *             in a little function and all of them will be
 *             used in whole programs.
 */

#include	"function.h"
#include	"default.h"
#include	"packet.h"
#include	"runlog.h"
#include	<unistd.h>
#include	<string.h>
#include	<sys/time.h>
#include "list_single.h"

int iIpArray[][4] = { 
	{1, 0, 0, 0}, 
	{1, 0, 0, 0} 
};

char cIpAddress[][20] = {"",""};
char cMacAddress[][20] = {
	"00:00:00:00:00:00",
	"00:00:00:00:00:00"
};

char    ram_buf[2000] = {0};
char    url[30];
char    mopt[100];
char	substr[1500];

/* calculate udp, tcp or icmp checksum */
uint16_t GetCheckSum(uint16_t* buf, int len)
{
    unsigned long sum;
    for (sum=0; len>0; len--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}

char ChangeHexToString(int iChoice)
{
    switch(iChoice) {
        case 0:	 return '0';
        case 1:  return '1';
        case 2:  return '2';
        case 3:  return '3';
        case 4:  return '4';
        case 5:  return '5';
        case 6:  return '6';
        case 7:  return '7';
        case 8:  return '8';
        case 9:  return '9';
        case 10: return 'A';
        case 11: return 'B';
        case 12: return 'C';
        case 13: return 'D';
        case 14: return 'E';
        case 15: return 'F';
    }
	return -1;
}

/* generate a host string */
char* GetUrlString()
{
    memset(url,0,sizeof(url));
    strcat(url,"www.");
    strcat(url,GetRandomCharactor(5));
    strcat(url,".com/");
    strcat(url,GetRandomCharactor(6));

    return url;
}

/* get two characters from input string */
char* subs(char *s,int n,int m)
{
    memset(substr,0,sizeof(substr));
    memcpy(substr,&s[n],m);

    return substr;
}

/* get a random number with microsecond */
int GetRandomNumber()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    srandom(tp.tv_usec + tp.tv_sec);

    return random();
}

/* get a random charactor */
char* GetRandomCharactor(int iLength)
{
    int iNum;
    int iRandomNum = 0;

    for(iNum = 0; iNum < iLength; iNum++) {
        iRandomNum = GetRandomNumber() % 200;
        if(((iRandomNum <= 122) && (iRandomNum >= 97)) ||
            ((iRandomNum <= 90) && (iRandomNum >= 65)) ||
            ((iRandomNum <= 57) && (iRandomNum >= 48))) {
            sprintf((char *)ram_buf + iNum, "%c", iRandomNum);
		} else {
            iNum--;
		}
    }

    return ram_buf;
}

/* get a random mac address */
char* GetRandomMacAddress(int iSmacOrDmac)
{
	int iMacLenth;
	iMacLenth = strlen(cMacAddress[iSmacOrDmac]);
	while (iMacLenth != 2) {
		iMacLenth--;
		if (cMacAddress[iSmacOrDmac][iMacLenth] == ':') {
			continue;
		}
		cMacAddress[iSmacOrDmac][iMacLenth] \
			= ChangeHexToString(GetRandomNumber()%15);
	}
	return cMacAddress[iSmacOrDmac];
}

/* get a increase mac address */
char* GetIncreaseMacAddress(int iSmacOrDmac)
{
	int iMacLenth;
	iMacLenth = strlen(cMacAddress[iSmacOrDmac]) - 1;
	while (iMacLenth != -1) {
		if(cMacAddress[iSmacOrDmac][iMacLenth] == '9'){
			cMacAddress[iSmacOrDmac][iMacLenth] = 'a' -1;
		}
		if(cMacAddress[iSmacOrDmac][iMacLenth] == 'f' 
			|| cMacAddress[iSmacOrDmac][iMacLenth] == ':') {
			if(cMacAddress[iSmacOrDmac][iMacLenth] == 'f') {
				cMacAddress[iSmacOrDmac][iMacLenth] = '0';
			}
			iMacLenth--;
		} else {
			cMacAddress[iSmacOrDmac][iMacLenth]++;
			break;
		}
	}
	return cMacAddress[iSmacOrDmac];
}

/* change mac address type from string to sixteen hexadecimal number*/
int mac_type_change (char *str, char *mac)
{
    int i;
	char *s;
	char *e;

    if ((mac == NULL) || (str == NULL)) {
        return -1;
    }

    s = (char *) str;
    for (i = 0; i < 6; ++i) {
        mac[i] = s ? strtoul (s, &e, 16) : 0;
        if (s)
            s = (*e) ? e + 1 : e;
    }
    return 0;
}

/* get a random ip address */
char* GetRandomIpAddress(int iSOrDIp)
{
	sprintf(cIpAddress[iSOrDIp], "%d.%d.%d.%d", 
		GetRandomNumber() % 255 + 1,
		GetRandomNumber() % 256,
		GetRandomNumber() % 256,
		GetRandomNumber() % 255 + 1
	);
	return cIpAddress[iSOrDIp];
}

/* get a increased ip address */
char* GetIncreaseIpAddress(int iSOrDIp)
{
    if (++iIpArray[iSOrDIp][3] > 255) { 
		iIpArray[iSOrDIp][3] = 1;
		iIpArray[iSOrDIp][2]++;
	} else if (iIpArray[iSOrDIp][2] > 255) { 
		iIpArray[iSOrDIp][2] = 0;
		iIpArray[iSOrDIp][1]++;
	} else if (iIpArray[iSOrDIp][1] > 255) { 
		iIpArray[iSOrDIp][1] = 0;
		iIpArray[iSOrDIp][0]++;
	}

    sprintf(cIpAddress[iSOrDIp], "%d.%d.%d.%d",
		iIpArray[iSOrDIp][0],
		iIpArray[iSOrDIp][1],
		iIpArray[iSOrDIp][2],
		iIpArray[iSOrDIp][3]
	);

    return cIpAddress[iSOrDIp];
}

/* get a increased port number */
int GetIncreasePort(int iSOrDPort)
{
	static int siPortArray[] = {0, 0};
	if (siPortArray[iSOrDPort]++ > 65535) {
		siPortArray[iSOrDPort] = 0;
	}
	return siPortArray[iSOrDPort];
}

/* get a random port number */
int GetRandomPort()
{
    return (1 + GetRandomNumber() % (65535 - 1));
}

/* get a random number for packet length */
int GetRandomPacketLength()
{
    return (64 + GetRandomNumber() % (1518 - 64));
}

/* get a increased number for packet length */
int GetIncreasePacketLength()
{
    static int iLength=64;
    if (iLength > 1518) {
	    iLength = 64;
	}

    return iLength++;
}

/* get a random number for vlan id */
int GetRandomVlan()
{
    return (2 + GetRandomNumber() % (4096 - 2));
}

/* get a increased number for vlan id */
int GetIncreaseVlan(int flag)
{
    static int vlan1 = 1;
    static int vlan2 = 1;
    if (!flag) {
        if (vlan1 > 4094) {
            vlan1 = 1;
		}
        return vlan1++;
    }
    if (vlan2 > 4094) {
        vlan2 = 1;
	}

    return vlan2++;
}

/* get a random protocol in udp,tcp and icmp */
uint8_t GetRandomLayer4Pro()
{
    int iRandomNum = random() % 3;
    if(iRandomNum == 0) {
		return UDP;
	} else if (iRandomNum == 1) {
		return TCP;
	} else {
		return ICMPv4;
	}
}

/* return a random protocol */
char* ChangeLayer4HexToString(uint16_t pro)
{
    switch(pro) {
		case ARP:    return "ARP";  
		case VLAN:   return "VLAN";  
		case ICMPv4: return "ICMPv4";  
		case IPv4:   return "IPv4";  
		case UDP:    return "UDP";  
		case TCP:    return "TCP";  
		default:     return "Unknown"; 
    }
}

uint16_t GetHex(char* pro)
{
	uint16_t tmp;
	if(strcmp(pro, "ARP") == 0) {
		tmp = ARP;
	} else if(strcmp(pro, "VLAN") == 0) { 
		tmp = VLAN;
	} else if(strcmp(pro, "IPv4") == 0) { 
		tmp = IPv4;
	} else if(strcmp(pro, "ICMPv4") == 0) {
		tmp = ICMPv4;
	} else if(strcmp(pro, "TCP") == 0) {
		tmp = TCP;
	} else if(strcmp(pro, "UDP") == 0) {
		tmp = UDP;
	}

	return htons(tmp);
}

/* deal with m option */
char* m_option(int argc,char* argv[])
{
    int nvar=1;
    char vbuf[100];

    while(nvar < argc){
        strcat(vbuf, " ");
        strcat(vbuf, argv[nvar]);
        nvar++;
    }

    char* var = strtok(vbuf, "-");
    while(1) {
        var = strtok(NULL, "-");
        if(var[0] == 'm'){
            strcat(mopt,var);
            return mopt;
        }
    }
}

/* to show program process */
void ProgramProcessingSchedule(int iVaribleNum, int iStanderNum)
{
    if(!iStanderNum) {
        return;
    }
	
    if(iStanderNum < 10) {
        if(iVaribleNum == iStanderNum) {
			printf(".....\n");
        }
    } else {
        if(iVaribleNum == (int)(iStanderNum * 0.2) ||
           iVaribleNum == (int)(iStanderNum * 0.4) ||
           iVaribleNum == (int)(iStanderNum * 0.6) ||
           iVaribleNum == (int)(iStanderNum * 0.8)) {
           printf(".");
           fflush(stdout);
        }
        if (iVaribleNum == iStanderNum) {
            printf(".\n");
        }
    }
}

/* to DisplayPacketData a packet */
void DisplayPacketData(char* pcPacket, int iPacketLength)
{
    int iNum;
    for(iNum=0; iNum<iPacketLength; iNum+=2) {
        printf("%02hhx%02hhx ", pcPacket[iNum], pcPacket[iNum+1]);
        if(iNum%16 == 14) {
            printf("\n");
		}
    }
    printf("\n");
}

void UseTimesFunction(int);
/* to duplicate a *.pcap file for N times */
void duplication(char* file, int num)
{
	display();
    int fd, i;

	UseTimesFunction(+1);

    if((fd = open(file, O_RDWR | O_APPEND)) < 0 ) {
		LOGRECORD(ERROR, "Duplication open error");
    }
    int end = lseek(fd, 0, SEEK_END);
    int start = lseek(fd, 24, SEEK_SET);
    int len = end - start;
    char* temp = malloc(len);
    if(read(fd, temp, len) < 0) {
		LOGRECORD(ERROR, "Duplication read error");
    }

    lseek(fd, 0, SEEK_END);
    for (i=1; i<num; i++) {
        if (write(fd, temp, len) < 0) {
			LOGRECORD(ERROR, "Duplication write error");
        }
    }

    free(temp);
    close(fd);

	LOGRECORD(DEBUG, "Duplication finished");
	PROGRAMEND();
}

/* copy function */
void memPcpy(char* dst, int pos, char* src, int len)
{
    int i;
    for(i=0; i<len; i++)
        dst[pos+i] = src[i];
}

/* compare ip */
int compare(unsigned char* src,unsigned char* dst)
{
    int len = sizeof(struct in6_addr), i;
    for (i=0; i<len; i++){
        if (src[8+i] != dst[i])
            return -1 ;
    }
    return 0;
}

/* change ipv6 address */
void chgip6(char* file)
{
    int fdin,fdout;
    char* result = "result.pcap";
    if((fdin = open(file,O_RDWR)) < 0){
        perror("open error");
        exit(0);
    }
    if((fdout = open(result, O_RDWR | O_CREAT, PERM)) < 0){
        perror("open error");
        exit(0);
    }
    char pcapbuf[24];
    if(read(fdin,pcapbuf,24) < 0){
        perror("read pcaphdr error !");
        exit(0);
    }
    if(write(fdout,pcapbuf,24) < 0){
        perror("write error !");
        exit(0);
    }

    int num = 0;
    char pktbuf[16];
    while(read(fdin,pktbuf,16)){
        _pkthdr* pkt_hdr = (_pkthdr*)pktbuf;
        printf("len:%d\n",pkt_hdr->len);
        if(write(fdout,pktbuf,16) < 0){
            perror("write error !");
            exit(0);
        }

        char macbuf[14];
        if(read(fdin,macbuf,14) < 0){
            perror("read pcaphdr error !");
            exit(0);
        }
        if(write(fdout,macbuf,14) < 0){
            perror("write error !");
            exit(0);
        }

        unsigned char ipbuf[40];
        if(read(fdin,ipbuf,40) < 0){
            perror("read pcaphdr error !");
            exit(0);
        }
        unsigned char buf1[sizeof(struct in6_addr)];
        unsigned char buf2[sizeof(struct in6_addr)];
        unsigned char buf1_temp[sizeof(struct in6_addr)];
//      unsigned char buf2_temp[sizeof(struct in6_addr)];

        inet_pton(AF_INET6,"2400:fe00:f000:0601::29",buf1);
        inet_pton(AF_INET6,"2100:fe00:f000:0601::30",buf2);
        unsigned int i;
        //copy
        if(num++ == 0){
            for(i=0;i<sizeof(struct in6_addr);i++){
                buf1_temp[i] = ipbuf[8+i];
            }
            /*
            for(i=0;i<sizeof(struct in6_addr);i++){
                buf2_temp[i] = temp4[24+i];
            }
            */
        }
        //_ip6hdr* ip6_hdr = (_ip6hdr*)ipbuf;
        //matching
        if(compare(ipbuf,buf1_temp)){
            //amend
            for(i=0;i<sizeof(struct in6_addr);i++){
                ipbuf[8+i]=buf1[i];
            }
            for(i=0;i<sizeof(struct in6_addr);i++){
                ipbuf[24+i]=buf2[i];
            }
        
        }else{
            //amend
            for(i=0;i<sizeof(struct in6_addr);i++){
                ipbuf[8+i]=buf2[i];
            }
            for(i=0;i<sizeof(struct in6_addr);i++){
                ipbuf[24+i]=buf1[i];
            }
        
        }

        if(write(fdout,ipbuf,40) < 0){
            perror("write error !");
            exit(0);
        }
        int datalen =  pkt_hdr->len - 14 - 40;
        char databuf[1518];
        if(read(fdin,databuf,datalen) < 0){
            perror("read pcaphdr error !");
            exit(0);
        }
        if(write(fdout,databuf,datalen) < 0){
            perror("write error !");
            exit(0);
        }
    }

    close(fdin);
    close(fdout);
    exit(0);
}

int ProtocolConversion(char* cpProtocol)
{
	if (strcmp(cpProtocol, "ip") == 0) {
		return IPv4;
	} else if (strcmp(cpProtocol, "arp") == 0) {
		return ARP;
	} else if (strcmp(cpProtocol, "vlan") == 0) {
		return VLAN; 
	} else if (strcmp(cpProtocol, "icmp") == 0) {
		return ICMPv4; 
	} else if (strcmp(cpProtocol, "tcp") == 0) {
		return TCP; 
	} else if (strcmp(cpProtocol, "udp") == 0) {
		return UDP; 
	}
	return 0;
}

