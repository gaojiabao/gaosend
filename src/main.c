#include    <stdlib.h>
#include    <getopt.h>
#include    "auth.h"
#include    "storage.h"
#include    "runlog.h"
#include    "default.h"
#include    <string.h>


void BuildPacket();
void SplitPacket(); 
void DuplicatePacket();
void MergePacket(int, char**); 
void SwitchPcapFormat();  
void ReplayPacket();
void DeepPacketInspection();
char* ParseReadList(char* pCmd);

/* Command line parameter control table */
struct option LongOptions[] = {
    {.name = "smac",      .has_arg = optional_argument, .val = 'a'}, 
    {.name = "dmac",      .has_arg = optional_argument, .val = 'b'}, 
    {.name = "sip",       .has_arg = optional_argument, .val = 's'}, 
    {.name = "dip",       .has_arg = optional_argument, .val = 'd'}, 
    {.name = "sport",     .has_arg = optional_argument, .val = 'P'}, 
    {.name = "dport",     .has_arg = optional_argument, .val = 'Q'}, 
    {.name = "vlan",     .has_arg = optional_argument, .val = 'V'}, 
    {.name = "qinq",     .has_arg = optional_argument, .val = 'W'}, 
    {.name = "protocol",  .has_arg = optional_argument, .val = 'p'}, 
    {.name = "len",       .has_arg = optional_argument, .val = 'l'}, 
    {.name = "url",       .has_arg = optional_argument, .val = 'u'}, 
    {.name = "interval",  .has_arg = optional_argument, .val = 'i'}, 
    {.name = "count",     .has_arg = optional_argument, .val = 'c'}, 
    {.name = "read",      .has_arg = optional_argument, .val = 'r'}, 
    {.name = "save",      .has_arg = optional_argument, .val = 'w'}, 
    {.name = "interface", .has_arg = required_argument, .val = 'I'}, 
    {.name = "string",    .has_arg = optional_argument, .val = 'S'}, 
    {.name = "rulelen",   .has_arg = optional_argument, .val = 'y'}, 
    {.name = "offset",    .has_arg = optional_argument, .val = 'O'}, 
    {.name = "rule",      .has_arg = required_argument, .val = 'Z'}, 
    {.name = "tcp-flag",  .has_arg = required_argument, .val = 'e'}, 
    {.name = "tcp-seq",   .has_arg = required_argument, .val = 'j'}, 
    {.name = "tcp-ack",   .has_arg = required_argument, .val = 'k'}, 
    {.name = "tcp-hdrlen",.has_arg = required_argument, .val = 'q'}, 
    {.name = "flow",      .has_arg = no_argument,       .val = 'F'}, 
    {.name = "debug",     .has_arg = no_argument,       .val = 'g'}, 
    {.name = "build",     .has_arg = no_argument,       .val = 'B'}, 
    {.name = "replay",    .has_arg = no_argument,       .val = 'R'}, 
    {.name = "duplicate", .has_arg = no_argument,       .val = 'D'}, 
    {.name = "devide",    .has_arg = no_argument,       .val = 'C'}, 
    {.name = "merge",     .has_arg = no_argument,       .val = 'm'}, 
    {.name = "statistic", .has_arg = no_argument,       .val = 'A'}, 
    {.name = "modify",    .has_arg = no_argument,       .val = 'M'}, 
    {.name = "switch",    .has_arg = no_argument,       .val = 'f'}, 
    {.name = "version",   .has_arg = no_argument,       .val = 'v'}, 
    {.name = "help",      .has_arg = no_argument,       .val = 'h'}, 
    {.name = "superman",  .has_arg = no_argument,       .val = 'X'}, 
    {NULL}, 
};

/* User help manual */
void UsageOfProgram() 
{
    LOGRECORD(INFO, \
        "Usage: gaosend [args ...]\n"
        "PACKET ARGS\n" 
        "\t--smac       -a   Source mac  [ fixed | random | increase ]\n"
        "\t--sip        -s   Source ip   [ fixed | random | increase ]\n"
        "\t--sport      -P   Source port [ fixed | random | increase ]\n"
        "\t--dmac       -b   Destation mac  [ fixed | random | increase ]\n"
        "\t--dip        -d   Destation ip   [ fixed | random | increase ]\n"
        "\t--dport      -Q   Destation port [ fixed | random | increase ]\n"
        "\t--protocol   -p   Protocol [ ip | arp | udp | tcp | icmp | random | HTTP-GET | HTTP-POST | DNS ]\n"
        "\t--vlan       -V   Vlan tag [ fixed | random | increase ]\n"
        "\t--qinq       -W   QinQ vlan tag [ fixed | random | increase ]\n"
        "\t--offset     -O   String offset in data part\n"
        "\t--url        -u   URL in Http GET or Http POST\n"
        "\t--length     -l   Packet length  [ fixed | increace | random ]\n"
        "\t--string     -S   String in data part\n"
        "\t--rulelen    -y   String length of rule\n"
        "FUNCTION ARGS\n"
        "\t--build      -B   Build packet with send or write mode\n"
        "\t--replay     -R   Replay packet, use with -r -I and -c\n"
        "\t--duplicate  -D   Duplicate N times into original pcap-file, use with -r and -c\n"
        "\t--devide     -C   Devide the pcap file to single pcap file, use with -r\n"
        "\t--merge      -m   Merge the pcap files into frist pcap file, use with -r and -w\n"
        "\t--statistic  -A   Statistic informations, use with -r\n"
        "\t--modify     -M   Modify packet, use with -r and other needed parameters\n"
        "\t--format     -f   Switch packet format to *.pcap, use with -r and -w\n"
        "OTHER ARGS\n"
        "\t--read       -r   Read packet from the  pcap file < filename >\n"
        "\t--save       -w   Save packet into a pcap file < filename >\n"
        "\t--flowcheck  -F   Turn on flow check switch, only use with -A\n"
        "\t--tcp-flag   -e   TCP flag bit\n"
        "\t--tcp-seq    -j   TCP sequence number\n"
        "\t--tcp-ack    -k   TCP acknowledge number\n"
        "\t--ruletype   -Z   Rule type [ aclnmask | aclex | mac_table ]\n"
        "\t--interval   -i   Interval time\n"
        "\t--interface  -I   Interface number\n"
        "\t--count      -c   Packets number\n"
        "\t--version    -v   Program version\n"
        "\t--help       -h   Help informations\n"
    );

    LOGRECORD(DEBUG, "Query user manual finished");
}

/* Software version information */
void VersionOfProgram()
{
    LOGRECORD(INFO, "Author  : GaoJiabao\n" 
            "E-mail  : 729272771@qq.com\n"
            "Version : %s-%s-%s",
            __DATE__, __TIME__, VERSION);
    LOGRECORD(DEBUG, "Query software version finished");
}

/* command line parameter storage container initialization */
void ParametersInit()
{
    CreateStorage();
    InsertNode("smac", SMAC, -1, 0);
    InsertNode("dmac", DMAC, -1, 0);
    InsertNode("sip", SIP, -1, 0);
    InsertNode("dip", DIP, -1, 0);
    InsertNode("sport", NULL, SPORT, 0);
    InsertNode("dport", NULL, DPORT, 0);
    InsertNode("tcp-seq", NULL, 1, 0);
    InsertNode("tcp-ack", NULL, 0, 0);
    InsertNode("tcp-flag", NULL, 16, 0);
    InsertNode("tcp-hdrlen", NULL, 20, 0);
    InsertNode("dport", NULL, DPORT, 0);
    InsertNode("vlannum", NULL, 0, 0);
    InsertNode("l3pro", "IPv4", -1, 0);
    InsertNode("l4pro", "UDP", -1, 0);
    InsertNode("offset", NULL, 0, 0);
    InsertNode("debug", NULL, 0, 0);
    InsertNode("flow", NULL, 0, 0);
    InsertNode("exec", NULL, 0, 0); // 0:send,1:save
    InsertNode("interface", INTERFACE, -1, 0);
    InsertNode("pktlen", NULL, PKTLEN, 0);
    InsertNode("count", NULL, COUNT, 0);
    InsertNode("interval", NULL, INTERVAL, 0);
    InsertNode("entrance", NULL, 99, 0);
    InsertNode("string", NULL, -1, 1);
}

/* Analysis of command line parameters */
void TerminalParametersAnalyse(int argc, char *argv[])
{
    char    cCmdInput;
    // Residual parameter: notxz EGHJKLNTUY
    char*   pParaOption = "fBFgDCmAMvhRX"
                "a:b:s:d:P:Q:V:W:p:l:u:i:c:r:w:I:S:y:O:Z:e:j:k:q:";

    int     iCounter = 0;
    char    cCmdBuf[1024];

    // Save command line input
    memset(cCmdBuf, 0 , sizeof(cCmdBuf));
    for (; iCounter<argc; iCounter++) {
        strcat(cCmdBuf, argv[iCounter]);
        strcat(cCmdBuf, " ");
    }

    // Storage container initialization
    ParametersInit();

    while((cCmdInput = getopt_long(argc, argv, pParaOption, LongOptions, NULL)) != -1)
    {
        switch(cCmdInput) 
        {
            case 'a': StorageInput("smac", optarg, 'c'); break;
            case 'b': StorageInput("dmac", optarg, 'c'); break;
            case 's': StorageInput("sip", optarg, 'c'); break;
            case 'd': StorageInput("dip", optarg, 'c'); break;
            case 'P': StorageInput("sport", optarg, 'i'); break;
            case 'Q': StorageInput("dport", optarg, 'i'); break;
            case 'V': StorageInput("vlan", optarg, 'i'); 
                      StorageInput("vlannum", "1", 'i'); break;
            case 'W': StorageInput("qinq", optarg, 'i'); 
                      StorageInput("vlannum", "2", 'i'); break;
            case 'p': StorageInput("protocol", optarg, 'c'); break;
            case 'l': StorageInput("pktlen", optarg, 'i'); break;
            case 'u': StorageInput("url", optarg, 'c'); break;
            case 'i': StorageInput("interval", optarg, 'i'); break;
            case 'c': StorageInput("count", optarg, 'i'); break;
            case 'r': StorageInput("read", optarg, 'c'); 
                      StorageInput("filelist", ParseReadList(cCmdBuf), 'c'); break; 
            case 'w': StorageInput("save", optarg, 'c'); 
                      StorageInput("exec", "1", 'i'); break;
            case 'I': StorageInput("interface", optarg, 'c'); break;
            case 'S': StorageInput("string", optarg, 'c'); break;
            case 'y': StorageInput("rulelen", optarg, 'c'); break;
            case 'O': StorageInput("offset", optarg, 'i'); break;
            case 'Z': StorageInput("rule", optarg, 'c'); break;
            case 'F': StorageInput("flow", "1", 'i'); break;
            case 'e': StorageInput("tcp-flag", optarg, 'i'); break;
            case 'j': StorageInput("tcp-seq", optarg, 'i'); break;
            case 'k': StorageInput("tcp-ack", optarg, 'i'); break;
            case 'q': StorageInput("tcp-hdrlen", optarg, 'i'); break;
            case 'g': StorageInput("debug", "1", 'i'); break;  
            case 'B': StorageInput("entrance", "101", 'i'); break; 
            case 'D': StorageInput("entrance", "102", 'i'); break; 
            case 'C': StorageInput("entrance", "103", 'i'); break; 
            case 'm': StorageInput("entrance", "104", 'i'); break; 
            case 'A': StorageInput("entrance", "105", 'i'); break; 
            case 'M': StorageInput("entrance", "106", 'i'); break; 
            case 'v': StorageInput("entrance", "107", 'i'); break; 
            case 'h': StorageInput("entrance", "108", 'i'); break; 
            case 'f': StorageInput("entrance", "109", 'i'); break; 
            case 'R': StorageInput("entrance", "110", 'i'); break; 
            case 'X': StorageInput("entrance", "111", 'i'); break; 
            default : LOGRECORD(ERROR, "Without this parameter '%c'", cCmdInput); 
        } // end of switch 
    } // end of while for parameter analysis

    
    LOGRECORD(DEBUG, "Terminal parameters analyse finished");
}

/* Main program entry */
int main(int argc, char* argv[])
{
    PROGRAMSTART();

    // Get command args from terminal 
    TerminalParametersAnalyse(argc, argv);

    // User access authentication 
    CertificationAuthority(argv);

    // Functional program entry
    switch(GetiValue("entrance"))
    {
        case 101: BuildPacket(); break;
        case 102: DuplicatePacket();break; 
        case 103: SplitPacket(); break; 
        case 104: MergePacket(argc, argv); break; 
        case 105: 
        case 106: DeepPacketInspection(); break; 
        case 107: VersionOfProgram (); break; 
        case 108: UsageOfProgram (); break; 
        case 109: SwitchPcapFormat(); break; 
        case 110: ReplayPacket(); break; 
        default : BuildPacket(); break;
    }

    PROGRAMEND();

    return 0;
}

