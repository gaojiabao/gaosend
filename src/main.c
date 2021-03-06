/*******************************************************
 *
 *  Author        : Mr.Gao
 *  Email         : 729272771@qq.com
 *  Filename      : main.c
 *  Last modified : 2017-04-25 14:10
 *  Description   : All program entry
 *
 * *****************************************************/


#include    <stdlib.h>
#include    <getopt.h>
#include    <string.h>
#include    "func.h"
#include    "runlog.h"
#include    "storage.h"
#include    "default.h"
#include    <stdio.h>


/* Command line parameter control table */
struct option LongOptions[] = {
    {.name = "smac",      .has_arg = optional_argument, .val = 'a'}, 
    {.name = "dmac",      .has_arg = optional_argument, .val = 'b'}, 
    {.name = "sip",       .has_arg = optional_argument, .val = 's'}, 
    {.name = "dip",       .has_arg = optional_argument, .val = 'd'}, 
    {.name = "sport",     .has_arg = optional_argument, .val = 'P'}, 
    {.name = "dport",     .has_arg = optional_argument, .val = 'Q'}, 
    {.name = "vlan",      .has_arg = optional_argument, .val = 'V'}, 
    {.name = "qinq",      .has_arg = optional_argument, .val = 'W'}, 
    {.name = "proto",     .has_arg = optional_argument, .val = 'p'}, 
    {.name = "len",       .has_arg = optional_argument, .val = 'l'}, 
    {.name = "url",       .has_arg = optional_argument, .val = 'u'}, 
    {.name = "interval",  .has_arg = optional_argument, .val = 'I'}, 
    {.name = "count",     .has_arg = optional_argument, .val = 'c'}, 
    {.name = "read",      .has_arg = optional_argument, .val = 'r'}, 
    {.name = "save",      .has_arg = optional_argument, .val = 'w'}, 
    {.name = "interface", .has_arg = required_argument, .val = 'i'}, 
    {.name = "string",    .has_arg = optional_argument, .val = 'S'}, 
    {.name = "rulelen",   .has_arg = optional_argument, .val = 'y'}, 
    {.name = "offset",    .has_arg = optional_argument, .val = 'O'}, 
    {.name = "rule",      .has_arg = required_argument, .val = 'Z'}, 
    {.name = "ip-flags",  .has_arg = required_argument, .val = 'x'}, 
    {.name = "ip-offset", .has_arg = required_argument, .val = 'o'}, 
    {.name = "tcp-flag",  .has_arg = required_argument, .val = 'z'}, 
    {.name = "tcp-seq",   .has_arg = required_argument, .val = 'j'}, 
    {.name = "tcp-ack",   .has_arg = required_argument, .val = 'k'}, 
    {.name = "tcp-hdrlen",.has_arg = required_argument, .val = 'q'}, 
    {.name = "express",   .has_arg = required_argument, .val = 'e'}, 
    {.name = "flow",      .has_arg = no_argument,       .val = 'f'}, 
    {.name = "debug",     .has_arg = no_argument,       .val = 'g'}, 
    {.name = "build",     .has_arg = no_argument,       .val = 'B'}, 
    {.name = "replay",    .has_arg = no_argument,       .val = 'R'}, 
    {.name = "dup",       .has_arg = no_argument,       .val = 'D'}, 
    {.name = "devide",    .has_arg = no_argument,       .val = 'C'}, 
    {.name = "merge",     .has_arg = no_argument,       .val = 'm'}, 
    {.name = "statistic", .has_arg = no_argument,       .val = 'A'}, 
    {.name = "modify",    .has_arg = no_argument,       .val = 'M'}, 
    {.name = "switch",    .has_arg = no_argument,       .val = 'F'}, 
    {.name = "version",   .has_arg = no_argument,       .val = 'v'}, 
    {.name = "help",      .has_arg = no_argument,       .val = 'h'}, 
    {.name = "superman",  .has_arg = no_argument,       .val = 'X'}, 
    {.name = "extract",   .has_arg = no_argument,       .val = 'E'}, 
    {NULL}, 
};

/* User help manual */
void UsageOfProgram() 
{
    LOGRECORD(INFO, \
        "Usage: gaosend [args ...]\n"
        "PACKET ARGS\n" 
        "\t-a, --smac         Source MAC address <fixd | rand | incr>\n"
        "\t-b, --dmac         Destation MAC address <fixd | rand | incr>\n"
        "\t-s, --sip          Source IP address  <fixd | rand | incr>\n"
        "\t-d, --dip          Destation IP address  <fixd | rand | incr>\n"
        "\t-P, --sport        Source port <fixd | rand | incr >\n"
        "\t-Q, --dport        Destation port <fixd | rand | incr>\n"
        "\t-V, --vlan         Vlan tag <fixd | rand >\n"
        "\t-W, --qinq         QinQ vlan tag <fixd | rand >\n"
        "\t-p, --proto        Protocol in <arp | icmp | rand | http-get | http-post | dns>\n"
        "\t-l, --length       Packet length  <fixd | incr | rand>\n"
        "\t-S, --string       Content of the text data section\n"
        "\t-O, --offset       The offset of a string in the data portion of a packet\n"
        "\t-u, --url          URL in Http-GET, Http POST or DNS\n"
        "FUNCTION ARGS\n"
        "\t-B, --build        Build packet with send or save mode\n"
        "\t-R, --replay       Replay packet, use with -r and -c\n"
        "\t-D, --dup          Duplicate N times into original pcap-file, use with -r -w and -c\n"
        "\t-C, --devide       Devide the pcap file to single pcap file, use with -r\n"
        "\t-m, --merge        Merge the pcap files into frist pcap file, use with -r and -w\n"
        "\t-A, --statistic    Statistic informations, use with -r and -f\n"
        "\t-M, --modify       Modify packet, use with -r -w and -e\n"
        "\t-F, --format       Switch packet format to *.pcap, use with -r and -w\n"
        "\t-E, --extract      Extracting the specified range package, use with -r -w and -e\n"
        "OTHER ARGS\n"
        "\t-i --interface    Interface number\n"
        "\t-c, --count        Program cycle times\n"
        "\t-r, --read         Read packet from the  pcap file <filename>\n"
        "\t-w, --save         Save packet into a pcap file <filename>\n"
        "\t-I, --interval     Interval time(ms)\n"
        "\t-x, --ip-flags     Set IP fragment flags\n"
        "\t-o, --ip-offset    Set IP fragment offset\n"
        "\t-f, --flowcheck    Turn on flow check switch\n"
        "\t-z, --tcp-flag     Set TCP flag bit\n"
        "\t-j, --tcp-seq      Set TCP sequence number\n"
        "\t-k, --tcp-ack      Set TCP acknowledge number\n"
        "\t-e, --express      Used to find the target packet\n"
        "\t-y, --rulelen      String length of rule\n"
        "\t-Z, --ruletype     Rule type <aclnmask | aclex | mac_table>\n"
        "\t-v, --version      Program version\n"
        "\t-h, --help         Help informations\n"
    );

    LOGRECORD(DEBUG, "Query user manual finished");
}

/* Software version information */
void VersionOfProgram()
{
    LOGRECORD(INFO, "Author  : GaoJiabao\n" 
            "E-mail  : 729272771@qq.com\n"
            "Version : %s.%s", VERSION, COMPILETIME);
    LOGRECORD(DEBUG, "Query software version finished");
}

/* command line parameter storage container initialization */
void ParametersInit()
{
    CreateStorage();
    InsertNode("smac", SMAC, -1, FG_INIT);
    InsertNode("dmac", DMAC, -1, FG_INIT);
    InsertNode("sip", SIP, -1, FG_INIT);
    InsertNode("dip", DIP, -1, FG_INIT);
    InsertNode("sport", NULL, SPORT, FG_INIT);
    InsertNode("dport", NULL, DPORT, FG_INIT);
    InsertNode("tcp-seq", NULL, 1, FG_INIT);
    InsertNode("tcp-ack", NULL, 0, FG_INIT);
    InsertNode("tcp-flag", NULL, 16, FG_INIT);
    InsertNode("tcp-hdrlen", NULL, 20, FG_INIT);
    InsertNode("vlannum", NULL, 0, FG_INIT);
    InsertNode("ip_flags", NULL, 0, FG_INIT);
    InsertNode("ip_offset", NULL, 0, FG_INIT);
    InsertNode("l3pro", "IPv4", -1, FG_INIT);
    InsertNode("l4pro", "UDP", -1, FG_INIT);
    InsertNode("offset", NULL, OFFSET, FG_INIT);
    InsertNode("debug", NULL, 0, FG_INIT);
    InsertNode("flow", NULL, 0, FG_INIT);
    InsertNode("exec", NULL, 0, FG_INIT); // 0:send,1:save
    InsertNode("interface", INTERFACE, -1, FG_INIT);
    InsertNode("pktlen", NULL, PKTLEN, FG_INIT);
    InsertNode("count", NULL, COUNT, FG_INIT);
    InsertNode("interval", NULL, INTERVAL, FG_INIT);
    InsertNode("entrance", NULL, 99, FG_INIT);
    InsertNode("string", NULL, -1, FG_INIT);
}

/* Analysis of command line parameters */
void TerminalParametersAnalyse(int argc, char *argv[])
{
    char  cCmdInput;
    // Residual parameter: ntz GHJKLNTUY
    char* pParaOption = "fBFgDCmAMvhRXE"
                "a:b:s:d:P:Q:V:W:p:l:u:i:c:r:w:x:I:S:y:o:O:Z:e:j:k:q:z:";

    // Save command line input
    int   iCounter;
    char* pCmdBuf = calloc(argc, 80);
    for (iCounter = 0; iCounter < argc; iCounter ++) {
        strcat(pCmdBuf, argv[iCounter]);
        strcat(pCmdBuf, " ");
    }
    if ( strlen(pCmdBuf) < 1024 * 100) {
        LOGRECORD(DEBUG, "User Input:%s", pCmdBuf);
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
            case 'I': StorageInput("interval", optarg, 'i'); break;
            case 'c': StorageInput("count", optarg, 'i'); break;
            case 'r': StorageInput("read", optarg, 'c'); 
                      StorageInput("filelist", \
                          ParseReadList(pCmdBuf), 'c'); break; 
            case 'w': StorageInput("save", optarg, 'c'); 
                      StorageInput("exec", "1", 'i'); break;
            case 'i': StorageInput("interface", optarg, 'c'); break;
            case 'S': StorageInput("string", optarg, 'c'); break;
            case 'y': StorageInput("rulelen", optarg, 'c'); break;
            case 'x': StorageInput("ip_flags", optarg, 'i'); break;
            case 'o': StorageInput("ip_offset", optarg, 'i'); break;
            case 'O': StorageInput("offset", optarg, 'i'); break;
            case 'Z': StorageInput("rule", optarg, 'c'); break;
            case 'e': StorageInput("express", optarg, 'c'); break;
            case 'f': StorageInput("flow", "1", 'i'); break;
            case 'z': StorageInput("tcp-flag", optarg, 'i'); break;
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
            case 'F': StorageInput("entrance", "109", 'i'); break; 
            case 'R': StorageInput("entrance", "110", 'i'); break; 
            case 'E': StorageInput("entrance", "111", 'i'); break; 
            case 'X': StorageInput("entrance", "112", 'i'); break; 
            default : LOGRECORD(ERROR, "Without this parameter '%c'", cCmdInput); 
        } // end of switch 
    } // end of while for parameter analysis

    
    free(pCmdBuf);
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
    switch(GetNum("entrance")) {
        case 101: BuildPacket(); break;
        case 102: DuplicatePacket();break; 
        case 103: SplitPacket(); break; 
        case 104: MergePacket(argc, argv); break; 
        case 105: StatisticPacket(); break;
        case 106: ModifyPacket(); break;
        case 107: VersionOfProgram(); break; 
        case 108: UsageOfProgram(); break; 
        case 109: SwitchPcapFormat(); break; 
        case 110: ReplayPacket(); break; 
        case 111: ExtractPacket(); break; 
        default : BuildPacket(); break;
    }

    PROGRAMEND();

    return 0;
}

