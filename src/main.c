#include	<stdio.h>
#include	<stdlib.h>
#include    <getopt.h>
#include	"auth.h"
#include	"list.h"
#include	"runlog.h"
#include	"default.h"

void BuildPacket();
void DevidePacket(); 
void ModifyPacket(); 
void DuplicatePacket();
void AnalysePacket(); 
void MergePacket(int, char**); 
void SwitchPcapFormat();  

struct option original_opts[] = {
	{.name = "smac",      .has_arg = optional_argument, .val = 'a'}, 
	{.name = "dmac",      .has_arg = optional_argument, .val = 'b'}, 
	{.name = "sip",       .has_arg = optional_argument, .val = 's'}, 
	{.name = "dip",       .has_arg = optional_argument, .val = 'd'}, 
	{.name = "sport",     .has_arg = optional_argument, .val = 'P'}, 
	{.name = "dport",     .has_arg = optional_argument, .val = 'Q'}, 
	{.name = "vlan1",     .has_arg = optional_argument, .val = 'V'}, 
	{.name = "vlan2",     .has_arg = optional_argument, .val = 'W'}, 
	{.name = "protocol",  .has_arg = optional_argument, .val = 'p'}, 
	{.name = "len",       .has_arg = optional_argument, .val = 'l'}, 
	{.name = "url",       .has_arg = optional_argument, .val = 'u'}, 
	{.name = "interval",  .has_arg = optional_argument, .val = 'i'}, 
	{.name = "count",     .has_arg = optional_argument, .val = 'c'}, 
	{.name = "readfile",  .has_arg = optional_argument, .val = 'r'}, 
	{.name = "savefile",  .has_arg = optional_argument, .val = 'w'}, 
	{.name = "interface", .has_arg = required_argument, .val = 'I'}, 
	{.name = "string",    .has_arg = optional_argument, .val = 'S'}, 
	{.name = "rulelen",   .has_arg = optional_argument, .val = 'y'}, 
	{.name = "offset",    .has_arg = optional_argument, .val = 'O'}, 
	{.name = "rule",      .has_arg = required_argument, .val = 'Z'}, 
	{.name = "debug",     .has_arg = no_argument,       .val = 'g'}, 
	{.name = "chgip6",    .has_arg = no_argument,       .val = 'x'}, 
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

/* help infomation for user */
void UsageOfProgram () 
{
	LOGRECORD(DEBUG, "Query help information start...");

	printf("Usage: gaosend [args ...]\n"
				"PACKET ARGS\n" 
				"\t--smac       -a   Source mac  [ fixed | random | increase ]\n"
				"\t--sip        -s   Source ip   [ fixed | random | increase ]\n"
				"\t--sport      -P   Source port [ fixed | random | increase ]\n"
				"\t--dmac       -b   Destation mac  [ fixed | random | increase ]\n"
				"\t--dip        -d   Destation ip   [ fixed | random | increase ]\n"
				"\t--dport      -Q   Destation port [ fixed | random | increase ]\n"
				"\t--protocol   -p   Protocol [ ip | arp | udp | tcp | icmp | random | HTTP-GET | HTTP-POST | DNS ]\n"
				"\t--vlan1      -V   Vlan1 value [ fixed | random | increase ]\n"
				"\t--vlan2      -W   Vlan2 value [ fixed | random | increase ]\n"
				"\t--offset     -O   String offset in data part\n"
				"\t--url        -u   URL in Http GET or Http POST\n"
				"\t--length     -l   Packet len  [ fixed | increace | random ]\n"
				"\t--string     -S   String in data part\n"
				"\t--rulelen    -y   String length of rule\n"
				"FUNCTION ARGS\n"
				"\t--duplicate  -D   Duplicate N times into original pcap-file, use with -r and -c\n"
				"\t--devide     -C   Devide the pcap file to single pcap file, use with -r\n"
				"\t--merge      -m   Merge the pcap files into frist pcap file, use with -r and -w\n"
				"\t--statistic  -A   Statistic informations, use with -r\n"
				"\t--modify     -M   Modify packet, use with -r and other needed parameters\n"
				"\t--format     -f   Switch packet format to *.pcap, use with -r and -w\n"
				"OTHER ARGS\n"
				"\t--readfile   -r   Read packet from the  pcap file < filename >\n"
				"\t--savefile   -w   Save packet into a pcap file < filename >\n"
				"\t--ruletype   -Z   Rule type [ aclnmask | aclex | mac_table ]\n"
				"\t--interval   -i   Interval time\n"
				"\t--interface  -I   Interface number\n"
				"\t--count      -c   Packets number\n"
				"\t--version    -v   Program version\n"
				"\t--help       -h   Help informations\n"
				);

	LOGRECORD(DEBUG, "Query help information finished...");
}

/* software version */
void VersionOfProgram ()
{
	LOGRECORD(DEBUG, "Query Program Version start...");
	printf ("Author  : GaoJiabao\n" 
				"E-mail  : 729272771@qq.com\n"
				"Version : %s-%s-%s\n",
				__DATE__, __TIME__, VERSION);
	LOGRECORD(DEBUG, "Query Program Version finished...");
}

void ParametersInit()
{
	create();
	insertion("smac", SMAC, -1, 0);
	insertion("dmac", DMAC, -1, 0);
	insertion("sip", SIP, -1, 0);
	insertion("dip", DIP, -1, 0);
	insertion("sport", NULL, SPORT, 0);
	insertion("dport", NULL, DPORT, 0);
	insertion("vlannum", NULL, 0, 0);
	insertion("l3pro", "IPv4", -1, 0);
	insertion("l4pro", "UDP", -1, 0);
	insertion("offset", NULL, 0, 0);
	insertion("debug", NULL, 0, 0);
	insertion("exec", NULL, 0, 0); //0:send,1:save
	insertion("interface", INTERFACE, -1, 0);
	insertion("pktlen", NULL, PKTLEN, 0);
	insertion("count", NULL, COUNTER, 0);
	insertion("interval", NULL, INTERVAL, 0);
	insertion("entrance", NULL, 100, 0);
	insertion("string", NULL, -1, 1);
}

/* get program args from terminal */
void TerminalParametersAnalyse(int argc, char *argv[])
{
	char    cmd;
	char    *option = "a:b:s:d:P:Q:V:W:p:l:u:i:c:r:w:I:S:y:O:Z:fgxDCmAMvhX";

	ParametersInit();

	while((cmd = getopt_long(argc, argv, option, original_opts, NULL)) != -1)
	{
		switch(cmd) 
		{
			case 'a': Storage("smac", optarg, 'c'); break;
			case 'b': Storage("dmac", optarg, 'c'); break;
			case 's': Storage("sip", optarg, 'c'); break;
			case 'd': Storage("dip", optarg, 'c'); break;
			case 'P': Storage("sport", optarg, 'i'); break;
			case 'Q': Storage("dport", optarg, 'i'); break;
			case 'V': Storage("vlan1", optarg, 'i'); 
					  Storage("vlannum", "1", 'i'); break;
			case 'W': Storage("vlan2", optarg, 'i'); 
					  Storage("vlannum", "2", 'i'); break;
			case 'p': Storage("protocol", optarg, 'c'); break;
			case 'l': Storage("pktlen", optarg, 'i'); break;
			case 'u': Storage("url", optarg, 'c'); break;
			case 'i': Storage("interval", optarg, 'i'); break;
			case 'c': Storage("count", optarg, 'i'); break;
			case 'r': Storage("readfile", optarg, 'c');break; 
			case 'w': Storage("savefile", optarg, 'c'); 
					  Storage("exec", "1", 'i'); break;
			case 'I': Storage("interface", optarg, 'c'); break;
			case 'S': Storage("string", optarg, 'c'); break;
			case 'y': Storage("rulelen", optarg, 'c'); break;
			case 'O': Storage("offset", optarg, 'i'); break;
			case 'Z': Storage("rule", optarg, 'c'); break;
			case 'g': Storage("debug", "1", 'i'); break;  
			case 'x': Storage("entrance", "101", 'i'); break; 
			case 'D': Storage("entrance", "102", 'i'); break; 
			case 'C': Storage("entrance", "103", 'i'); break; 
			case 'm': Storage("entrance", "104", 'i'); break; 
			case 'A': Storage("entrance", "105", 'i'); break; 
			case 'M': Storage("entrance", "106", 'i'); break; 
			case 'v': Storage("entrance", "107", 'i'); break; 
			case 'h': Storage("entrance", "108", 'i'); break; 
			case 'X': Storage("entrance", "109", 'i'); break; 
			case 'f': Storage("entrance", "110", 'i'); break; 
			default : LOGRECORD(ERROR, "Parameters analyse error"); 
		}// end of switch
	}// end of while

	LOGRECORD(DEBUG, "Terminal parameters analyse finished");
}

int main(int argc, char* argv[])
{
	PROGRAMSTART();
	UseTimesFunction(+1);

	/* judge authority */
	CertificationAuthority(argv);

	/* get command args from terminal */
	TerminalParametersAnalyse(argc, argv);

	switch(GetiValue("entrance"))
	{
		case 100: BuildPacket(); break;
				  //case 101: chgip6(optarg);break;
		case 102: DuplicatePacket();break; 
		case 103: DevidePacket(); break; 
		case 104: MergePacket(argc, argv); break; 
		case 105: AnalysePacket(); break; 
		case 106: 
#if 0
				  for(;;) {
					  ModifyPacket(); 
				  }
#else 
				  ModifyPacket(); 
#endif
				  break; 
		case 107: VersionOfProgram (); break; 
		case 108: UsageOfProgram (); break; 
		case 109: SuperManUser(); break; 
		case 110: SwitchPcapFormat(); break; 
		default: LOGRECORD(ERROR, "Entrance code error!");
	}

	PROGRAMEND();

	return 0;
}

