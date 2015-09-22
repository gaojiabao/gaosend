#include	<stdio.h>
#include    <getopt.h>

#include	"auth.h"
#include	"list_single.h"
#include	"default.h"

struct option original_opts[] = {
    {.name = "smac",      .has_arg = optional_argument, .val = 'a'}, 
    {.name = "dmac",      .has_arg = optional_argument, .val = 'b'}, 
    {.name = "sip",       .has_arg = optional_argument, .val = 's'}, 
    {.name = "dip",       .has_arg = optional_argument, .val = 'd'}, 
    {.name = "sport",     .has_arg = optional_argument, .val = 'P'}, 
    {.name = "dport",     .has_arg = optional_argument, .val = 'Q'}, 
    {.name = "len",       .has_arg = optional_argument, .val = 'l'}, 
    {.name = "l3pro",     .has_arg = optional_argument, .val = 'q'}, 
    {.name = "l4pro",     .has_arg = optional_argument, .val = 'p'}, 
    {.name = "l7pro",     .has_arg = optional_argument, .val = 'H'}, 
    {.name = "vlan1",     .has_arg = optional_argument, .val = 'V'}, 
    {.name = "vlan2",     .has_arg = optional_argument, .val = 'W'}, 
    {.name = "url",       .has_arg = optional_argument, .val = 'u'}, 
    {.name = "interval",  .has_arg = optional_argument, .val = 'i'}, 
    {.name = "counter",   .has_arg = optional_argument, .val = 'c'}, 
    {.name = "filename",  .has_arg = optional_argument, .val = 'w'}, 
    {.name = "duplicate", .has_arg = optional_argument, .val = 'D'}, 
    {.name = "devide",    .has_arg = required_argument, .val = 'C'}, 
    {.name = "merge",     .has_arg = required_argument, .val = 'm'}, 
    {.name = "interface", .has_arg = required_argument, .val = 'I'}, 
    {.name = "statistic", .has_arg = required_argument, .val = 'A'}, 
    {.name = "modify",    .has_arg = required_argument, .val = 'M'}, 
    {.name = "string",    .has_arg = optional_argument, .val = 'S'}, 
    {.name = "strlen",    .has_arg = optional_argument, .val = 'y'}, 
    {.name = "offset",    .has_arg = optional_argument, .val = 'O'}, 
    {.name = "rule",      .has_arg = required_argument, .val = 'Z'}, 
    {.name = "version",   .has_arg = no_argument,       .val = 'v'}, 
    {.name = "help",      .has_arg = no_argument,       .val = 'h'}, 
    {.name = "debug",     .has_arg = no_argument,       .val = 'g'}, 
    {NULL}, 
};

void ParametersInit()
{
	create();
	insertion("smac", SMAC, 0);
	insertion("dmac", DMAC, 0);
	insertion("sip", SIP, 0);
	insertion("dip", DIP, 0);
	/*
	insertion("sport", SPORT, 0);
	insertion("dport", DPORT, 0);
	insertion("vlan1", VLAN1, 0);
	insertion("vlan2", VLAN2, 0);
	*/
	insertion("interface", INTERFACE, 0);
	insertion("l3pro", "IPv4", 0);
	insertion("interval", INTERVAL, 0);
	insertion("entrance", "100", 0);
	insertion("vlnum", "0", 0);

}

/* get program args from terminal */
void TerminalParametersAnalyse(int argc, char *argv[])
{
    char    cmd;
    char    *option = "x:a:b:s:d:P:Q:l:p:q:H:V:W:u: \
                f:i:c:n:w:C:m:D:I:S:y:O:Z:A:M:Xvhg0";

	ParametersInit();

    while ((cmd = getopt_long(argc, argv, option, original_opts, NULL)) != -1)
    {
        switch (cmd) 
        {
            case 'a': Storage("smac", optarg); break;
            case 'b': Storage("dmac", optarg); break;
            case 's': Storage("sip", optarg); break;
            case 'd': Storage("dip", optarg); break;
            case 'P': Storage("sport", optarg); break;
            case 'Q': Storage("dport", optarg); break;
            case 'V': Storage("vlan1", optarg); break;
            case 'W': Storage("vlan2", optarg); break;
            case 'q': Storage("l3pro", optarg); break;
            case 'p': Storage("l4pro", optarg); break;
            case 'H': Storage("l7pro", optarg); break;
            case 'l': Storage("pktlen", optarg); break;
            case 'u': Storage("url", optarg); break;
            case 'i': Storage("interval", optarg); break;
            case 'c': Storage("counter", optarg); break;
            case 'w': Storage("pcapfile", optarg); iWriteMode++; break;
            case 'I': Storage("interface", optarg); break;
            case 'S': Storage("string", optarg); break;
            case 'y': Storage("rulelen", optarg); break;
            case 'O': Storage("offset", optarg); break;
            case 'Z': Storage("rule", optarg); break;
            case 'x': Storage("entrance", "101");break;
            case 'D': Storage("entrance", "102");break;
            case 'C': Storage("entrance", "103");break;
            case 'm': Storage("entrance", "104");break;
            case 'A': Storage("entrance", "105");break;
            case 'M': Storage("entrance", "106");break;
            case 'v': Storage("entrance", "107");break;
            case 'h': Storage("entrance", "108");break;
            case 'g': Storage("entrance", "109");break; 
            case 'X': Storage("entrance", "110");break;
            default : LOGRECORD(ERROR, "Parameters analyse error");
        }// end of switch
    }// end of while

	TerminalParametersInitialization();
    LOGRECORD(DEBUG, "Terminal parameters analyse finished");
}

int main(int argc, char* argv[])
{
    PROGRAMSTART();

    /* judge authority */
    CertificationAuthority(argv);

    /* get command args from terminal */
    TerminalParametersAnalyse(argc, argv);
	printf("%d\n",atoi(GetValue("entrance")));
	switch(atoi(GetValue("entrance")))
	{
		case 100: BuildPacketEnterance(); break;
		case 107: VersionOfProgram (); break; 
		case 108: UsageOfProgram (); break; 
		case 110: SuperMan(); break; 
	/*
		case 101: chgip6(optarg);break;
		case 102: duplication(optarg, atoi(argv[optind]));break; 
		case 103: devide(optarg); break; 
		case 104: merge(m_option(argc,argv)); break; 
		case 105: PcapFileAnalyse(optarg); break; 
		case 106: ModifyPacketParameters(optarg); break; 
		case 109: DebugModeEntrance(); break; 
	*/
		default: printf("*********here\n");
	}

	display();

    PROGRAMEND();

    return 0;
}

