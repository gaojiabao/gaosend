#!/usr/bin/env python

import re
import os
import time
import argparse


# Global statistical counter
totle_no = 0
success_no = 0
failed_no = 0
other_no = 0

# Test case list
all_case_list = [
    "gaosend -B -c 100",
    "gaosend -B -a 00:23:76:00:00:ee -c 100 ",
    "gaosend -B -a incr -c 100",
    "gaosend -B -a rand -c 100",
    "gaosend -B -b 00:23:76:00:00:ff -c 100 ",
    "gaosend -B -b incr -c 100",
    "gaosend -B -b rand -c 100",
    "gaosend -B -a 00:23:76:00:00:ee -b 00:23:76:00:00:ff -c 100 ",
    "gaosend -B -a rand -b incr -c 100 ",
    "gaosend -B -a incr -b rand -c 100 ",
    "gaosend -B -a incr -b incr -c 100 ",
    "gaosend -B -a rand -b rand -c 100 ",

    "gaosend -B -s 1.1.1.1 -c 100",
    "gaosend -B -s incr -c 100",
    "gaosend -B -s rand -c 100",
    "gaosend -B -d 2.2.2.2 -c 100",
    "gaosend -B -d incr -c 100",
    "gaosend -B -d rand -c 100",
    "gaosend -B -s 192.168.1.1 -d 192.168.1.2 -c 100",
    "gaosend -B -s 192.168.1.1 -d rand -c 100",
    "gaosend -B -s 192.168.1.1 -d incr -c 100",
    "gaosend -B -s rand -d 192.168.1.2 -c 100",
    "gaosend -B -s incr -d 192.168.1.2 -c 100",
    "gaosend -B -s rand -d incr -c 100",
    "gaosend -B -s incr -d rand -c 100",
    "gaosend -B -s incr -d incr -c 100",
    "gaosend -B -s rand -d rand -c 100",

    "gaosend -B -P 65535 -c 100",
    "gaosend -B -P rand -c 100",
    "gaosend -B -P incr -c 100",
    "gaosend -B -Q 1023 -c 100",
    "gaosend -B -Q rand -c 100",
    "gaosend -B -Q incr -c 100",
    "gaosend -B -P 65535 -Q 1023 -c 100",
    "gaosend -B -P incr -Q rand -c 100",
    "gaosend -B -P rand -Q incr -c 100",
    "gaosend -B -P incr -Q incr -c 100",
    "gaosend -B -P rand -Q rand -c 100",
    "gaosend -B -a 00:23:76:00:00:ee -b 00:23:76:00:00:ff -s 192.168.1.1 -d 192.168.1.2 -c 100",
    "gaosend -B -a rand -b incr -s incr -d rand -P rand -Q incr -c 100",

    "gaosend -B -V 100 -c 100",
    "gaosend -B -V rand -c 100",
    "gaosend -B -W 100 -c 200",
    "gaosend -B -W rand -c 200",
    "gaosend -B -V 100 -W 200  -c 100",
    "gaosend -B -V rand -W 200  -c 100",
    "gaosend -B -V rand -W rand -c 100",
    "gaosend -B -a rand -b incr -s incr -d rand -P rand -Q incr -V rand -c 100 ",
    "gaosend -B -a rand -b incr -s incr -d rand -P rand -Q incr -W rand -c 100 ",
    "gaosend -B -a rand -b incr -s incr -d rand -P rand -Q incr -V rand  -W rand -c 100 ",
    "gaosend -B -a rand -b incr -s incr -d rand -P rand -Q incr -V rand  -W 200 -c 100 ",

    "gaosend -B -p udp -l rand -c 100",
    "gaosend -B -p udp -l 64 -c 100",
    "gaosend -B -p udp -l 50 -c 100",
    "gaosend -B -p udp -l 100 -c 100",
    "gaosend -B -p udp -l 2000 -c 100",
    "gaosend -B -p udp -l 100 -S rand -c 100",
    "gaosend -B -p udp -l 64 -S rand -c 100",
    "gaosend -B -p udp -l 50 -S rand -c 100",
    "gaosend -B -p udp -l 100 -S rand -c 100",
    "gaosend -B -p udp -l 2000 -S rand -c 100",
    "gaosend -B -p udp -l 64 -S abc -O 0 -c 100",
    "gaosend -B -p udp -l 64 -S abc -O 10 -c 100",
    #"gaosend -B -p udp -l 64 -S abc -O 100 -c 100",
    "gaosend -B -a rand -b incr -s incr -d rand -P rand -Q incr -V rand  -W 200 -c 100 -p udp",

    "gaosend -B -p tcp -l rand -c 100",
    "gaosend -B -p tcp -l 64 -c 100",
    #"gaosend -B -p tcp -l 50 -c 100",
    "gaosend -B -p tcp -l 100 -c 100",
    "gaosend -B -p tcp -l 2000 -c 100",
    "gaosend -B -p tcp -l 100 -S rand -c 100",
    "gaosend -B -p tcp -l 64 -S rand -c 100",
    #"gaosend -B -p tcp -l 50 -S rand -c 100",
    "gaosend -B -p tcp -l 100 -S rand -c 100",
    "gaosend -B -p tcp -l 2000 -S rand -c 100",
    "gaosend -B -p tcp -l 64 -S abc -O 0 -c 100",
    #"gaosend -B -p tcp -l 64 -S abc -O 10 -c 100",
    #"gaosend -B -p tcp -l 64 -S abc -O 100 -c 100",
    "gaosend -B -a rand -b incr -s incr -d rand -P rand -Q incr -V rand  -W 200 -c 100 -p tcp",

    "gaosend -B -p arp -c 100",
    "gaosend -B -a rand -b incr -p arp -c 100",
    "gaosend -B -a 00:23:76:00:00:ee -b rand -p arp -c 100",
    "gaosend -B -p icmp -c 100",
    "gaosend -B -a rand -b rand -s rand -d incr -p icmp -c 100",
    "gaosend -B -a rand -b rand -s rand -d incr -W random -p icmp -c 100",
    "gaosend -B -p dns -c 100",
    "gaosend -B -a rand -b rand -s rand -d incr -P rand -Q incr -p dns -c 100",
    "gaosend -B -a rand -b rand -s rand -d incr -P rand -Q -W rand incr -p dns -c 100",
    "gaosend -B -a rand -b rand -s rand -d incr -P rand -Q -W rand incr -p dns -u www.360.cn -c 100",
    "gaosend -B -p http -c 100",
    "gaosend -B -a rand -b rand -s rand -d incr -P rand -Q incr -p http -c 100",
    "gaosend -B -a rand -b rand -s rand -d incr -P rand -Q -W rand incr -p http -c 100",
    "gaosend -B -p http-get -c 100",
    "gaosend -B -a rand -b rand -s rand -d incr -P rand -Q incr -p http-get -c 100",
    "gaosend -B -a rand -b rand -s rand -d incr -P rand -Q -W rand incr -p http-get -c 100",
    "gaosend -B -a rand -b rand -s rand -d incr -P rand -Q -W rand incr -p http-get -u www.360.cn -c 100",
    "gaosend -B -p http-post -c 100",
    "gaosend -B -a rand -b rand -s rand -d incr -P rand -Q incr -p http-post -c 100",
    "gaosend -B -a rand -b rand -s rand -d incr -P rand -Q -W rand incr -p http-post -c 100",
    "gaosend -B -a rand -b rand -s rand -d incr -P rand -Q -W rand incr -p http-post -u www.360.cn -c 100",

    "gaosend -B -a rand -b incr -s incr -d rand -P rand -Q incr -V rand  -W 200 -p udp6 -c 100",
    "gaosend -B -a rand -b incr -s incr -d rand -P rand -Q incr -V rand  -W 200 -p tcp6 -c 100",
    "gaosend -B -a rand -b rand -s rand -d incr -W random -p icmp6 -c 100",
    "gaosend -B -a rand -b rand -s rand -d incr -P rand -Q -W rand incr -c 100 -p dns6",
    "gaosend -B -a rand -b rand -s rand -d incr -P rand -Q -W rand incr -c 100 -p http6",
    "gaosend -B -a rand -b rand -s rand -d incr -P rand -Q -W rand incr -c 100 -p http-get",
    "gaosend -B -a rand -b rand -s rand -d incr -P rand -Q -W rand incr -c 100 -p http-post6",

    "gaosend -R -r pcap/http_one_stream.pcap",
    #"gaosend -R -r pcap/http_one_stream.pcap -c 100 -i eth0",
    "gaosend -R -r pcap/http_one_stream.pcap -c 100 -i ens33",
    "gaosend -R -r pcap/http_one_stream.pcap -c 10 -I 500",
    "gaosend -D -r pcap/http_one_stream.pcap -w save.pcap -c 100",
    "gaosend -D -r pcap/http_one_stream.pcap -w save.pcap -c 10000",

    "gaosend -C -r pcap/http_one_stream.pcap -w save.pcap",

    "gaosend -m -r http_one_stream_*.pcap -w save.pcap",
    "gaosend  -r -w save.pcap http_one_stream_*.pcap -m",
    "gaosend -m -r pcap/http_one_stream.pcap -w save.pcap",

    "gaosend -A -r pcap/http_one_stream.pcap",
    "gaosend -A -r pcap/http_one_stream.pcap -f",

    "gaosend -F -r pcap/http_one_stream.pcapng -w save.pcap",

    #"gaosend -M -r pcap/http_one_stream.pcap -w save.pcap",
    "gaosend -M -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -s 1.1.1.1 -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -s 1.1.1.1 -d 2.2.2.2 -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -s rand -d 2.2.2.2 -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -s 1.1.1.1 -d incr -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -s rand -d incr -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -s rand -d rand -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -s incr -d incr -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",

    "gaosend -M -a 00:23:76:00:00:ee -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -b 00:23:76:00:00:ff -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -a 00:23:76:00:00:ee  -b 00:23:76:00:00:ff -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -a rand  -b 00:23:76:00:00:ff -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -a 00:23:76:00:00:ee -b incr -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -a rand  -b incr -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -a rand  -b rand -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -a incr -b incr -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",

    "gaosend -M -P 101 -Q 102 -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -P 101 -Q rand -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -P 101 -Q incr -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -P incr -Q incr -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -P incr -Q rand -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -P rand -Q incr -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -P rand -Q rand -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",

    "gaosend -M -V 100 -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -V rand -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -W 200 -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -W rand -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -V 100 -W 200 -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -V rand -W 200 -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -V 100 -W rand -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -V rand -W rand -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",

    "gaosend -M -a rand -b incr -s incr -d rand -P rand -Q incr -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -a rand -b incr -s incr -d rand -P rand -Q incr -V rand -W 200 -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -a rand -b incr -s incr -d rand -P rand -Q incr -W rand -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    #"gaosend -M -a rand -b incr -s incr -d rand -P rand -Q incr -W rand -r pcap/http_one_stream.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -a rand -b incr -s incr -d rand -P rand -Q incr -W rand -p ipv6 -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129",
    "gaosend -M -W rand -P rand -b incr -Q incr -s incr -p ipv6 -r pcap/http_one_stream.pcap -w save.pcap -E IP,10.18.219.14,10.16.13.129 -d rand -a rand ",
]


def judge_result(res):
    global success_no, failed_no, other_no
    res = res >> 8
    if res == 0:
        failed_no += 1
        print "\033[1;31;5mfailed %d\033[0m" % (res) 
    elif res == 1:
        success_no += 1 
        print "\033[1;32;1msuccess %d\033[0m" % (res)
    else:
        other_no += 1
        print "\033[1;33;1mother %d\033[0m" % (res)
    

def execution_case(case_no):
    global totle_no
    if int(case_no) == 0:
        num = 1
        totle_no = len(all_case_list)
        for case in all_case_list:
            save_file_name = "case-%d.pcap" % (num)
            case = case.replace("save.pcap", save_file_name)
            print "*" * 60 + "\ncase %d: %s" % (num, case)
            judge_result(os.system(case))
            num += 1
            print "=" * 60, "\n"
    elif int(case_no) in range(1, len(all_case_list) + 1):
        num = int(case_no)
        totle_no = 1
        save_file_name = "case-%d.pcap" % (num)
        case = all_case_list[num - 1].replace("save.pcap", save_file_name)
        print "*" * 60 + "\ncase %d: %s" % (num, case)
        judge_result(os.system(case));
        print "=" * 60, "\n"
    else:
        print "\033[1;31;1mTest case not exist\033[0m"
        exit(0)
        
        
def make_date_version():
    sub_version = time.strftime('%Y%m%d%H%M%S',time.localtime(time.time()))
    with open('include/default.h', 'r') as f:
        lines=f.readlines()
        f.close()
    with open('include/default.h', 'w') as w:
        for line in lines:
            if 'COMPILETIME' in line:
                sp = line.rsplit(' ', 1)
                line = '%s "%s"\n' % (sp[0], sub_version)
            w.write(line)
        w.close()


def version_add_one():
    with open('include/default.h', 'r') as f:
        lines=f.readlines()
        f.close()
    with open('include/default.h', 'w') as w:
        for line in lines:
            if 'VERSION' in line:
                sp = line.rsplit('"', 1)[0].rsplit(".", 1)
                line = '%s.%d"\n' % (sp[0], int(sp[1])+1)
            w.write(line)
        w.close()
    

def compile_program(add_version=False):
    if add_version:
        version_add_one()
    make_date_version()
    os.system("ctags -R")
    exec_res = os.system('gcc -o /usr/local/bin/gaosend src/*.c -I./include -O2  -Wall -g')
    if exec_res != 0:
        print "\033[1;31;1mCompile failed...\033[0m"
    else:
        print "\033[1;32;1mCompile finished...\033[0m"
    time.sleep(2)


def display_result():
    print "\033[1;36;1m" + "#" * 30 + "\033[0m"
    print "\033[1;34;1mTotle   : %d\033[0m" % (totle_no)
    print "\033[1;32;1mSuccess : %d\033[0m" % (success_no)
    print "\033[1;33;1mOther   : %d\033[0m" % (other_no)
    print "\033[1;31;1mFailed  : %d\033[0m" % (failed_no)
    print "\033[1;36;1m" + "#" * 30 + "\033[0m"


def main():
    parser = argparse.ArgumentParser(description='Compile program or perform test cases')
    parser.add_argument('-n', '--number')
    parser.add_argument('-c', '--compile', action='store_true')
    args = parser.parse_args()

    if args.compile:
        compile_program(True)
    elif args.number:
        if args.number.isdigit():
            execution_case(args.number)
        display_result()
    else:
        compile_program()


if __name__ == "__main__":
    main()

