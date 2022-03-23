#include <stdio.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <bcc/BPF.h>
#include <bcc/perf_reader.h>
#include <bcc/BPFTable.h>
#include <bcc/libbpf.h>
#include <bcc/bcc_common.h>
#include <bcc/bcc_syms.h>
#include <bcc/bpf_module.h>
#include <bcc/bcc_elf.h>
#include <bcc/bcc_proc.h>
#include <bcc/bcc_usdt.h>

#define FUNCNAME_MAX_LEN 64
#define IFNAMSIZ 16
#define XT_TABLE_MAXNAMELEN 32

using namespace std;

//get my own IP//
string getMyIP()
{
	// int tpid=fork();
	// if(!tpid)
	// {
	// 	// create a tester.txt to temp put IP address in buffer file ideally
	// 	execve(hostname -I | awk '{print $1}' > tester.txt)
	// }
	// watpid(tpid);
	// read from tester.txt
	return "";
}

string bpf_text = ""; //read from skbtracer.c

typedef struct event_t {
    char 	func_name[FUNCNAME_MAX_LEN];
    uint8_t flags;
    uint8_t cpu;

    // route info
    char 		ifname[IFNAMSIZ];
    uint32_t 	netns;

    // pkt info
    uint8_t dest_mac[6];
    uint32_t len;
    uint8_t ip_version;
    uint8_t l4_proto;
    uint16_t tot_len;
    uint64_t saddr[2];
    uint64_t daddr[2];
    uint8_t icmptype;
    uint16_t icmpid;
    uint16_t icmpseq;
    uint16_t sport;
    uint16_t dport;
    uint16_t tcpflags;

    // ipt info
    uint32_t hook;
    uint8_t pf;
    uint32_t verdict;
    char tablename[XT_TABLE_MAXNAMELEN];
    uint64_t ipt_delay;

    void *skb;
    // skb info
    uint8_t pkt_type; //skb->pkt_type

    // call stack
    int kernel_stack_id;
    uint64_t kernel_ip;

    //time
    uint64_t start_ns;
    uint64_t test;
} event;

void event_printer(void* cpu, void* data, int sz)
{
	char src_addr[INET6_ADDRSTRLEN];
	char dst_addr[INET6_ADDRSTRLEN];

	event_t event;
	if(event.ip_version == 4)
	{
		inet_ntop(AF_INET, event.saddr, src_addr, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, event.daddr, dst_addr, INET_ADDRSTRLEN);
	}
	else
	{
		inet_ntop(AF_INET6, event.saddr, src_addr, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, event.daddr, dst_addr, INET6_ADDRSTRLEN);
	}
	cout<<"event printing\n";
	return;
}

bool is_done = false;

int main(int argc, char const *argv[])
{
	//assign bpf_text to text from skbtracer.c
	ifstream istr("skbtracer.c");
	if(istr)
	{
		ostringstream ss;
		ss << istr.rdbuf();
		bpf_text = ss.str();
	}

	ebpf::BPF bpf;
	bpf.init(bpf_text);

	auto buffer = bpf.open_perf_buffer("pbuff", &event_printer);

	// event_printer();
	cout<<"fin\n";
	while (!is_done)
	{
		// auto retvl = bpf.poll_perf_buffer("event_printer");
		auto retval = bpf.poll_perf_buffer("pbuff");
	}
	return 0;
}