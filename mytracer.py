#!/usr/bin/python3
from bcc import BPF
import argparse
import struct
import socket
from socket import inet_ntop, AF_INET, AF_INET6

examples = """examples:
      skbtracer.py                                      # trace all packets
      skbtracer.py --proto=icmp -H 1.2.3.4 --icmpid 22  # trace icmp packet with addr=1.2.3.4 and icmpid=22
      skbtracer.py --proto=tcp  -H 1.2.3.4 -P 22        # trace tcp  packet with addr=1.2.3.4:22
      skbtracer.py --proto=udp  -H 1.2.3.4 -P 22        # trace udp  packet wich addr=1.2.3.4:22
      skbtracer.py -t -T -p 1 --debug -P 80 -H 127.0.0.1 --proto=tcp --kernel-stack --icmpid=100 -N 10000
"""

parser = argparse.ArgumentParser(
    description="Trace any packet through TCP/IP stack",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-H", "--ipaddr", type=str,
    help="ip address")

parser.add_argument("--proto", type=str,
    help="tcp|udp|icmp|any ")

parser.add_argument("--icmpid", type=int, default=0,
    help="trace icmp id")

parser.add_argument("-c", "--catch-count", type=int, default=1000000,
    help="catch and print count")

parser.add_argument("-P", "--port", type=int, default=0,
    help="udp or tcp port")

parser.add_argument("-p", "--pid", type=int, default=0,
    help="trace this PID only")

parser.add_argument("-N", "--netns", type=int, default=0,
    help="trace this Network Namespace only")

parser.add_argument("--dropstack", action="store_true",
    help="output kernel stack trace when drop packet")

parser.add_argument("--callstack", action="store_true",
    help="output kernel stack trace")

parser.add_argument("--iptable", action="store_true",
    help="output iptable path")

parser.add_argument("--route", action="store_true",
    help="output route path")

parser.add_argument("--keep", action="store_true",
    help="keep trace packet all lifetime")

parser.add_argument("-T", "--time", action="store_true",
    help="show HH:MM:SS timestamp")

parser.add_argument("-t", "--timestamp", action="store_true",
    help="show timestamp in seconds at us resolution")

parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)

parser.add_argument("--debug", action="store_true",
    help=argparse.SUPPRESS)

args = parser.parse_args()
if args.debug == True:
    print("pid=%d time=%d timestamp=%d ipaddr=%s port=%d netns=%d proto=%s icmpid=%d dropstack=%d" % \
            (args.pid,args.time,args.timestamp,args.ipaddr, args.port,args.netns,args.proto,args.icmpid, args.dropstack))
    sys.exit()


ipproto={}
#ipproto["tcp"]="IPPROTO_TCP"
ipproto["tcp"]="6"
#ipproto["udp"]="IPPROTO_UDP"
ipproto["udp"]="17"
#ipproto["icmp"]="IPPROTO_ICMP"
ipproto["icmp"]="1"
proto = 0 if args.proto == None else (0 if ipproto.get(args.proto) == None else ipproto[args.proto])
#ipaddr=socket.htonl(struct.unpack("I",socket.inet_aton("0" if args.ipaddr == None else args.ipaddr))[0])
#port=socket.htons(args.port)
ipaddr=(struct.unpack("I",socket.inet_aton("0" if args.ipaddr == None else args.ipaddr))[0])
port=(args.port)
icmpid=socket.htons(args.icmpid)

bpf_def="#define __BCC_ARGS__\n"
bpf_args="#define __BCC_pid (%d)\n" % (args.pid)
bpf_args+="#define __BCC_ipaddr (0x%x)\n" % (ipaddr)
bpf_args+="#define __BCC_port (%d)\n" % (port)
bpf_args+="#define __BCC_netns (%d)\n" % (args.netns)
bpf_args+="#define __BCC_proto (%s)\n" % (proto)
bpf_args+="#define __BCC_icmpid (%d)\n" % (icmpid)
bpf_args+="#define __BCC_dropstack (%d)\n" % (args.dropstack)
bpf_args+="#define __BCC_callstack (%d)\n" % (args.callstack)
bpf_args+="#define __BCC_iptable (%d)\n" % (args.iptable)
bpf_args+="#define __BCC_route (%d)\n" % (args.route)
bpf_args+="#define __BCC_keep (%d)\n" % (args.keep)

bpf_text=open(r"skbtracer.c", "r").read()
bpf_text=bpf_def + bpf_text
bpf_source=bpf_text.replace("__BCC_ARGS_DEFINE__", bpf_args)
bpf_source+= """
#include <linux/sched.h>

BPF_PERF_OUTPUT(events);

typedef struct data_t
{
	u32 pid;
	char comm[TASK_COMM_LEN];
} data_t;

typedef struct sys_enter_openat_args_t
{
	// taken from /sys/kernel/debug/tracing/syscalls/sys_enter_openat/format
	uint64_t _unused;

	int32_t snr;
	uint64_t dfd;
	char filename[8];
	uint64_t flags;
	uint64_t mode;
} sys_enter_openat_args_t;

int sys_enter_openat_fn (sys_enter_openat_args_t* args)
{
	data_t data = {};
	uint32_t curpid = (uint32_t)(bpf_get_current_pid_tgid() >> 32);
	bpf_trace_printk("openat has fired %d \\n", curpid);

	data.pid = curpid;
	bpf_probe_read_str(data.comm, TASK_COMM_LEN, args->filename);

	events.perf_submit(args, &data, sizeof(data));

	return 0;
}
"""


bpf = BPF(text = bpf_source)
bpf.attach_tracepoint(tp = "syscalls:sys_enter_openat", fn_name = "sys_enter_openat_fn")

def sys_enter_openat_handler(cpu, data, size):
	event = bpf["events"].event(data)
	pid = event.pid
	comm = event.comm

	print("pid: ", pid, "-- command: ", comm)

bpf["events"].open_perf_buffer(sys_enter_openat_handler)

while True:
	try:
		bpf.perf_buffer_poll()
	except KeyboardInterrupt:
		exit()