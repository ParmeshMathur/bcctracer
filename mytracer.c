// #include <linux/sched.h>

#ifdef __BCC_ARGS__
__BCC_ARGS_DEFINE__
#else

// BPF_PERF_OUTPUT(events);

// typedef struct data_t
// {
// 	u32 pid;
// 	char comm[TASK_COMM_LEN];
// } data_t;

// typedef struct sys_enter_openat_args_t
// {
// 	// taken from /sys/kernel/debug/tracing/syscalls/sys_enter_openat/format
// 	uint64_t _unused;

// 	int32_t snr;
// 	uint64_t dfd;
// 	char filename[8];
// 	uint64_t flags;
// 	uint64_t mode;
// } sys_enter_openat_args_t;

// int sys_enter_openat_fn (sys_enter_openat_args_t* args)
// {
// 	data_t data = {};
// 	uint32_t curpid = (uint32_t)(bpf_get_current_pid_tgid() >> 32);
// 	bpf_trace_printk("openat has fired %d \\n", curpid);

// 	data.pid = curpid;
// 	bpf_probe_read_str(data.comm, TASK_COMM_LEN, args->filename);

// 	events.perf_submit(args, &data, sizeof(data));

// 	return 0;
// }

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
BPF_HASH(currsock, u32, struct sock *);
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();
	// stash the sock ptr for lookup on return
	currsock.update(&pid, &sk);
	return 0;
};
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	skpp = currsock.lookup(&pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}
	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		currsock.delete(&pid);
		return 0;
	}
	// pull in details
	struct sock *skp = *skpp;
	u32 saddr = skp->__sk_common.skc_rcv_saddr;
	u32 daddr = skp->__sk_common.skc_daddr;
	u16 dport = skp->__sk_common.skc_dport;
	// output
	bpf_trace_printk("trace_tcp4connect %x %x %d\\n", saddr, daddr, ntohs(dport));
	currsock.delete(&pid);
	return 0;
}