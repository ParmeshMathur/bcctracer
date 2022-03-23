#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define IFNAMSIZ 16
#define XT_TABLE_MAXNAMELEN 32
#define FUNCNAME_MAX_LEN 64

struct event_t 
{
    char func_name[FUNCNAME_MAX_LEN];
    u8 flags;
    u8 cpu;

    // route info
    char ifname[IFNAMSIZ];
    u32  netns;

    // pkt info
    u8 dest_mac[6];
    u32 len;
    u8 ip_version;
    u8 l4_proto;
    u16 tot_len;
    u64 saddr[2];
    u64 daddr[2];
    u8 icmptype;
    u16 icmpid;
    u16 icmpseq;
    u16 sport;
    u16 dport;
    u16 tcpflags;

    // ipt info
    u32 hook;
    u8 pf;
    u32 verdict;
    char tablename[XT_TABLE_MAXNAMELEN];
    u64 ipt_delay;

    void *skb;
    // skb info
    u8 pkt_type; //skb->pkt_type

    // call stack
    int kernel_stack_id;
    u64 kernel_ip;

    //time
    u64 start_ns;
    u64 test;
};
// BPF_PERF_OUTPUT(route_event);
//NEW DEF for libbpf//
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} route_event SEC(".maps");

struct ipt_do_table_args
{
    struct sk_buff *skb;
    const struct nf_hook_state *state;
    struct xt_table *table;
    u64 start_ns;
};
// BPF_HASH(cur_ipt_do_table_args, u32, struct ipt_do_table_args);
//NEW DEF for libbpf//
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct ipt_do_table_args);
} cur_ipt_do_table_args SEC(".maps")

union ___skb_pkt_type 
{
    __u8 value;
    struct 
    {
        __u8			__pkt_type_offset[0];
        __u8			pkt_type:3;
        __u8			pfmemalloc:1;
        __u8			ignore_df:1;

        __u8			nf_trace:1;
        __u8			ip_summed:2;
    };
};


enum 
{
__TCP_FLAG_CWR,
__TCP_FLAG_ECE,
__TCP_FLAG_URG,
__TCP_FLAG_ACK,
__TCP_FLAG_PSH,
__TCP_FLAG_RST,
__TCP_FLAG_SYN,
__TCP_FLAG_FIN
};

#define TCP_FLAGS_INIT(new_flags, orig_flags, flag) \
    do { \
        if (orig_flags & flag) { \
            new_flags |= (1U<<__##flag); \
        } \
    } while (0)


#define CALL_STACK(ctx, event) \
    do { \
    if (__BCC_callstack) \
        get_stack(ctx, event); \
    } while (0)


/**
  * Common tracepoint handler. Detect IPv4/IPv6 and
  * emit event with address, interface and namespace.
  */
static int
do_trace_skb(struct event_t *event, void *ctx, struct sk_buff *skb, void *netdev)
{
    struct net_device *dev;

    char *head;
    char *l2_header_address;
    char *l3_header_address;
    char *l4_header_address;

    u16 mac_header;
    u16 network_header;

    u8 proto_icmp_echo_request;
    u8 proto_icmp_echo_reply;
    u8 l4_offset_from_ip_header;

    struct icmphdr icmphdr;
    union tcp_word_hdr tcphdr;
    struct udphdr udphdr;

    // Get device pointer, we'll need it to get the name and network namespace
    event->ifname[0] = 0;
    if (netdev)
        dev = netdev;
    else
        member_read(&dev, skb, dev);

    //bpf_probe_read
    bpf_core_read(&event->ifname, IFNAMSIZ, dev->name);

    if (event->ifname[0] == 0 || dev == NULL)
        bpf_strncpy(event->ifname, "nil", IFNAMSIZ);

    event->flags |= ROUTE_EVENT_IF;

    #ifdef CONFIG_NET_NS
        struct net* net;

        // Get netns id. The code below is equivalent to: event->netns = dev->nd_net.net->ns.inum
        possible_net_t *skc_net = &dev->nd_net;
        member_read(&net, skc_net, net);
        struct ns_common *ns = member_address(net, ns);
        member_read(&event->netns, ns, inum);

        // maybe the skb->dev is not init, for this situation, we can get ns by sk->__sk_common.skc_net.net->ns.inum
        if (event->netns == 0)
        {
            struct sock *sk;
            struct sock_common __sk_common;
            struct ns_common* ns2;
            member_read(&sk, skb, sk);
            if (sk != NULL)
            {
                member_read(&__sk_common, sk, __sk_common);
                ns2 = member_address(__sk_common.skc_net.net, ns);
                member_read(&event->netns, ns2, inum);
            }
        }
    #endif

    event->cpu = bpf_get_smp_processor_id();
    member_read(&event->len, skb, len);
    member_read(&head, skb, head);
    member_read(&mac_header, skb, mac_header);
    member_read(&network_header, skb, network_header);

    if(network_header == 0) {
        network_header = mac_header + MAC_HEADER_SIZE;
    }

    l2_header_address = mac_header + head;
    //bpf_probe_read
    bpf_core_read(&event->dest_mac, 6, l2_header_address);

    l3_header_address = head + network_header;
    //bpf_probe_read
    bpf_core_read(&event->ip_version, sizeof(u8), l3_header_address);
    event->ip_version = event->ip_version >> 4 & 0xf;

    if (event->ip_version == 4)
    {
        struct iphdr iphdr;
        // //bpf_probe_read
        bpf_core_read(&iphdr, sizeof(iphdr), l3_header_address);
        bpf_core_read(&iphdr, sizeof(iphdr), l3_header_address)

        l4_offset_from_ip_header = iphdr.ihl * 4;
        event->l4_proto  = iphdr.protocol;
        event->saddr[0] = iphdr.saddr;
        event->daddr[0] = iphdr.daddr;
    	event->tot_len = ntohs(iphdr.tot_len);

    	if (event->l4_proto == IPPROTO_ICMP) 
        {
       	    proto_icmp_echo_request = ICMP_ECHO;
       	    proto_icmp_echo_reply   = ICMP_ECHOREPLY;
        }

    }
    else if (event->ip_version == 6)
    {
        // Assume no option header --> fixed size header
        struct ipv6hdr* ipv6hdr = (struct ipv6hdr*)l3_header_address;
        l4_offset_from_ip_header = sizeof(*ipv6hdr);

        //bpf_probe_read
        bpf_core_read(&event->l4_proto,  sizeof(ipv6hdr->nexthdr),  (char*)ipv6hdr + offsetof(struct ipv6hdr, nexthdr));
        //bpf_probe_read
        bpf_core_read(event->saddr, sizeof(ipv6hdr->saddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, saddr));
        //bpf_probe_read
        bpf_core_read(event->daddr, sizeof(ipv6hdr->daddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, daddr));
    	//bpf_probe_read
        bpf_core_read(&event->tot_len, sizeof(ipv6hdr->payload_len), (char*)ipv6hdr + offsetof(struct ipv6hdr, payload_len));
        event->tot_len = ntohs(event->tot_len);

    	if (event->l4_proto == IPPROTO_ICMPV6)
        {
            proto_icmp_echo_request = ICMPV6_ECHO_REQUEST;
            proto_icmp_echo_reply   = ICMPV6_ECHO_REPLY;
        }

    }
    else 
        return -1;

    l4_header_address = l3_header_address + l4_offset_from_ip_header;
    switch (event->l4_proto)
    {
        case IPPROTO_ICMPV6:
        case IPPROTO_ICMP:
            //bpf_probe_read
        bpf_core_read(&icmphdr, sizeof(icmphdr), l4_header_address);
            if (icmphdr.type != proto_icmp_echo_request && icmphdr.type != proto_icmp_echo_reply) {
                return -1;
            }
            event->icmptype = icmphdr.type;
            event->icmpid   = be16_to_cpu(icmphdr.un.echo.id);
            event->icmpseq  = be16_to_cpu(icmphdr.un.echo.sequence);
            break;
        case IPPROTO_TCP:
            //bpf_probe_read
        bpf_core_read(&tcphdr, sizeof(tcphdr), l4_header_address);
            init_tcpflags_bits(event->tcpflags, tcp_flag_word(&tcphdr));
            event->sport = be16_to_cpu(tcphdr.hdr.source);
            event->dport = be16_to_cpu(tcphdr.hdr.dest);
            break;
        case IPPROTO_UDP:
            //bpf_probe_read
        bpf_core_read(&udphdr, sizeof(udphdr), l4_header_address);
            event->sport = be16_to_cpu(udphdr.source);
            event->dport = be16_to_cpu(udphdr.dest);
            break;
        default:
            return -1;
    }

    #if __BCC_keep
    #endif


    /*
     * netns filter
     */
    if (__BCC_netns !=0 && event->netns != 0 && event->netns != __BCC_netns) {
        return -1;
    }

    /*
     * pid filter
     */
    #if __BCC_pid
        u64 tgid = bpf_get_current_pid_tgid() >> 32;
        if (tgid != __BCC_pid)
            return -1;
    #endif

    /*
     * skb filter
     */
    #if __BCC_ipaddr
        if (event->ip_version == 4)
        {
           if (__BCC_ipaddr != event->saddr[0] && __BCC_ipaddr != event->daddr[0])
               return -1;
        }
        else 
           return -1;
    #endif

    #if __BCC_proto
        if !(__BCC_proto & event->l4_proto)
           return -1;
    #endif

    #if __BCC_port
        if ( (event->l4_proto == IPPROTO_UDP || event->l4_proto == IPPROTO_TCP) &&
        (__BCC_port != event->sport && __BCC_port != event->dport))
           return -1;
    #endif

    #if __BCC_icmpid
        if (__BCC_proto == IPPROTO_ICMP && __BCC_icmpid != event->icmpid)
           return -1;
    #endif

    #if __BCC_keep
    #endif

    return 0;
}

static int
do_trace(void *ctx, struct sk_buff *skb, const char *func_name, void *netdev)
{
    struct event_t event = {};
    union ___skb_pkt_type type = {};

    if (do_trace_skb(&event, ctx, skb, netdev) < 0)
        return 0;

    event.skb=skb;
    //bpf_probe_read
    bpf_core_read(&type.value, 1, ((char*)skb) + offsetof(typeof(*skb), __pkt_type_offset));
    event.pkt_type = type.pkt_type;

    event.start_ns = bpf_ktime_get_ns();
    bpf_strncpy(event.func_name, func_name, FUNCNAME_MAX_LEN);
    CALL_STACK(ctx, &event);
    route_event.perf_submit(ctx, &event, sizeof(event));
out:
    return 0;
}


#if __BCC_iptable
static int
__ipt_do_table_in(struct pt_regs *ctx, struct sk_buff *skb,
		const struct nf_hook_state *state, struct xt_table *table)
{
    u32 pid = bpf_get_current_pid_tgid();

    struct ipt_do_table_args args = {
        .skb = skb,
        .state = state,
        .table = table,
    };
    args.start_ns = bpf_ktime_get_ns();
    cur_ipt_do_table_args.update(&pid, &args);

    return 0;
};

static int
__ipt_do_table_out(struct pt_regs * ctx, struct sk_buff *skb)
{
    struct event_t event = {};
    union ___skb_pkt_type type = {};
    struct ipt_do_table_args *args;
    u32 pid = bpf_get_current_pid_tgid();

    args = cur_ipt_do_table_args.lookup(&pid);
    if (args == 0)
        return 0;

    cur_ipt_do_table_args.delete(&pid);

    if (do_trace_skb(&event, ctx, args->skb, NULL) < 0)
        return 0;

    event.flags |= ROUTE_EVENT_IPTABLE;
    event.ipt_delay = bpf_ktime_get_ns() - args->start_ns;
    member_read(&event.hook, args->state, hook);
    member_read(&event.pf, args->state, pf);
    member_read(&event.tablename, args->table, name);
    event.verdict = PT_REGS_RC(ctx);
    event.skb=args->skb;
    //bpf_probe_read
    bpf_core_read(&type.value, 1, ((char*)args->skb) + offsetof(typeof(*args->skb), __pkt_type_offset));
    event.pkt_type = type.pkt_type;

    event.start_ns = bpf_ktime_get_ns();
    CALL_STACK(ctx, &event);
    route_event.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

#endif


#if __BCC_dropstack
int kprobe____kfree_skb(struct pt_regs *ctx, struct sk_buff *skb)
{
    struct event_t event = {};

    if (do_trace_skb(&event, ctx, skb, NULL) < 0)
        return 0;

    event.flags |= ROUTE_EVENT_DROP;
    event.start_ns = bpf_ktime_get_ns();
    bpf_strncpy(event.func_name, __func__+8, FUNCNAME_MAX_LEN);
    get_stack(ctx, &event);
    route_event.perf_submit(ctx, event, sizeof(*event));
    return 0;
}
#endif

#if 0
int kprobe__ip6t_do_table(struct pt_regs *ctx, struct sk_buff *skb, const struct nf_hook_state *state, struct xt_table *table)
{
    return __ipt_do_table_in(ctx, skb, state, table);
};

int kretprobe__ip6t_do_table(struct pt_regs *ctx)
{
    return __ipt_do_table_out(ctx);
}
#endif
