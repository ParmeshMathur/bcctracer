# skbtracer

skbtracer is a tool for skb network packet path tracing based on ebpf technology, the implementation code is based on [BCC](https://github.com/iovisor/bcc) (Linux Kernel 4.15+ required).

## Example of use

```
skbtracer.py                                      # trace all packets
skbtracer.py --proto=icmp -H 1.2.3.4 --icmpid 22  # trace icmp packet with addr=1.2.3.4 and icmpid=22
skbtracer.py --proto=tcp  -H 1.2.3.4 -P 22        # trace tcp  packet with addr=1.2.3.4:22
skbtracer.py --proto=udp  -H 1.2.3.4 -P 22        # trace udp  packet wich addr=1.2.3.4:22
skbtracer.py -t -T -p 1 --debug -P 80 -H 127.0.0.1 --proto=tcp --kernel-stack --icmpid=100 -N 10000
```

Running result:

```bash
$ sudo ./skbtracer.py -c 100
time       NETWORK_NS   CPU    INTERFACE          DEST_MAC     IP_LEN PKT_INFO                                 TRACE_INFO
[06:47:28 ][4026531992] 0      b'nil'             00042de08c77 196    T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a594e0.0:b'ip_output'
[06:47:28 ][4026531992] 0      b'eth0'            00042de08c77 196    T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a594e0.0:b'ip_finish_output'
[06:47:28 ][4026531992] 0      b'eth0'            00042de08c77 196    T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a594e0.0:b'__dev_queue_xmit'
[06:47:28 ][4026531992] 0      b'nil'             000439849c02 76     T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a59ee0.0:b'ip_output'
[06:47:28 ][4026531992] 0      b'eth0'            000439849c02 76     T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a59ee0.0:b'ip_finish_output'
[06:47:28 ][4026531992] 0      b'eth0'            000439849c02 76     T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a59ee0.0:b'__dev_queue_xmit'
[06:47:28 ][4026531992] 0      b'nil'             000429e08c77 228    T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a59ae0.0:b'ip_output'
[06:47:28 ][4026531992] 0      b'eth0'            000429e08c77 228    T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a59ae0.0:b'ip_finish_output'
[06:47:28 ][4026531992] 0      b'eth0'            000429e08c77 228    T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a59ae0.0:b'__dev_queue_xmit'
[06:47:28 ][4026531992] 0      b'nil'             000439e08c77 76     T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a59ce0.0:b'ip_output'
[06:47:28 ][4026531992] 0      b'eth0'            000439e08c77 76     T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a59ce0.0:b'ip_finish_output'
```

## Function enhancement

1. Adjust the implementation based on the number of grabs (more accurate, avoids exceptions being ignored in some environments).
2. Add field with IP length.
3. Add field for running CPU.

The code of this article comes from [gist](https://gist.github.com/chendotjs/194768c411f15ecfec11e7235c435fa0).

For a more general network scheme see the repository [WeaveWorks tcptracer-bpf](https://github.com/weaveworks/tcptracer-bpf).

## Related documentation 

* [In-depth analysis of container network dup packet problems using ebpf](https://blog.csdn.net/alex_yangchuansheng/article/details/104058072)
* [Tracing packets with Linux tracepoint, perf, and eBPF (2017)](https://github.com/DavadDi/bpf_study/blob/master/trace-packet-with-tracepoint-perf-ebpf/index_zh.md)
