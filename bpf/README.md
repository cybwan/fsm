```

clear;make -f bpf/Makefile kern-trace

make -f bpf/Makefile pipy-demo

make -f bpf/Makefile test-up

make -f Makefile.CNI go-build-fsm-tc

make -f Makefile.CNI test

make -f Makefile.CNI clean bpf load
make -f bpf/Makefile test-tc-detach
bin/fsm-tc --action=attach
make -f bpf/Makefile test-tc-show
make -f bpf/Makefile h1-curl-demo
tc_egress 
tc_ingress

bin/fsm-tc --action=init-progs-map
bin/fsm-tc --action=init-nat-map

bin/fsm-tc --action=show-progs-map
bin/fsm-tc --action=show-nat-map
bin/fsm-tc --action=show-nat-map | jq .key -c
bin/fsm-tc --action=show-nat-map | jq .value -c

refactor ebpf interceptor.
Deprecated

make -f bpf/Makefile h1-pipy-demo
make -f bpf/Makefile curl-1
tc_ingress
tc_egress

SidecarAdminPort = 15000
SidecarOutboundListenerPort = 15001
SidecarInboundListenerPort = 15003
SidecarPrometheusInboundListenerPort = 15010
FSMDNSProxyPort = 15053
```



https://elixir.bootlin.com/linux/v6.11.4/source/include/net/tcp_states.h

https://m.elecfans.com/article/2064612.html

https://zhuanlan.zhihu.com/p/98821434

https://zhuanlan.zhihu.com/p/600644770

https://blog.51cto.com/wzgl08/1666021

https://www.cs.montana.edu/courses/spring2004/440/topics/15-transport/lectures/slideset2.pdf





https://github.com/torvalds/linux/blob/master/net/netfilter/nf_conntrack_core.c

https://github.com/torvalds/linux/blob/master/net/openvswitch/conntrack.c

https://arthurchiao.art/blog/conntrack-design-and-implementation/



https://github.com/chobits/tapip/blob/master/tcp/tcp_state.c



https://book.huihoo.com/iptables-tutorial/book1.htm



https://blog.csdn.net/eroswang/article/details/3357617

https://blog.51cto.com/u_4983206/1149724
