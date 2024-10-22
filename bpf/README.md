```

make -f bpf/Makefile kern-trace

make -f bpf/Makefile pipy-demo

make -f bpf/Makefile test-up

make -f Makefile.CNI go-build-fsm-tc

make -f Makefile.CNI test

make -f Makefile.CNI clean bpf load
make -f bpf/Makefile test-tc-detach
bin/fsm-tc --action=attach
make -f bpf/Makefile test-tc-show
make -f bpf/Makefile h1-curl-1
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
```
