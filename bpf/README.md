```

make -f bpf/Makefile kern-trace

make -f bpf/Makefile pipy-demo

make -f bpf/Makefile test-up

make -f Makefile.CNI test

make -f Makefile.CNI clean bpf load
make -f bpf/Makefile test-tc-detach
bpf/fsm-tc --action=attach
make -f bpf/Makefile test-tc-show
make -f bpf/Makefile curl-1

bpf/fsm-tc --action=init-progs-map
bpf/fsm-tc --action=init-nat-map

bpf/fsm-tc --action=show-progs-map
bpf/fsm-tc --action=show-nat-map

refactor ebpf interceptor.
Deprecated
```

