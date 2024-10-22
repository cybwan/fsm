```

make -f bpf/Makefile kern-trace

make -f bpf/Makefile pipy-demo

make -f bpf/Makefile test-up

make -f Makefile.CNI test

make -f Makefile.CNI clean bpf load
make -f bpf/Makefile test-tc-detach
bpf/tc-attach
make -f bpf/Makefile test-tc-show
make -f bpf/Makefile curl-1

refactor ebpf interceptor.
Deprecated
```

