```
make -f Makefile.CNI clean bpf load

make -f bpf/Makefile kern-trace

make -f bpf/Makefile pipy-demo

make -f bpf/Makefile test-up

make -f bpf/Makefile curl-1
```

