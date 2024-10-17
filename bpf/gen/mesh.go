package gen

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags $BPF_CFLAGS bpf $BPF_SRC_DIR/mesh.kern.c -- -I $BPF_INC_DIR
