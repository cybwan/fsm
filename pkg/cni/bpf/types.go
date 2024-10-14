package bpf

import "github.com/flomesh-io/fsm/pkg/logger"

var (
	log = logger.New("fsm-bpf")
)

const (
	BPF_FS = `/sys/fs/bpf`

	MESH_PROG_NAME     = `mesh`
	FSM_PROGS_MAP_NAME = `fsm_progs`
)
