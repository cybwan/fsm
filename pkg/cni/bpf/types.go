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

const (
	MESH_DP_HAND_SHAKE_PROG_ID = uint32(1)
	MESH_DP_CONN_TRACK_PROG_ID = uint32(2)
	MESH_DP_PASS_PROG_ID       = uint32(3)
	MESH_DP_DROP_PROG_ID       = uint32(4)
)
