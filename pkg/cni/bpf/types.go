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
	MESH_DP_HANDSHAKE_PROG_ID = uint32(1)
	MESH_DP_CONNTRACK_PROG_ID = uint32(2)
	MESH_DP_PASS_PROG_ID      = uint32(3)
	MESH_DP_DROP_PROG_ID      = uint32(4)
)

const (
	MESH_DP_HANDSHAKE_PROG_NAME = `classifier_handshake`
	MESH_DP_CONNTRACK_PROG_NAME = `classifier_conntrack`
	MESH_DP_PASS_PROG_NAME      = `classifier_pass`
	MESH_DP_DROP_PROG_NAME      = `classifier_drop`
)
