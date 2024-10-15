package bpf

import "github.com/flomesh-io/fsm/pkg/logger"

var (
	log = logger.New("fsm-ebpf")
)

const (
	BPF_FS = `/sys/fs/bpf`

	FSM_PROG_NAME      = `fsm`
	FSM_PROGS_MAP_NAME = `fsm_progs`
)

const (
	MESH_CNI_HANDSHAKE_PROG_ID = uint32(1)
	MESH_CNI_CONNTRACK_PROG_ID = uint32(2)
	MESH_CNI_PASS_PROG_ID      = uint32(3)
	MESH_CNI_DROP_PROG_ID      = uint32(4)
)

const (
	MESH_CNI_HANDSHAKE_PROG_NAME = `classifier_handshake`
	MESH_CNI_CONNTRACK_PROG_NAME = `classifier_conntrack`
	MESH_CNI_PASS_PROG_NAME      = `classifier_pass`
	MESH_CNI_DROP_PROG_NAME      = `classifier_drop`
)
