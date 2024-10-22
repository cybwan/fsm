package bpf

const (
	BPF_FS = `/sys/fs/bpf`

	FSM_PROG_NAME      = `fsm`
	FSM_MAP_NAME_PROGS = `fsm_progs`
	FSM_MAP_NAME_NAT   = `fsm_nat`
)

const (
	FSM_CNI_HANDSHAKE_PROG_ID = uint32(1)
	FSM_CNI_CONNTRACK_PROG_ID = uint32(2)
	FSM_CNI_PASS_PROG_ID      = uint32(3)
	FSM_CNI_DROP_PROG_ID      = uint32(4)
)

const (
	FSM_CNI_HANDSHAKE_PROG_NAME = `classifier_handshake`
	FSM_CNI_CONNTRACK_PROG_NAME = `classifier_conntrack`
	FSM_CNI_PASS_PROG_NAME      = `classifier_pass`
	FSM_CNI_DROP_PROG_NAME      = `classifier_drop`
)

const (
	IPPROTO_ICMP L4Proto = 1
	IPPROTO_TCP  L4Proto = 6
	IPPROTO_UDP  L4Proto = 17
)

type L4Proto uint8

const (
	NAT_TYPE_SNAT NatType = 1
	NAT_TYPE_DNAT NatType = 2
)

type NatType uint8

const (
	NAT_LB_ALGO_RDRB NatLbAlgo = 0
	NAT_LB_ALGO_HASH NatLbAlgo = 1
)

type NatLbAlgo uint8
