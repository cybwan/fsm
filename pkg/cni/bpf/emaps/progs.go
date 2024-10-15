package emaps

import (
	"path"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/flomesh-io/fsm/pkg/cni/bpf"
)

func InitFsmProgsMap() {
	pinnedFile := path.Join(bpf.BPF_FS, bpf.FSM_PROG_NAME, bpf.FSM_PROGS_MAP_NAME)
	progsMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
	}

	type ebpfProg struct {
		progKey  uint32
		progName string
	}

	progs := []ebpfProg{
		{
			progKey:  bpf.FSM_CNI_HANDSHAKE_PROG_ID,
			progName: bpf.FSM_CNI_HANDSHAKE_PROG_NAME,
		},
		{
			progKey:  bpf.FSM_CNI_CONNTRACK_PROG_ID,
			progName: bpf.FSM_CNI_CONNTRACK_PROG_NAME,
		},
		{
			progKey:  bpf.FSM_CNI_PASS_PROG_ID,
			progName: bpf.FSM_CNI_PASS_PROG_NAME,
		},
		{
			progKey:  bpf.FSM_CNI_DROP_PROG_ID,
			progName: bpf.FSM_CNI_DROP_PROG_NAME,
		},
	}

	for _, prog := range progs {
		pinnedFile = path.Join(bpf.BPF_FS, bpf.FSM_PROG_NAME, prog.progName)
		pinnedProg, progErr := ebpf.LoadPinnedProgram(pinnedFile, &ebpf.LoadPinOptions{})
		if progErr != nil {
			log.Fatal().Err(progErr).Msgf("failed to load ebpf prog: %s", pinnedFile)
		}
		progFD := pinnedProg.FD()
		if err := progsMap.Update(unsafe.Pointer(&prog.progKey), unsafe.Pointer(&progFD), ebpf.UpdateAny); err != nil {
			log.Fatal().Err(err).Msgf("failed to update ebpf map: %s", bpf.FSM_PROGS_MAP_NAME)
		}
	}
}
