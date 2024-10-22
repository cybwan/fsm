package emaps

import (
	"fmt"
	"path"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/flomesh-io/fsm/pkg/cni/bpf"
)

func InitFsmProgsMap() {
	pinnedFile := path.Join(bpf.BPF_FS, bpf.FSM_PROG_NAME, bpf.FSM_MAP_NAME_PROGS)
	progsMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
	}
	defer progsMap.Close()

	type ebpfProg struct {
		progKey  uint32
		progName string
	}

	progs := []ebpfProg{
		{
			progKey:  bpf.FSM_CNI_HANDSHAKE_PROG_KEY,
			progName: bpf.FSM_CNI_HANDSHAKE_PROG_NAME,
		},
		{
			progKey:  bpf.FSM_CNI_CONNTRACK_PROG_KEY,
			progName: bpf.FSM_CNI_CONNTRACK_PROG_NAME,
		},
		{
			progKey:  bpf.FSM_CNI_PASS_PROG_KEY,
			progName: bpf.FSM_CNI_PASS_PROG_NAME,
		},
		{
			progKey:  bpf.FSM_CNI_DROP_PROG_KEY,
			progName: bpf.FSM_CNI_DROP_PROG_NAME,
		},
	}

	for _, prog := range progs {
		pinnedFile = path.Join(bpf.BPF_FS, bpf.FSM_PROG_NAME, prog.progName)
		pinnedProg, progErr := ebpf.LoadPinnedProgram(pinnedFile, &ebpf.LoadPinOptions{})
		if progErr != nil {
			log.Fatal().Err(progErr).Msgf("failed to load ebpf prog: %s", pinnedFile)
		}
		defer pinnedProg.Close()

		progFD := pinnedProg.FD()
		if err := progsMap.Update(unsafe.Pointer(&prog.progKey), unsafe.Pointer(&progFD), ebpf.UpdateAny); err != nil {
			log.Fatal().Err(err).Msgf("failed to update ebpf map: %s", bpf.FSM_MAP_NAME_PROGS)
		}
	}
}

func ShowFsmProgsMap() {
	pinnedFile := path.Join(bpf.BPF_FS, bpf.FSM_PROG_NAME, bpf.FSM_MAP_NAME_PROGS)
	progsMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
	}
	defer progsMap.Close()

	var progKey uint32
	var progFD int

	it := progsMap.Iterate()
	for it.Next(unsafe.Pointer(&progKey), unsafe.Pointer(&progFD)) {
		fmt.Println(progKey, "=>", progFD)
	}
}
