package bpf

import (
	"fmt"
	"path"
	"unsafe"

	"github.com/cilium/ebpf"
)

func InitFsmProgsMap() {
	pinnedFile := path.Join(BPF_FS, MESH_PROG_NAME, FSM_PROGS_MAP_NAME)
	progsMap, _ := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	fmt.Println(progsMap.String(), progsMap.FD())

	type ebpfProg struct {
		progKey  uint32
		progName string
	}

	progs := []ebpfProg{
		{
			progKey:  MESH_DP_HANDSHAKE_PROG_ID,
			progName: MESH_DP_HANDSHAKE_PROG_NAME,
		},
		{
			progKey:  MESH_DP_CONNTRACK_PROG_ID,
			progName: MESH_DP_CONNTRACK_PROG_NAME,
		},
		{
			progKey:  MESH_DP_PASS_PROG_ID,
			progName: MESH_DP_PASS_PROG_NAME,
		},
		{
			progKey:  MESH_DP_DROP_PROG_ID,
			progName: MESH_DP_DROP_PROG_NAME,
		},
	}

	for _, prog := range progs {
		pinnedFile = path.Join(BPF_FS, MESH_PROG_NAME, prog.progName)
		pinnedProg, _ := ebpf.LoadPinnedProgram(pinnedFile, &ebpf.LoadPinOptions{})
		progFD := pinnedProg.FD()
		progsMap.Update(unsafe.Pointer(&prog.progKey), unsafe.Pointer(&progFD), ebpf.UpdateAny)
	}
}
