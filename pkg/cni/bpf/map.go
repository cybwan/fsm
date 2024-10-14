package bpf

import (
	"fmt"
	"path"

	"github.com/cilium/ebpf"
)

func InitFsmProgsMap() {
	pinnedProgs := path.Join(BPF_FS, MESH_PROG_NAME, FSM_PROGS_MAP_NAME)
	progsMap, _ := ebpf.LoadPinnedMap(pinnedProgs, &ebpf.LoadPinOptions{})
	fmt.Println(progsMap.String(), progsMap.FD())
}
