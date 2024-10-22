package emaps

import (
	"encoding/json"
	"fmt"
	"path"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/flomesh-io/fsm/pkg/cni/bpf"
	"github.com/flomesh-io/fsm/pkg/cni/bpf/gen"
)

func InitFsmNatMap() {
	pinnedFile := path.Join(bpf.BPF_FS, bpf.FSM_PROG_NAME, bpf.FSM_MAP_NAME_NAT)
	natMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
	}

	defer natMap.Close()

	natKey := gen.FsmNatKeyT{}
	natOps := gen.FsmNatOpsT{}
	if err := natMap.Update(unsafe.Pointer(&natKey), unsafe.Pointer(&natOps), ebpf.UpdateAny); err != nil {
		log.Fatal().Err(err).Msgf("failed to update ebpf map: %s", bpf.FSM_MAP_NAME_NAT)
	}
}

func ShowFsmNatMap() {
	pinnedFile := path.Join(bpf.BPF_FS, bpf.FSM_PROG_NAME, bpf.FSM_MAP_NAME_NAT)
	natMap, mapErr := ebpf.LoadPinnedMap(pinnedFile, &ebpf.LoadPinOptions{})
	if mapErr != nil {
		log.Fatal().Err(mapErr).Msgf("failed to load ebpf map: %s", pinnedFile)
	}
	defer natMap.Close()

	natKey := gen.FsmNatKeyT{}
	natOps := gen.FsmNatOpsT{}
	it := natMap.Iterate()
	for it.Next(unsafe.Pointer(&natKey), unsafe.Pointer(&natOps)) {
		keyBytes, _ := json.MarshalIndent(natKey, "", " ")
		opsBytes, _ := json.MarshalIndent(natOps, "", " ")
		fmt.Printf(`{"key":%s,"value":%s}`, string(keyBytes), string(opsBytes))
		fmt.Println()
	}
}
