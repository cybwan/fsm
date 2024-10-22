package tc

import (
	"fmt"
	"net"
	"path"

	"github.com/cilium/ebpf"
	"github.com/flomesh-io/fsm/pkg/cni/bpf"
	"github.com/flomesh-io/fsm/pkg/logger"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

var (
	log = logger.New("fsm-cni-tc")
)

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func stringPtr(v string) *string {
	return &v
}

func getSidecarIngressProgFD() (int, error) {
	pinnedFile := path.Join(bpf.BPF_FS, bpf.FSM_PROG_NAME, bpf.FSM_CNI_SIDECAR_INGRESS_PROG_NAME)
	if pinnedProg, progErr := ebpf.LoadPinnedProgram(pinnedFile, &ebpf.LoadPinOptions{}); progErr == nil {
		return pinnedProg.FD(), nil
	} else {
		return -1, progErr
	}
}

func getSidecarEgressProgFD() (int, error) {
	pinnedFile := path.Join(bpf.BPF_FS, bpf.FSM_PROG_NAME, bpf.FSM_CNI_SIDECAR_EGRESS_PROG_NAME)
	if pinnedProg, progErr := ebpf.LoadPinnedProgram(pinnedFile, &ebpf.LoadPinOptions{}); progErr == nil {
		return pinnedProg.FD(), nil
	} else {
		return -1, progErr
	}
}

func AttachBpfProg(dev, name string) error {
	iface, ifaceErr := net.InterfaceByName(dev)
	if ifaceErr != nil {
		log.Error().Msgf("get iface error: %v", ifaceErr)
		return ifaceErr
	}

	rtnl, rtnlErr := tc.Open(&tc.Config{})
	if rtnlErr != nil {
		log.Error().Msgf("open rtnl error: %v", rtnlErr)
		return rtnlErr
	}

	defer func() {
		if err := rtnl.Close(); err != nil {
			log.Error().Msgf("could not close rtnetlink socket: %v\n", err)
		}
	}()

	ingressProgFD, ingressProgFDErr := getSidecarIngressProgFD()
	if ingressProgFDErr != nil {
		log.Error().Msgf("fail to load sidecar ingress prog: %v", ingressProgFDErr)
		return ingressProgFDErr
	}

	egressProgFD, egressProgFDErr := getSidecarEgressProgFD()
	if egressProgFDErr != nil {
		log.Error().Msgf("fail to load sidecar egress prog: %v", egressProgFDErr)
		return egressProgFDErr
	}

	qdiscs, qdiscErr := rtnl.Qdisc().Get()
	if qdiscErr != nil {
		log.Error().Msgf("get qdisc error: %v", qdiscErr)
		return qdiscErr
	}

	find := false
	for _, qdisc := range qdiscs {
		if qdisc.Kind == "clsact" && qdisc.Ifindex == uint32(iface.Index) {
			find = true
			break
		}
	}
	if !find {
		// init clasact if not exists
		err := rtnl.Qdisc().Add(&tc.Object{
			Msg: tc.Msg{
				Family:  unix.AF_UNSPEC,
				Ifindex: uint32(iface.Index),
				Handle:  core.BuildHandle(0xFFFF, 0x0000),
				Parent:  tc.HandleIngress,
			},
			Attribute: tc.Attribute{
				Kind: "clsact",
			},
		})
		if err != nil {
			return err
		}
	}

	ingressFilter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			// Handle:  0,
			Parent: 0xFFFFFFF2, // ingress
			Info: core.BuildHandle(
				66,     // prio
				0x0300, // protocol
			),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    uint32Ptr(uint32(ingressProgFD)),
				Name:  stringPtr(fmt.Sprintf("%s_ingress", name)),
				Flags: uint32Ptr(0x1),
			},
		},
	}
	if err := rtnl.Filter().Add(&ingressFilter); err != nil {
		return err
	}

	egressFilter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			// Handle:  0,
			Parent: 0xFFFFFFF3, // egress
			Info: core.BuildHandle(
				66,     // prio
				0x0300, // protocol
			),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    uint32Ptr(uint32(egressProgFD)),
				Name:  stringPtr(fmt.Sprintf("%s_egress", name)),
				Flags: uint32Ptr(0x1),
			},
		},
	}
	if err := rtnl.Filter().Add(&egressFilter); err != nil {
		return err
	}

	return nil
}
