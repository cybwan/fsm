// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package gen

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfDpCtCtrtact struct {
	Ca struct {
		ActType uint8
		Ftrap   uint8
		Oaux    uint16
		Cidx    uint32
		Fwrid   uint32
		Mark    uint16
		Record  uint16
	}
	Lock    struct{ Val uint32 }
	Start   uint32
	Counter uint32
	Entries uint32
}

type bpfDpCtKey struct {
	Daddr [4]uint32
	Saddr [4]uint32
	Sport uint16
	Dport uint16
	Zone  uint16
	Proto uint8
	V6    uint8
}

type bpfDpCtTact struct {
	Ca struct {
		ActType uint8
		Ftrap   uint8
		Oaux    uint16
		Cidx    uint32
		Fwrid   uint32
		Mark    uint16
		Record  uint16
	}
	Lock struct{ Val uint32 }
	_    [4]byte
	Ctd  struct {
		Rid uint16
		Aid uint16
		Nid uint32
		Pi  struct {
			T struct {
				State  uint32
				Fndir  uint32
				TcpCts [2]struct {
					Hstate   uint16
					InitAcks uint16
					Seq      uint32
					Pack     uint32
					Pseq     uint32
				}
			}
			Frag  uint16
			Npmhh uint16
			Pmhh  [4]uint32
			L3i   struct{ State uint32 }
		}
		Dir uint32
		Smr uint32
		Xi  struct {
			NatFlags uint8
			Nv6      uint8
			NatXifi  uint16
			NatXport uint16
			NatRport uint16
			NatXip   [4]uint32
			NatRip   [4]uint32
			NatXmac  [6]uint8
			NatRmac  [6]uint8
			Inactive uint8
			_        [3]byte
		}
		Pb struct {
			Bytes   uint64
			Packets uint64
		}
	}
	Ito     uint64
	Lts     uint64
	PortAct struct {
		Oport uint16
		Fr    uint16
	}
	_ [60]byte
}

type bpfDpDnatOptKey struct {
	Xaddr uint32
	Xport uint16
	Proto uint8
	V6    uint8
}

type bpfDpDnatOptTact struct {
	Daddr uint32
	Saddr uint32
	Dport uint16
	Sport uint16
	_     [4]byte
	Ts    uint64
}

type bpfDpSnatOptKey struct {
	Daddr uint32
	Saddr uint32
	Dport uint16
	Sport uint16
	Proto uint8
	V6    uint8
	_     [2]byte
}

type bpfDpSnatOptTact struct {
	Xaddr uint32
	Xport uint16
	_     [2]byte
}

type bpfXpkt struct {
	Skb struct {
		Data    uint32
		DataEnd uint32
	}
	L2 struct {
		Vlan    [3]uint16
		DlType  uint16
		DlDst   [6]uint8
		DlSrc   [6]uint8
		VlanPcp uint8
		Valid   uint8
		Ssnid   uint16
	}
	L34 struct {
		Tos    uint8
		Proto  uint8
		Valid  uint8
		Frg    uint8
		Source uint16
		Dest   uint16
		Seq    uint32
		Ack    uint32
		Saddr  [4]uint32
		Daddr  [4]uint32
	}
	Il2 struct {
		Vlan    [3]uint16
		DlType  uint16
		DlDst   [6]uint8
		DlSrc   [6]uint8
		VlanPcp uint8
		Valid   uint8
		Ssnid   uint16
	}
	Il34 struct {
		Tos    uint8
		Proto  uint8
		Valid  uint8
		Frg    uint8
		Source uint16
		Dest   uint16
		Seq    uint32
		Ack    uint32
		Saddr  [4]uint32
		Daddr  [4]uint32
	}
	Nat struct {
		Nxip       [4]uint32
		Nrip       [4]uint32
		Nxport     uint16
		Nrport     uint16
		Nxifi      uint16
		Nxmac      [6]uint8
		Nrmac      [6]uint8
		CtSts      uint8
		SelAid     uint8
		Nv6        uint8
		XlateProto uint8
		_          [2]byte
		Ito        uint64
	}
	Ctx struct {
		Bd        uint16
		PyBytes   uint16
		Act       uint8
		L3Off     uint8
		Phit      uint16
		NhNum     uint16
		QosId     uint16
		Rcode     uint32
		Ifi       uint32
		_         [1]byte /* unsupported bitfield */
		Tc        uint8
		Pprop     uint8
		LkupDmac  [6]uint8
		Iport     uint16
		Oport     uint16
		Zone      uint16
		L4Off     uint8
		TableId   uint8
		Sseid     uint64
		Dseid     uint64
		Mirr      uint16
		TcpFlags  uint8
		Nf        uint8
		RuleId    uint16
		L3Adj     int16
		Il3Off    uint8
		Il4Off    uint8
		ItcpFlags uint8
		_         [1]byte /* unsupported bitfield */
		L3Len     uint16
		L3Plen    uint16
		Il3Len    uint16
		Il3Plen   uint16
		DpMark    uint16
		DpRec     uint16
		TunOff    uint16
		FwMid     uint16
		FwLid     uint16
		FwRid     uint16
	}
}

type bpfXpktFib4Key struct {
	Daddr uint32
	Saddr uint32
	Sport uint16
	Dport uint16
	Ifi   uint16
	Proto uint8
	Pad   uint8
}

type bpfXpktFib4Ops struct {
	Ca struct {
		ActType uint8
		Ftrap   uint8
		Oaux    uint16
		Cidx    uint32
		Fwrid   uint32
		Mark    uint16
		Record  uint16
	}
	Its  uint64
	Zone uint32
	Ops  [7]struct {
		Ca struct {
			ActType uint8
			Ftrap   uint8
			Oaux    uint16
			Cidx    uint32
			Fwrid   uint32
			Mark    uint16
			Record  uint16
		}
		PortAct struct {
			Oport uint16
			Fr    uint16
		}
		_ [60]byte
	}
	_ [4]byte
}

type bpfXpktNatKey struct {
	Daddr [4]uint32
	Dport uint16
	Zone  uint16
	Mark  uint16
	Proto uint8
	V6    uint8
}

type bpfXpktNatOps struct {
	Ito       uint64
	Pto       uint64
	Lock      struct{ Val uint32 }
	NatType   uint8
	_         [1]byte
	LbAlgo    uint16
	EpSel     uint16
	EpCnt     uint16
	Endpoints [16]struct {
		NatFlags uint8
		Nv6      uint8
		NatXifi  uint16
		NatXport uint16
		NatRport uint16
		NatXip   [4]uint32
		NatRip   [4]uint32
		NatXmac  [6]uint8
		NatRmac  [6]uint8
		Inactive uint8
		_        [3]byte
	}
	_ [4]byte
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	SidecarEgress   *ebpf.ProgramSpec `ebpf:"sidecar_egress"`
	SidecarIngress  *ebpf.ProgramSpec `ebpf:"sidecar_ingress"`
	TcConnTrackFunc *ebpf.ProgramSpec `ebpf:"tc_conn_track_func"`
	TcDrop          *ebpf.ProgramSpec `ebpf:"tc_drop"`
	TcHandShakeFunc *ebpf.ProgramSpec `ebpf:"tc_hand_shake_func"`
	TcPass          *ebpf.ProgramSpec `ebpf:"tc_pass"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	FsmCt      *ebpf.MapSpec `ebpf:"fsm_ct"`
	FsmCtCtr   *ebpf.MapSpec `ebpf:"fsm_ct_ctr"`
	FsmCtKey   *ebpf.MapSpec `ebpf:"fsm_ct_key"`
	FsmDnatOpt *ebpf.MapSpec `ebpf:"fsm_dnat_opt"`
	FsmEgrIpv4 *ebpf.MapSpec `ebpf:"fsm_egr_ipv4"`
	FsmFib4    *ebpf.MapSpec `ebpf:"fsm_fib4"`
	FsmFib4Key *ebpf.MapSpec `ebpf:"fsm_fib4_key"`
	FsmFib4Ops *ebpf.MapSpec `ebpf:"fsm_fib4_ops"`
	FsmIgrIpv4 *ebpf.MapSpec `ebpf:"fsm_igr_ipv4"`
	FsmNat     *ebpf.MapSpec `ebpf:"fsm_nat"`
	FsmProgs   *ebpf.MapSpec `ebpf:"fsm_progs"`
	FsmSnatOpt *ebpf.MapSpec `ebpf:"fsm_snat_opt"`
	FsmXpkts   *ebpf.MapSpec `ebpf:"fsm_xpkts"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	FsmCt      *ebpf.Map `ebpf:"fsm_ct"`
	FsmCtCtr   *ebpf.Map `ebpf:"fsm_ct_ctr"`
	FsmCtKey   *ebpf.Map `ebpf:"fsm_ct_key"`
	FsmDnatOpt *ebpf.Map `ebpf:"fsm_dnat_opt"`
	FsmEgrIpv4 *ebpf.Map `ebpf:"fsm_egr_ipv4"`
	FsmFib4    *ebpf.Map `ebpf:"fsm_fib4"`
	FsmFib4Key *ebpf.Map `ebpf:"fsm_fib4_key"`
	FsmFib4Ops *ebpf.Map `ebpf:"fsm_fib4_ops"`
	FsmIgrIpv4 *ebpf.Map `ebpf:"fsm_igr_ipv4"`
	FsmNat     *ebpf.Map `ebpf:"fsm_nat"`
	FsmProgs   *ebpf.Map `ebpf:"fsm_progs"`
	FsmSnatOpt *ebpf.Map `ebpf:"fsm_snat_opt"`
	FsmXpkts   *ebpf.Map `ebpf:"fsm_xpkts"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.FsmCt,
		m.FsmCtCtr,
		m.FsmCtKey,
		m.FsmDnatOpt,
		m.FsmEgrIpv4,
		m.FsmFib4,
		m.FsmFib4Key,
		m.FsmFib4Ops,
		m.FsmIgrIpv4,
		m.FsmNat,
		m.FsmProgs,
		m.FsmSnatOpt,
		m.FsmXpkts,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	SidecarEgress   *ebpf.Program `ebpf:"sidecar_egress"`
	SidecarIngress  *ebpf.Program `ebpf:"sidecar_ingress"`
	TcConnTrackFunc *ebpf.Program `ebpf:"tc_conn_track_func"`
	TcDrop          *ebpf.Program `ebpf:"tc_drop"`
	TcHandShakeFunc *ebpf.Program `ebpf:"tc_hand_shake_func"`
	TcPass          *ebpf.Program `ebpf:"tc_pass"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.SidecarEgress,
		p.SidecarIngress,
		p.TcConnTrackFunc,
		p.TcDrop,
		p.TcHandShakeFunc,
		p.TcPass,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfel.o
var _BpfBytes []byte
