package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"

	"github.com/flomesh-io/fsm/pkg/cni/bpf/emaps"
	"github.com/flomesh-io/fsm/pkg/cni/ns"
	"github.com/flomesh-io/fsm/pkg/cni/server/helpers"
	"github.com/flomesh-io/fsm/pkg/logger"
)

var (
	log   = logger.New("fsm-ebpf-cli")
	flags = pflag.NewFlagSet(`fsm`, pflag.ExitOnError)
)

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func stringPtr(v string) *string {
	return &v
}

func attachTC(dev string) error {
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		log.Error().Msgf("get iface error: %v", err)
		return err
	}
	rtnl, err := tc.Open(&tc.Config{})
	if err != nil {
		log.Error().Msgf("open rtnl error: %v", err)
		return err
	}
	defer func() {
		if err := rtnl.Close(); err != nil {
			log.Error().Msgf("could not close rtnetlink socket: %v\n", err)
		}
	}()
	qdiscs, err := rtnl.Qdisc().Get()
	if err != nil {
		log.Error().Msgf("get qdisc error: %v", err)
		return err
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
	ing := helpers.GetTrafficControlIngressProg()
	if ing == nil {
		return fmt.Errorf("can not get ingress prog")
	}

	filter := tc.Object{
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
				FD:    uint32Ptr(uint32(ing.FD())),
				Name:  stringPtr("tc_ingress"),
				Flags: uint32Ptr(0x1),
			},
		},
	}
	if err := rtnl.Filter().Add(&filter); err != nil {
		return err
	}
	egress := helpers.GetTrafficControlEgressProg()
	if ing == nil {
		return fmt.Errorf("can not get egress prog")
	}

	filter = tc.Object{
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
				FD:    uint32Ptr(uint32(egress.FD())),
				Name:  stringPtr("tc_egress"),
				Flags: uint32Ptr(0x1),
			},
		},
	}
	if err := rtnl.Filter().Add(&filter); err != nil {
		return err
	}

	return nil
}

func attach() {
	nspath := `/run/netns/h1`
	netns, err := ns.GetNS(`/run/netns/h1`)
	if err != nil {
		log.Error().Err(err).Msgf("get ns %s error", nspath)
		return
	}

	err = netns.Do(func(_ ns.NetNS) error {
		return attachTC(`eth0`)
	})

	if err != nil {
		log.Error().Err(err).Msgf("failed for %s: %v", nspath, err)
	}
}

var (
	action string
)

func init() {
	flags.StringVar(&action, "action", "", "action")
}

func parseFlags() error {
	if err := flags.Parse(os.Args); err != nil {
		return err
	}
	_ = flag.CommandLine.Parse([]string{})
	return nil
}

func main() {
	if err := parseFlags(); err != nil {
		log.Fatal().Err(err).Msg("Error parsing cmd line arguments")
	}
	if strings.EqualFold(action, `attach`) {
		attach()
	}
	if strings.EqualFold(action, `init-progs-map`) {
		emaps.InitFsmProgsMap()
	}
	if strings.EqualFold(action, `show-progs-map`) {
		emaps.ShowFsmProgsMap()
	}
	if strings.EqualFold(action, `init-nat-map`) {
		emaps.InitFsmNatMap()
	}
	if strings.EqualFold(action, `show-nat-map`) {
		emaps.ShowFsmNatMap()
	}
}
