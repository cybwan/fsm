package main

import (
	"flag"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/flomesh-io/fsm/pkg/cni/bpf/emaps"
	"github.com/flomesh-io/fsm/pkg/cni/ns"
	"github.com/flomesh-io/fsm/pkg/cni/tc"
	"github.com/flomesh-io/fsm/pkg/logger"
)

var (
	log   = logger.New("fsm-ebpf-cli")
	flags = pflag.NewFlagSet(`fsm`, pflag.ExitOnError)
)

func attach() {
	nspath := `/run/netns/h1`
	netns, err := ns.GetNS(`/run/netns/h1`)
	if err != nil {
		log.Error().Err(err).Msgf("get ns %s error", nspath)
		return
	}

	err = netns.Do(func(_ ns.NetNS) error {
		return tc.AttachBpfProg(`eth0`, `sidecar`)
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
