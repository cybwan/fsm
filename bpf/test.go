package main

import (
	"fmt"

	"github.com/flomesh-io/fsm/pkg/cni/ns"
	"github.com/flomesh-io/fsm/pkg/logger"
)

var (
	log = logger.New("test")
)

func main() {
	netns, err := ns.GetNS(`/run/netns/h1`)
	if err != nil {
		log.Error().Err(err).Msgf("get ns %s error", `/run/netns/h1`)
		return
	}
	fmt.Println(netns)
}
