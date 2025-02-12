package v2

import (
	"fmt"
	"net"

	"github.com/libp2p/go-netroute"
)

func MatchRoute(dst string) error {
	nr, err := netroute.New()
	if err != nil {
		return err
	}
	iface, gateway, preferredSrc, err := nr.Route(net.ParseIP(dst))
	if err != nil {
		return err
	}

	fmt.Println("iface:", iface.Name)
	fmt.Println("gateway:", gateway)
	fmt.Println("preferredSrc:", preferredSrc)

	return nil
}
