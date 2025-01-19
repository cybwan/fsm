package v2

import (
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"k8s.io/utils/strings/slices"

	"github.com/flomesh-io/fsm/pkg/service"
	"github.com/flomesh-io/fsm/pkg/xnetwork/xnet/maps"
	"github.com/flomesh-io/fsm/pkg/xnetwork/xnet/util"
)

func (s *Server) doConfigE4lbs() {
	eipAdvs := s.xnetworkController.GetEIPAdvertisements()
	if len(eipAdvs) > 0 {
		for _, eipAdv := range eipAdvs {
			if !slices.Contains(eipAdv.Spec.Nodes, s.nodeName) {
				continue
			}

			meshSvc := service.MeshService{Name: eipAdv.Spec.Service.Name}
			if len(eipAdv.Spec.Service.Namespace) > 0 {
				meshSvc.Namespace = eipAdv.Spec.Service.Namespace
			} else {
				meshSvc.Namespace = eipAdv.Namespace
			}
			k8sSvc := s.kubeController.GetService(meshSvc)
			if k8sSvc == nil {
				continue
			}

			fmt.Println(k8sSvc.Namespace, k8sSvc.Name, k8sSvc.Spec.ClusterIP)

			eip := net.ParseIP(eipAdv.Spec.EIP)
			if eip == nil {
				continue
			}

			if eip.To4() == nil {
				continue
			}

			lnk, err := netlink.LinkByName("flb0")
			if err != nil {
				log.Error().Err(err)
			}

			ipConfig := &netlink.Addr{IPNet: &net.IPNet{
				IP:   eip,
				Mask: net.CIDRMask(32, 32),
			}}

			if err = netlink.AddrAdd(lnk, ipConfig); err != nil {
				log.Error().Err(err)
			}
		}
	}
}

func (s *Server) setupE4lbNat(eip string) {
	var err error
	var brVal *maps.IFaceVal
	brKey := new(maps.IFaceKey)
	brKey.Len = uint8(len(bridgeDev))
	copy(brKey.Name[0:brKey.Len], bridgeDev)
	for {
		brVal, err = maps.GetIFaceEntry(brKey)
		if err != nil {
			log.Error().Err(err).Msg(`failed to get node bridge info`)
			time.Sleep(time.Second * 5)
			continue
		}
		if brVal == nil {
			log.Error().Msg(`failed to get node bridge info`)
			time.Sleep(time.Second * 5)
			continue
		}
		break
	}

	natKey := new(maps.NatKey)
	natKey.Dport = util.HostToNetShort(53)
	natKey.Proto = uint8(maps.IPPROTO_TCP)
	natVal := new(maps.NatVal)
	natVal.AddEp(net.ParseIP(eip), 53, brVal.Mac[:], false)
	for _, tcDir := range []maps.TcDir{maps.TC_DIR_IGR, maps.TC_DIR_EGR} {
		natKey.TcDir = uint8(tcDir)
		if err = maps.AddNatEntry(maps.SysE4lb, natKey, natVal); err != nil {
			log.Fatal().Err(err).Msg(`failed to store dns nat`)
		}
	}
}
