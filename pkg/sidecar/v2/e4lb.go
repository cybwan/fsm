package v2

import (
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/strings/slices"

	"github.com/flomesh-io/fsm/pkg/service"
	"github.com/flomesh-io/fsm/pkg/xnetwork/xnet/arp"
	"github.com/flomesh-io/fsm/pkg/xnetwork/xnet/maps"
	"github.com/flomesh-io/fsm/pkg/xnetwork/xnet/route"
	"github.com/flomesh-io/fsm/pkg/xnetwork/xnet/util"
)

func (s *Server) doConfigE4lbs() {
	e4lbSvcs := make(map[types.UID]*corev1.Service)
	e4lbEips := make(map[types.UID]string)
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

			eip := net.ParseIP(eipAdv.Spec.EIP)
			if eip == nil || eip.To4() == nil || eip.IsUnspecified() || eip.IsMulticast() {
				continue
			}

			e4lbSvcs[k8sSvc.GetUID()] = k8sSvc
			e4lbEips[k8sSvc.GetUID()] = eipAdv.Spec.EIP
		}
	}

	s.announceE4lbService(e4lbSvcs, e4lbEips)
}

func (s *Server) announceE4lbService(e4lbSvcs map[types.UID]*corev1.Service, e4lbEips map[types.UID]string) {
	if len(e4lbSvcs) == 0 {
		return
	}

	var defaultEth string
	var defaultHwAddr net.HardwareAddr
	if dev, _, err := route.DiscoverGateway(); err != nil {
		log.Error().Msg(err.Error())
		return
	} else if viaEth, err := netlink.LinkByName(dev); err != nil {
		log.Error().Msg(err.Error())
		return
	} else {
		defaultHwAddr = viaEth.Attrs().HardwareAddr
		defaultEth = dev
	}

	for uid, k8sSvc := range e4lbSvcs {
		eip, exists := e4lbEips[uid]
		if !exists {
			continue
		}
		if len(k8sSvc.Spec.ClusterIP) == 0 {
			continue
		}

		var ports []uint16
		for _, port := range k8sSvc.Spec.Ports {
			if !strings.EqualFold(string(port.Protocol), string(corev1.ProtocolTCP)) {
				continue
			}
			if port.Port > 0 && port.Port <= math.MaxUint16 {
				ports = append(ports, uint16(port.Port))
			}
			fmt.Println(k8sSvc.Namespace, k8sSvc.Name, k8sSvc.Spec.ClusterIP, port.Port)
		}
		if len(ports) == 0 {
			continue
		}

		for _, port := range ports {
			if err := s.setupE4lbServiceNat(eip, k8sSvc.Spec.ClusterIP, port); err != nil {
				log.Error().Msg(err.Error())
				continue
			}
		}

		fmt.Println("default device:", defaultEth, defaultHwAddr)
		if err := arp.Announce(defaultEth, eip, defaultHwAddr); err != nil {
			log.Error().Msg(err.Error())
		}
	}
}

func (s *Server) setupE4lbServiceNat(vip, eip string, port uint16) error {
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
	natKey.Daddr[0], _ = util.IPv4ToInt(net.ParseIP(vip))
	natKey.Dport = util.HostToNetShort(port)
	natKey.Proto = uint8(maps.IPPROTO_TCP)
	natVal := new(maps.NatVal)
	natVal.AddEp(net.ParseIP(eip), port, brVal.Mac[:], brVal.Ifi, maps.BPF_F_EGRESS, nil, true)
	for _, tcDir := range []maps.TcDir{maps.TC_DIR_IGR, maps.TC_DIR_EGR} {
		natKey.TcDir = uint8(tcDir)
		if err = maps.AddNatEntry(maps.SysE4lb, natKey, natVal); err != nil {
			return fmt.Errorf(`failed to store dns nat, vip: %s`, vip)
		}
	}

	return nil
}
