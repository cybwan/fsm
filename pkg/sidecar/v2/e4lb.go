package v2

import (
    "fmt"
    "math"
    "net"
    "strings"
    "time"

    "github.com/vishvananda/netlink"
    corev1 "k8s.io/api/core/v1"
    "k8s.io/utils/strings/slices"

    "github.com/flomesh-io/fsm/pkg/service"
    "github.com/flomesh-io/fsm/pkg/xnetwork/xnet/arp"
    "github.com/flomesh-io/fsm/pkg/xnetwork/xnet/maps"
    "github.com/flomesh-io/fsm/pkg/xnetwork/xnet/route"
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
                fmt.Println(1)
                continue
            }

            eip := net.ParseIP(eipAdv.Spec.EIP)
            if eip == nil {
                fmt.Println(2)
                continue
            }

            if eip.To4() == nil {
                fmt.Println(3)
                continue
            }

            for _, port := range ports {
                if err := s.setupE4lbNat(eipAdv.Spec.EIP, k8sSvc.Spec.ClusterIP, port); err != nil {
                    log.Error().Err(err)
                    fmt.Println(4)
                    continue
                }
            }

            lbEth, err := netlink.LinkByName("flb0")
            if err != nil {
                log.Error().Err(err)
                fmt.Println(5)
                continue
            }

            ipConfig := &netlink.Addr{IPNet: &net.IPNet{
                IP:   eip,
                Mask: net.CIDRMask(32, 32),
            }}

            if err = netlink.AddrAdd(lbEth, ipConfig); err != nil {
                log.Error().Err(err).Msgf("fail to add addr:%s to dev:%s", eip, lbEth.Attrs().Name)
                fmt.Println(6)
                //continue
            }

            dev, _, _ := route.DiscoverGateway()
            viaEth, err := netlink.LinkByName(dev)
            if err != nil {
                log.Error().Err(err)
                fmt.Println(7)
                continue
            }
            fmt.Println("default device:", dev, viaEth.Attrs().HardwareAddr)
            err = arp.Announce(dev, eipAdv.Spec.EIP, viaEth.Attrs().HardwareAddr)
            if err != nil {
                log.Error().Err(err)
                fmt.Println(8)
            }
        }
    }
}

func (s *Server) setupE4lbNat(vip, eip string, port uint16) error {
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
