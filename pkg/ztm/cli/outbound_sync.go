package cli

import (
	"encoding/json"
	"fmt"

	ztm "github.com/cybwan/ztm-sdk-go"
	"github.com/cybwan/ztm-sdk-go/app/tunnel"
	"github.com/mitchellh/hashstructure/v2"
	corev1 "k8s.io/api/core/v1"

	mcsv1alpha1 "github.com/flomesh-io/fsm/pkg/apis/multicluster/v1alpha1"
	fsminformers "github.com/flomesh-io/fsm/pkg/k8s/informers"
	"github.com/flomesh-io/fsm/pkg/service"
)

func (c *client) SyncOutbound(ztmMesh, ztmEndpoint string) {
	agentClient := ztm.NewAgentClient("127.0.0.1:7777", false)

	oldCache, exists := c.outboundCache[ztmMesh]
	if !exists {
		oldCache = make(map[string]*OutboundMetadata)
	}

	newCache := make(map[string]*OutboundMetadata)
	c.outboundCache[ztmMesh] = newCache

	serviceExports := c.informers.List(fsminformers.InformerKeyServiceExport)
	for _, serviceExportIf := range serviceExports {
		serviceExport := serviceExportIf.(*mcsv1alpha1.ServiceExport)
		svc := service.MeshService{
			Namespace: serviceExport.Namespace,
			Name:      serviceExport.Name,
		}

		svcIf, ok, svcErr := c.informers.GetByKey(fsminformers.InformerKeyService, svc.String())
		if svcErr != nil {
			continue
		}
		if !ok {
			continue
		}
		service := svcIf.(*corev1.Service)
		serviceUID := string(service.UID)
		outboundMetadata := oldCache[serviceUID]
		if outboundMetadata == nil {
			outboundMetadata = new(OutboundMetadata)
		}

		endpoints := c.kubeProvider.ListEndpointsForService(svc)
		if len(endpoints) == 0 {
			continue
		}

		meta := new(ServiceMetadata)
		meta.ID = serviceUID
		meta.ClusterSet = c.GetClusterSet()
		meta.ServiceAccountName = serviceExport.Spec.ServiceAccountName
		meta.Namespace = service.Namespace
		meta.Name = service.Name

		for _, rule := range serviceExport.Spec.Rules {
			targets := make([]ztm.Target, 0)
			for _, port := range service.Spec.Ports {
				if uint32(port.Port) == uint32(rule.PortNumber) {
					meta.Ports = append(meta.Ports, port)
					outboundMetadata.Ports = append(outboundMetadata.Ports, rule.PortNumber)
					for _, ep := range endpoints {
						if uint32(ep.Port) == uint32(port.TargetPort.IntVal) {
							targets = append(targets, ztm.Target{Host: ep.IP.String(), Port: uint16(ep.Port)})
						}
					}
					break
				}
			}

			if hash, err := hashstructure.Hash(targets, hashstructure.FormatV2,
				&hashstructure.HashOptions{
					ZeroNil:         true,
					IgnoreZeroValue: true,
					SlicesAsSets:    true,
				}); err == nil {
				if hash != outboundMetadata.TargetsHash {
					if portErr := agentClient.OpenOutbound(ztmMesh,
						ztmEndpoint,
						ztm.ZTM,
						tunnel.APP,
						ztm.TCP,
						fmt.Sprintf("%s_%d", serviceUID, rule.PortNumber),
						targets); portErr != nil {
						log.Error().Msg(portErr.Error())
					} else {
						outboundMetadata.TargetsHash = hash
					}
				}
			}
		}

		if hash, err := hashstructure.Hash(meta, hashstructure.FormatV2,
			&hashstructure.HashOptions{
				ZeroNil:         true,
				IgnoreZeroValue: true,
				SlicesAsSets:    true,
			}); err == nil {
			if hash != outboundMetadata.TunnelMetaHash {
				if bytes, err := json.MarshalIndent(meta, "", " "); err == nil {
					err = agentClient.PublishFile(ztmMesh,
						fmt.Sprintf("/%s/root/%s", ztm.BaseFolder, serviceUID), bytes)
					if err != nil {
						log.Error().Msg(err.Error())
					} else {
						outboundMetadata.TunnelMetaHash = hash
					}
				}
			}
		}

		newCache[serviceUID] = outboundMetadata
		delete(oldCache, serviceUID)
	}

	if len(oldCache) > 0 {
		for serviceUID, outboundMetadata := range oldCache {
			if err := agentClient.EraseFile(ztmMesh, fmt.Sprintf("%s/root/%s", ztm.BaseFolder, serviceUID)); err != nil {
				log.Error().Msg(err.Error())
			}

			for _, port := range outboundMetadata.Ports {
				if err := agentClient.CloseOutbound(ztmMesh,
					ztmEndpoint,
					ztm.ZTM,
					tunnel.APP,
					ztm.TCP,
					fmt.Sprintf("%s_%d", serviceUID, port)); err != nil {
					log.Error().Msg(err.Error())
				}
			}
		}
	}
}
