package cli

import (
	"encoding/json"
	"fmt"

	ztm "github.com/cybwan/ztm-sdk-go"
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
		oldCache = make(map[string]*ServiceMetadata)
	}

	newCache := make(map[string]*ServiceMetadata)
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
		serviceMetadata := oldCache[serviceUID]
		if serviceMetadata == nil {
			serviceMetadata = new(ServiceMetadata)
		}

		endpoints := c.kubeProvider.ListEndpointsForService(svc)
		if len(endpoints) == 0 {
			continue
		}

		targets := make([]ztm.Target, 0)
		for _, ep := range endpoints {
			targets = append(targets, ztm.Target{Host: ep.IP.String(), Port: uint16(ep.Port)})
		}

		if hash, err := hashstructure.Hash(targets, hashstructure.FormatV2,
			&hashstructure.HashOptions{
				ZeroNil:         true,
				IgnoreZeroValue: true,
				SlicesAsSets:    true,
			}); err == nil {
			if hash != serviceMetadata.TargetsHash {
				if portErr := agentClient.OpenOutbound(ztmMesh,
					ztmEndpoint,
					ztm.ZTM,
					ztm.APP_TUNNEL,
					ztm.TCP,
					serviceUID,
					targets); portErr != nil {
					log.Error().Msg(portErr.Error())
				} else {
					serviceMetadata.TargetsHash = hash
				}
			}
		}

		meta := new(TunnelMeta)
		meta.ID = serviceUID
		meta.ClusterSet = c.GetClusterSet()
		meta.ServiceAccountName = serviceExport.Spec.ServiceAccountName
		meta.Namespace = service.Namespace
		meta.Name = service.Name
		meta.Ports = service.Spec.Ports

		if hash, err := hashstructure.Hash(meta, hashstructure.FormatV2,
			&hashstructure.HashOptions{
				ZeroNil:         true,
				IgnoreZeroValue: true,
				SlicesAsSets:    true,
			}); err == nil {
			if hash != serviceMetadata.TunnelMetaHash {
				if bytes, err := json.Marshal(meta); err == nil {
					err = agentClient.PublishFile(ztmMesh,
						fmt.Sprintf("/home/root/%s", serviceUID), bytes)
					if err != nil {
						log.Error().Msg(err.Error())
					} else {
						serviceMetadata.TunnelMetaHash = hash
					}
				}
			}
		}

		newCache[serviceUID] = serviceMetadata
		delete(oldCache, serviceUID)
	}

	if len(oldCache) > 0 {
		for serviceUID := range oldCache {
			if err := agentClient.EraseFile(ztmMesh, fmt.Sprintf("/home/root/%s", serviceUID)); err != nil {
				log.Error().Msg(err.Error())
			}

			if err := agentClient.CloseOutbound(ztmMesh,
				ztmEndpoint,
				ztm.ZTM,
				ztm.APP_TUNNEL,
				ztm.TCP,
				serviceUID); err != nil {
				log.Error().Msg(err.Error())
			}
		}
	}
}
