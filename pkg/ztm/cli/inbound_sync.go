package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	ztm "github.com/cybwan/ztm-sdk-go"
	"github.com/mitchellh/hashstructure/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mcsv1alpha1 "github.com/flomesh-io/fsm/pkg/apis/multicluster/v1alpha1"
	fsminformers "github.com/flomesh-io/fsm/pkg/k8s/informers"
)

var (
	startPortNum = int32(10000)
)

func (c *client) allocInboundPort() int32 {
	c.lock.Lock()
	defer c.lock.Unlock()
	startPortNum++
	return startPortNum
}

func (c *client) SyncInbound(ztmMesh, ztmEndpoint string) {
	agentClient := ztm.NewAgentClient("127.0.0.1:7777", false)

	cache, exists := c.inboundCache[ztmMesh]
	if !exists {
		cache = new(InboundMetadata)
		cache.tunnelCache = make(map[string]*TunnelMetadata)
		cache.importCache = make(map[string]uint64)
		c.inboundCache[ztmMesh] = cache
	}

	if metadatas, metaErr := agentClient.ListFiles(ztmMesh); metaErr == nil {
		for _, meta := range metadatas {
			serviceUID := strings.TrimPrefix(meta.Name, "/home/root/")
			desc, descErr := agentClient.DescribeFile(ztmMesh, meta.Name)
			if descErr != nil {
				log.Error().Msg(descErr.Error())
				continue
			}

			oldTunnelCache := cache.tunnelCache
			newTunnelCache := make(map[string]*TunnelMetadata)

			tunnelMetadata := oldTunnelCache[serviceUID]
			if tunnelMetadata == nil {
				tunnelMetadata = new(TunnelMetadata)
				tunnelMetadata.Inbounds = make(map[string]int32)
			}

			if strings.EqualFold(tunnelMetadata.Hash, desc.Hash) {
				newTunnelCache[serviceUID] = tunnelMetadata
				delete(oldTunnelCache, serviceUID)
				continue
			}

			content, fileErr := agentClient.DownloadFile(ztmMesh, meta.Name)
			if fileErr != nil {
				log.Error().Msg(fileErr.Error())
				continue
			}

			serviceMetadata := new(ServiceMetadata)
			if err := json.Unmarshal([]byte(content), serviceMetadata); err != nil {
				continue
			}

			if strings.EqualFold(serviceMetadata.ClusterSet, c.GetClusterSet()) {
				continue
			}

			if ns := c.k8sController.GetNamespace(serviceMetadata.Namespace); ns == nil {
				continue
			}

			oldInboundCache := tunnelMetadata.Inbounds
			newInboundCache := make(map[string]int32)

			for _, port := range serviceMetadata.Ports {
				inbound := fmt.Sprintf("%s_%d", serviceMetadata.ID, port.Port)
				targetPort, exists := oldInboundCache[inbound]
				if exists {
					newInboundCache[inbound] = targetPort
					delete(oldInboundCache, inbound)
				} else {
					targetPort = c.allocInboundPort()
					newInboundCache[inbound] = targetPort

					if err := agentClient.OpenInbound(ztmMesh,
						ztmEndpoint,
						ztm.ZTM,
						ztm.APP_TUNNEL,
						ztm.TCP,
						inbound,
						[]ztm.Listen{
							{
								IP:   c.agentPod.Status.PodIP,
								Port: uint16(targetPort),
							},
						}); err != nil {
						log.Error().Msg(err.Error())
					}
				}
			}

			if len(oldInboundCache) > 0 {
				for inbound := range oldInboundCache {
					if err := agentClient.CloseInbound(ztmMesh,
						ztmEndpoint,
						ztm.ZTM,
						ztm.APP_TUNNEL,
						ztm.TCP,
						inbound); err != nil {
						log.Error().Msg(err.Error())
					}
				}
			}

			tunnelMetadata.ServiceMetadata = serviceMetadata
			tunnelMetadata.Inbounds = newInboundCache
			newTunnelCache[serviceUID] = tunnelMetadata
			cache.tunnelCache = newTunnelCache
		}
	}

	services := make(map[string]map[string][]int32)

	for _, tunnelMetadata := range cache.tunnelCache {
		svcCache, exists := services[tunnelMetadata.ServiceMetadata.Namespace]
		if !exists {
			svcCache = make(map[string][]int32)
			services[tunnelMetadata.ServiceMetadata.Namespace] = svcCache
		}

		portCache, exists := svcCache[tunnelMetadata.ServiceMetadata.Name]
		if !exists {
			portCache = make([]int32, 0)
			svcCache[tunnelMetadata.ServiceMetadata.Name] = portCache
		}
		for _, port := range tunnelMetadata.ServiceMetadata.Ports {
			exists := false
			for _, pnum := range portCache {
				if pnum == port.Port {
					exists = true
					break
				}
			}
			if !exists {
				portCache = append(portCache, port.Port)
				svcCache[tunnelMetadata.ServiceMetadata.Name] = portCache
			}
		}
	}

	oldImportCache := cache.importCache
	newImportCache := make(map[string]uint64)
	for ns, svcCache := range services {
		for svc, portCache := range svcCache {
			serviceImport := mcsv1alpha1.ServiceImport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: ns,
					Name:      svc,
				},
				TypeMeta: metav1.TypeMeta{
					APIVersion: "multicluster.flomesh.io/v1alpha1",
					Kind:       "ServiceImport",
				},
				Spec: mcsv1alpha1.ServiceImportSpec{
					Type: mcsv1alpha1.ClusterSetIP,
				},
			}

			ports := make([]mcsv1alpha1.ServicePort, 0)
			for _, portNum := range portCache {
				var servicePort *mcsv1alpha1.ServicePort = nil
				for _, tunnelMetadata := range cache.tunnelCache {
					if strings.EqualFold(tunnelMetadata.ServiceMetadata.Namespace, ns) &&
						strings.EqualFold(tunnelMetadata.ServiceMetadata.Name, svc) {
						for _, port := range tunnelMetadata.ServiceMetadata.Ports {
							if port.Port == portNum {
								if servicePort == nil {
									servicePort = new(mcsv1alpha1.ServicePort)
									servicePort.Name = port.Name
									servicePort.Port = port.Port
									servicePort.Protocol = port.Protocol
									servicePort.AppProtocol = port.AppProtocol
									serviceImport.Spec.ServiceAccountName = tunnelMetadata.ServiceMetadata.ServiceAccountName
								}
								inbound := fmt.Sprintf("%s_%d", tunnelMetadata.ServiceMetadata.ID, port.Port)
								targetPort, exists := tunnelMetadata.Inbounds[inbound]
								if exists {
									servicePort.Endpoints = append(servicePort.Endpoints,
										newEndpoint(tunnelMetadata.ServiceMetadata.ClusterSet,
											c.agentPod.Status.PodIP,
											c.agentPod.Status.PodIP,
											"/",
											targetPort),
									)
								}
								break
							}
						}
					}
				}
				if servicePort != nil {
					ports = append(ports, *servicePort)
				}
			}

			serviceImport.Spec.Ports = ports

			importName := fmt.Sprintf("%s/%s", ns, svc)
			importHash := oldImportCache[importName]
			if hash, err := hashstructure.Hash(serviceImport, hashstructure.FormatV2,
				&hashstructure.HashOptions{
					ZeroNil:         true,
					IgnoreZeroValue: true,
					SlicesAsSets:    true,
				}); err == nil {
				if hash == importHash {
					newImportCache[importName] = hash
					delete(oldImportCache, importName)
					continue
				}
			}

			impIf, _, impErr := c.informers.GetByKey(fsminformers.InformerKeyServiceImport, importName)

			if impErr != nil {
				continue
			}

			if impIf != nil {
				importSvc := impIf.(*mcsv1alpha1.ServiceImport)
				importSvc.Spec.Ports = serviceImport.Spec.Ports
				importSvc.Spec.ServiceAccountName = serviceImport.Spec.ServiceAccountName
				if _, err := c.mcsClient.MulticlusterV1alpha1().
					ServiceImports(ns).Update(context.TODO(), importSvc, metav1.UpdateOptions{}); err != nil {
					log.Error().Msg(err.Error())
				}
			} else {
				if _, err := c.mcsClient.MulticlusterV1alpha1().
					ServiceImports(ns).
					Create(context.TODO(), &serviceImport, metav1.CreateOptions{}); err != nil {
					log.Error().Msg(err.Error())
				}
			}
		}
	}

	if len(oldImportCache) > 0 {
		for importName := range oldImportCache {
			segs := strings.Split(importName, "/")
			if err := c.mcsClient.MulticlusterV1alpha1().
				ServiceImports(segs[0]).Delete(context.TODO(), segs[1], metav1.DeleteOptions{}); err != nil {
				log.Error().Msg(err.Error())
			}
		}
	}

	cache.importCache = newImportCache
}
