package cli

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	ztm "github.com/cybwan/ztm-sdk-go"
	"github.com/mitchellh/hashstructure/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mcsv1alpha1 "github.com/flomesh-io/fsm/pkg/apis/multicluster/v1alpha1"
	ztmv1 "github.com/flomesh-io/fsm/pkg/apis/ztm/v1alpha1"
)

func (c *client) Refresh() {
	c.lock.Lock()
	defer c.lock.Unlock()

	if _, spec, uid, ok := c.GetAgent(); ok {
		if hash, err := hashstructure.Hash(spec, hashstructure.FormatV2,
			&hashstructure.HashOptions{
				ZeroNil:         true,
				IgnoreZeroValue: true,
				SlicesAsSets:    true,
			}); err == nil {
			if c.agentHash == hash {
				return
			}

			c.agentSpec = spec
			c.agentUID = uid
			c.agentHash = hash

			if len(c.cancelFuncs) > 0 {
				for _, cancelFunc := range c.cancelFuncs {
					cancelFunc()
				}
				c.cancelFuncs = nil
			}

			go c.startSync()
		}
	}
}

func (c *client) startSync() {
	agentSpec, agentOk := c.agentSpec.(ztmv1.AgentSpec)
	if !agentOk {
		return
	}
	if len(agentSpec.JoinMeshes) == 0 {
		return
	}

	agentPermit := new(ztm.Permit)
	agentPermit.Bootstraps = agentSpec.Permit.Bootstraps
	agentPermit.CA = agentSpec.Permit.Ca
	agentPermit.Agent.PrivateKey = agentSpec.Permit.Agent.PrivateKey
	agentPermit.Agent.Certificate = agentSpec.Permit.Agent.Certificate

	agentClient := ztm.NewAgentClient("127.0.0.1:7777", false)

	for _, mesh := range agentSpec.JoinMeshes {
		if joinErr := agentClient.Join(mesh.MeshName, c.GetClusterSet(), agentPermit); joinErr != nil {
			log.Error().Msg(joinErr.Error())
			continue
		}

		meshEndpoints, epErr := agentClient.ListEndpoints(mesh.MeshName)
		if epErr != nil {
			log.Error().Msg(epErr.Error())
			continue
		}

		var localEndpoint *ztm.Endpoint
		for _, meshEndpoint := range meshEndpoints {
			if meshEndpoint.Local {
				localEndpoint = meshEndpoint
				break
			}
		}
		if localEndpoint == nil {
			continue
		}

		if _, appErr := agentClient.StartApp(mesh.MeshName, localEndpoint.UUID, ztm.ZTM, ztm.APP_TUNNEL, ""); appErr != nil {
			log.Error().Msg(appErr.Error())
			continue
		}

		ctx, cancelFunc := context.WithCancel(context.Background())
		c.cancelFuncs = append(c.cancelFuncs, cancelFunc)
		go c.OutboundListener(ctx.Done(), mesh.MeshName, localEndpoint.UUID)

		for {
			// Inbound
			metadatas, metaErr := agentClient.ListFiles(mesh.MeshName)
			if metaErr != nil {
				log.Error().Msg(metaErr.Error())
				continue
			}

			for _, meta := range metadatas {
				content, fileErr := agentClient.DownloadFile(mesh.MeshName, meta.Name)
				if fileErr != nil {
					log.Error().Msg(fileErr.Error())
					continue
				}
				svcMeta := new(TunnelMeta)
				json.Unmarshal([]byte(content), svcMeta)
				if strings.EqualFold(svcMeta.ClusterSet, c.GetClusterSet()) {
					continue
				}

				ports := make([]mcsv1alpha1.ServicePort, 0)
				for _, p := range svcMeta.Ports {
					ports = append(ports, mcsv1alpha1.ServicePort{
						Name:        p.Name,
						Port:        p.Port,
						Protocol:    p.Protocol,
						AppProtocol: p.AppProtocol,
						Endpoints: []mcsv1alpha1.Endpoint{
							newEndpoint(svcMeta.ClusterSet,
								c.agentPod.Status.PodIP,
								c.agentPod.Status.PodIP,
								"/",
								p.TargetPort.IntVal),
						},
					})

					agentClient.OpenInbound(mesh.MeshName,
						localEndpoint.UUID,
						ztm.ZTM,
						ztm.APP_TUNNEL,
						ztm.TCP,
						svcMeta.ID,
						[]ztm.Listen{
							{
								IP:   c.agentPod.Status.PodIP,
								Port: uint16(p.TargetPort.IntVal),
							},
						})
				}

				serviceImport := mcsv1alpha1.ServiceImport{
					ObjectMeta: metav1.ObjectMeta{
						Name:      svcMeta.Name,
						Namespace: svcMeta.Namespace,
					},
					TypeMeta: metav1.TypeMeta{
						APIVersion: "multicluster.flomesh.io/v1alpha1",
						Kind:       "ServiceImport",
					},
					Spec: mcsv1alpha1.ServiceImportSpec{
						Type:               mcsv1alpha1.ClusterSetIP,
						Ports:              ports,
						ServiceAccountName: svcMeta.ServiceAccountName,
					},
				}

				c.mcsClient.MulticlusterV1alpha1().
					ServiceImports(svcMeta.Namespace).
					Create(context.TODO(), &serviceImport, metav1.CreateOptions{})
			}

			time.Sleep(time.Second * 5)
		}
	}
}

func newEndpoint(clusterKey, host, ip, path string, port int32) mcsv1alpha1.Endpoint {
	return mcsv1alpha1.Endpoint{
		ClusterKey: clusterKey,
		Target: mcsv1alpha1.Target{
			Host: host,
			IP:   ip,
			Port: port,
			Path: path,
		},
	}
}
