package cli

import (
	"fmt"

	ztm "github.com/cybwan/ztm-go-sdk"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/rs/zerolog/log"

	mcsv1alpha1 "github.com/flomesh-io/fsm/pkg/apis/multicluster/v1alpha1"
	ztmv1 "github.com/flomesh-io/fsm/pkg/apis/ztm/v1alpha1"
	fsminformers "github.com/flomesh-io/fsm/pkg/k8s/informers"
	"github.com/flomesh-io/fsm/pkg/service"
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
	agentPermit := new(ztm.Permit)
	agentPermit.Bootstraps = agentSpec.Permit.Bootstraps
	agentPermit.CA = agentSpec.Permit.Ca
	agentPermit.Agent.PrivateKey = agentSpec.Permit.Agent.PrivateKey
	agentPermit.Agent.Certificate = agentSpec.Permit.Agent.Certificate
	agentClient := ztm.NewAgentClient("127.0.0.1:7777")
	if len(agentSpec.JoinMeshes) > 0 {
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

			if localEndpoint != nil {
				serviceExports := c.informers.List(fsminformers.InformerKeyServiceExport)
				for _, serviceExportIf := range serviceExports {
					serviceExport := serviceExportIf.(*mcsv1alpha1.ServiceExport)
					svc := service.MeshService{
						Namespace: serviceExport.Namespace,
						Name:      serviceExport.Name,
					}
					endpoints := c.kubeProvider.ListEndpointsForService(svc)
					for _, endpoint := range endpoints {
						fmt.Println(serviceExport.Namespace, serviceExport.Name, endpoint.IP, endpoint.Port)
						//if err := agentClient.CreateEndpointService(
						//	mesh.MeshName,
						//	localEndpoint.UUID,
						//	constants.ProtocolTCP,
						//	svc.Name,
						//	endpoint.IP.String(),
						//	uint16(endpoint.Port)); err != nil {
						//	log.Error().Msg(err.Error())
						//}
					}
				}
			}
		}
	}
}
