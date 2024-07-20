package cli

import (
	"github.com/mitchellh/hashstructure/v2"
	"github.com/rs/zerolog/log"

	ztm "github.com/cybwan/ztm-go-sdk"

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
			meshEndpoints, epErr := agentClient.ListMeshEndpoints(mesh.MeshName)
			if epErr != nil {
				log.Error().Msg(epErr.Error())
				continue
			}

			var localEndpoint *ztm.MeshEndpoint
			for _, meshEndpoint := range meshEndpoints {
				if meshEndpoint.IsLocal {
					localEndpoint = meshEndpoint
					break
				}
			}

			if localEndpoint != nil {
				for _, service := range mesh.ServiceExports {
					if err := agentClient.CreateEndpointService(
						mesh.MeshName,
						localEndpoint.UUID,
						service.Protocol,
						service.ServiceName,
						service.IP,
						service.Port); err != nil {
						log.Error().Msg(err.Error())
					}
				}
				for _, service := range mesh.ServiceImports {
					if err := agentClient.CreateEndpointPort(
						mesh.MeshName,
						localEndpoint.UUID,
						service.Protocol,
						service.IP,
						service.Port,
						service.ServiceName); err != nil {
						log.Error().Msg(err.Error())
					}
				}
			}
		}
	}
}
