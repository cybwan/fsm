package cli

import (
	"context"

	ztm "github.com/cybwan/ztm-sdk-go"
	"github.com/mitchellh/hashstructure/v2"

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
		go c.InboundListener(ctx.Done(), mesh.MeshName, localEndpoint.UUID)
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
