package cli

import (
	"context"
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/flomesh-io/fsm/pkg/announcements"
	ztmv1 "github.com/flomesh-io/fsm/pkg/apis/ztm/v1alpha1"
	configClientset "github.com/flomesh-io/fsm/pkg/gen/client/config/clientset/versioned"
	ztmClientset "github.com/flomesh-io/fsm/pkg/gen/client/ztm/clientset/versioned"
	"github.com/flomesh-io/fsm/pkg/k8s"
	fsminformers "github.com/flomesh-io/fsm/pkg/k8s/informers"
	"github.com/flomesh-io/fsm/pkg/messaging"
	"github.com/flomesh-io/fsm/pkg/workerpool"
	"github.com/flomesh-io/fsm/pkg/ztm"
)

// NewAgentController returns a new agent.Controller which means to provide access to locally-cached agent resources
func NewAgentController(context context.Context,
	agentName string,
	kubeConfig *rest.Config,
	kubeClient kubernetes.Interface,
	configClient configClientset.Interface,
	ztmClient ztmClientset.Interface,
	informerCollection *fsminformers.InformerCollection,
	msgBroker *messaging.Broker,
	selectInformers ...InformerKey) ztm.AgentController {
	return newClient(agentName,
		context,
		kubeConfig,
		kubeClient,
		configClient,
		ztmClient,
		informerCollection,
		msgBroker,
		selectInformers...)
}

func newClient(agentName string,
	context context.Context,
	kubeConfig *rest.Config,
	kubeClient kubernetes.Interface,
	configClient configClientset.Interface,
	ztmClient ztmClientset.Interface,
	informerCollection *fsminformers.InformerCollection,
	msgBroker *messaging.Broker,
	selectInformers ...InformerKey) *client {
	// Initialize client object
	c := &client{
		agentName: agentName,

		context:      context,
		kubeConfig:   kubeConfig,
		kubeClient:   kubeClient,
		configClient: configClient,
		ztmClient:    ztmClient,

		informers:         informerCollection,
		msgBroker:         msgBroker,
		msgWorkerPoolSize: 0,
		msgWorkQueues:     workerpool.NewWorkerPool(0),
	}

	// Initialize informers
	informerInitHandlerMap := map[InformerKey]func(){
		ZtmAgents: c.initAgentMonitor,
	}

	// If specific informers are not selected to be initialized, initialize all informers
	if len(selectInformers) == 0 {
		selectInformers = []InformerKey{
			ZtmAgents,
		}
	}

	for _, informer := range selectInformers {
		informerInitHandlerMap[informer]()
	}

	return c
}

func (c *client) initAgentMonitor() {
	agentEventTypes := k8s.EventTypes{
		Add:    announcements.ZtmAgentAdded,
		Update: announcements.ZtmAgentUpdated,
		Delete: announcements.ZtmAgentDeleted,
	}
	c.informers.AddEventHandler(fsminformers.InformerKeyZtmAgent,
		k8s.GetEventHandlerFuncs(nil, agentEventTypes, c.msgBroker))
}

// GetAgent returns a ZtmAgent resource if found, nil otherwise.
func (c *client) GetAgent() (agent, spec interface{}, uid string, ok bool) {
	agentIf, exists, err := c.informers.GetByKey(fsminformers.InformerKeyZtmAgent, c.GetAgentName())
	if exists && err == nil {
		ztmAgent := agentIf.(*ztmv1.Agent)
		agent = ztmAgent
		spec = ztmAgent.Spec
		uid = string(ztmAgent.UID)
		ok = true
	}
	return
}

// GetAgentName returns agent name.
func (c *client) GetAgentName() string {
	return c.agentName
}

// GetAgentUID returns agent uid.
func (c *client) GetAgentUID() string {
	return c.agentUID
}

// GetClusterSet returns cluster set.
func (c *client) GetClusterSet() string {
	return c.clusterSet
}

// SetClusterSet sets cluster set.
func (c *client) SetClusterSet(name, group, zone, region string) {
	c.clusterSet = fmt.Sprintf("%s.%s.%s.%s", name, group, zone, region)
}
