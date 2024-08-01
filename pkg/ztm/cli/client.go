package cli

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"

	"github.com/flomesh-io/fsm/pkg/announcements"
	ztmv1 "github.com/flomesh-io/fsm/pkg/apis/ztm/v1alpha1"
	"github.com/flomesh-io/fsm/pkg/endpoint"
	configClientset "github.com/flomesh-io/fsm/pkg/gen/client/config/clientset/versioned"
	multiclusterClientset "github.com/flomesh-io/fsm/pkg/gen/client/multicluster/clientset/versioned"
	ztmClientset "github.com/flomesh-io/fsm/pkg/gen/client/ztm/clientset/versioned"
	"github.com/flomesh-io/fsm/pkg/k8s"
	fsminformers "github.com/flomesh-io/fsm/pkg/k8s/informers"
	"github.com/flomesh-io/fsm/pkg/logger"
	"github.com/flomesh-io/fsm/pkg/messaging"
	"github.com/flomesh-io/fsm/pkg/workerpool"
	"github.com/flomesh-io/fsm/pkg/ztm"
)

var (
	log = logger.New("fsm-ztm-agent")
)

// NewAgentController returns a new agent.Controller which means to provide access to locally-cached agent resources
func NewAgentController(context context.Context,
	agentName string,
	kubeConfig *rest.Config,
	k8sController k8s.Controller,
	kubeProvider endpoint.Provider,
	configClient configClientset.Interface,
	mcsClient multiclusterClientset.Interface,
	ztmClient ztmClientset.Interface,
	agentPod *corev1.Pod,
	informerCollection *fsminformers.InformerCollection,
	msgBroker *messaging.Broker,
	selectInformers ...k8s.InformerKey) ztm.AgentController {
	return newClient(agentName,
		context,
		kubeConfig,
		k8sController,
		kubeProvider,
		configClient,
		mcsClient,
		ztmClient,
		agentPod,
		informerCollection,
		msgBroker,
		selectInformers...)
}

func newClient(agentName string,
	context context.Context,
	kubeConfig *rest.Config,
	k8sController k8s.Controller,
	kubeProvider endpoint.Provider,
	configClient configClientset.Interface,
	mcsClient multiclusterClientset.Interface,
	ztmClient ztmClientset.Interface,
	agentPod *corev1.Pod,
	informerCollection *fsminformers.InformerCollection,
	msgBroker *messaging.Broker,
	selectInformers ...k8s.InformerKey) *client {
	// Initialize client object
	c := &client{
		agentName: agentName,

		context:       context,
		kubeConfig:    kubeConfig,
		k8sController: k8sController,
		kubeProvider:  kubeProvider,
		configClient:  configClient,
		mcsClient:     mcsClient,
		ztmClient:     ztmClient,
		agentPod:      agentPod,

		outboundCache: make(map[string]map[string]*ServiceMetadata),

		informers:         informerCollection,
		msgBroker:         msgBroker,
		msgWorkerPoolSize: 0,
		msgWorkQueues:     workerpool.NewWorkerPool(0),
	}

	// Initialize informers
	informerInitHandlerMap := map[k8s.InformerKey]func(){
		k8s.Namespaces:      c.initNamespaceMonitor,
		k8s.Services:        c.initServicesMonitor,
		k8s.ServiceAccounts: c.initServiceAccountsMonitor,
		k8s.Pods:            c.initPodMonitor,
		k8s.Endpoints:       c.initEndpointMonitor,
		ServiceExport:       c.initServiceExportMonitor,
		ServiceImport:       c.initServiceImportMonitor,
		ZtmAgents:           c.initAgentMonitor,
	}

	// If specific informers are not selected to be initialized, initialize all informers
	if len(selectInformers) == 0 {
		selectInformers = []k8s.InformerKey{
			k8s.Namespaces, k8s.Services, k8s.ServiceAccounts, k8s.Pods, k8s.Endpoints,
			ServiceExport, ServiceImport, ZtmAgents,
		}
	}

	for _, informer := range selectInformers {
		informerInitHandlerMap[informer]()
	}

	return c
}

// Initializes Namespace monitoring
func (c *client) initNamespaceMonitor() {
	// Add event handler to informer
	nsEventTypes := k8s.EventTypes{
		Add:    announcements.NamespaceAdded,
		Update: announcements.NamespaceUpdated,
		Delete: announcements.NamespaceDeleted,
	}
	c.informers.AddEventHandler(fsminformers.InformerKeyNamespace,
		k8s.GetEventHandlerFuncs(nil, nsEventTypes, c.msgBroker))
}

// Initializes Service monitoring
func (c *client) initServicesMonitor() {
	svcEventTypes := k8s.EventTypes{
		Add:    announcements.ServiceAdded,
		Update: announcements.ServiceUpdated,
		Delete: announcements.ServiceDeleted,
	}
	c.informers.AddEventHandler(fsminformers.InformerKeyService,
		k8s.GetEventHandlerFuncs(nil, svcEventTypes, c.msgBroker))
}

// Initializes Service Account monitoring
func (c *client) initServiceAccountsMonitor() {
	svcEventTypes := k8s.EventTypes{
		Add:    announcements.ServiceAccountAdded,
		Update: announcements.ServiceAccountUpdated,
		Delete: announcements.ServiceAccountDeleted,
	}
	c.informers.AddEventHandler(fsminformers.InformerKeyServiceAccount,
		k8s.GetEventHandlerFuncs(nil, svcEventTypes, c.msgBroker))
}

func (c *client) initPodMonitor() {
	podEventTypes := k8s.EventTypes{
		Add:    announcements.PodAdded,
		Update: announcements.PodUpdated,
		Delete: announcements.PodDeleted,
	}
	c.informers.AddEventHandler(fsminformers.InformerKeyPod,
		k8s.GetEventHandlerFuncs(nil, podEventTypes, c.msgBroker))
}

func (c *client) initEndpointMonitor() {
	eptEventTypes := k8s.EventTypes{
		Add:    announcements.EndpointAdded,
		Update: announcements.EndpointUpdated,
		Delete: announcements.EndpointDeleted,
	}
	c.informers.AddEventHandler(fsminformers.InformerKeyEndpoints,
		k8s.GetEventHandlerFuncs(nil, eptEventTypes, c.msgBroker))
}

func (c *client) initServiceExportMonitor() {
	svcExportEventTypes := k8s.EventTypes{
		Add:    announcements.ServiceExportAdded,
		Update: announcements.ServiceExportUpdated,
		Delete: announcements.ServiceExportDeleted,
	}
	c.informers.AddEventHandler(fsminformers.InformerKeyServiceExport,
		k8s.GetEventHandlerFuncs(nil, svcExportEventTypes, c.msgBroker))
}

func (c *client) initServiceImportMonitor() {
	svcImportEventTypes := k8s.EventTypes{
		Add:    announcements.ServiceImportAdded,
		Update: announcements.ServiceImportUpdated,
		Delete: announcements.ServiceImportDeleted,
	}
	c.informers.AddEventHandler(fsminformers.InformerKeyServiceImport,
		k8s.GetEventHandlerFuncs(nil, svcImportEventTypes, c.msgBroker))
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
