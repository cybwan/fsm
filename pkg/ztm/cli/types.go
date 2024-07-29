package cli

import (
	"context"
	"sync"

	"k8s.io/client-go/rest"

	"github.com/flomesh-io/fsm/pkg/endpoint"
	configClientset "github.com/flomesh-io/fsm/pkg/gen/client/config/clientset/versioned"
	ztmClientset "github.com/flomesh-io/fsm/pkg/gen/client/ztm/clientset/versioned"
	"github.com/flomesh-io/fsm/pkg/k8s"
	"github.com/flomesh-io/fsm/pkg/k8s/informers"
	"github.com/flomesh-io/fsm/pkg/messaging"
	"github.com/flomesh-io/fsm/pkg/workerpool"
)

const (
	ServiceExport k8s.InformerKey = "ServiceExport"
	ServiceImport k8s.InformerKey = "ServiceImport"
	ZtmAgents     k8s.InformerKey = "ZtmAgents"
)

// client is the type used to represent the k8s client for the connector resources
type client struct {
	agentName string
	agentSpec interface{}
	agentUID  string
	agentHash uint64

	clusterSet string

	informers     *informers.InformerCollection
	msgBroker     *messaging.Broker
	msgWorkQueues *workerpool.WorkerPool
	// msgWorkerPoolSize is the default number of workerpool workers (0 is GOMAXPROCS)
	msgWorkerPoolSize int

	kubeConfig    *rest.Config
	k8sController k8s.Controller
	kubeProvider  endpoint.Provider
	configClient  configClientset.Interface

	ztmClient ztmClientset.Interface

	lock        sync.Mutex
	context     context.Context
	cancelFuncs []context.CancelFunc
}
