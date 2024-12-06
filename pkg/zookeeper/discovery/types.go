package discovery

import (
	"sync"

	"github.com/flomesh-io/fsm/pkg/logger"
	"github.com/flomesh-io/fsm/pkg/zookeeper"
)

var (
	log = logger.New("fsm-zookeeper-discovery")
)

type ServiceDiscovery struct {
	client   *zookeeper.Client
	mutex    *sync.Mutex
	basePath string
	services *sync.Map
	ops      FuncOps
}

type ServiceInstance interface {
	ServiceName() string
	InstanceId() string

	Marshal() ([]byte, error)
	Unmarshal(string, []byte) error
}

// entry contain a service instance
type entry struct {
	sync.Mutex
	instance ServiceInstance
}

type FuncOps interface {
	NewInstance(serviceName, instanceId string) ServiceInstance
	PathForService(basePath, serviceName string) (servicePath string)
	PathForInstance(basePath, serviceName, instanceId string) (instancePath string)
	ServiceInstanceId(basePath, instancePath string) (serviceName, instanceId string, err error)
}
