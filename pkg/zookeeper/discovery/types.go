package discovery

import (
	"sync"

	"github.com/flomesh-io/fsm/pkg/logger"
	"github.com/flomesh-io/fsm/pkg/zookeeper"
)

var (
	log = logger.New("curator_discovery")
)

type ServiceDiscovery struct {
	client   *zookeeper.Client
	mutex    *sync.Mutex
	basePath string
	services *sync.Map
	listener *zookeeper.ZkEventListener

	newInstanceFunc       func(serviceName, instanceId string) ServiceInstance
	pathForServiceFunc    func(basePath, serviceName string) (servicePath string)
	pathForInstanceFunc   func(basePath, serviceName, instanceId string) (instancePath string)
	serviceInstanceIdFunc func(basePath, instancePath string) (serviceName, instanceId string, err error)
}

// Entry contain a service instance
type Entry struct {
	sync.Mutex
	instance ServiceInstance
}

type ServiceInstance interface {
	ServiceName() string
	InstanceId() string

	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
}

type ServiceInstanceA struct {
	Name                string      `json:"name,omitempty"`
	ID                  string      `json:"id,omitempty"`
	Address             string      `json:"address,omitempty"`
	Port                int         `json:"port,omitempty"`
	Payload             interface{} `json:"payload,omitempty"`
	RegistrationTimeUTC int64       `json:"registrationTimeUTC,omitempty"`
	Tag                 string      `json:"tag,omitempty"`
}
