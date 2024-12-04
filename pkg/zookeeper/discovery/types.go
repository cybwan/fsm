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
}

type ServiceInstance struct {
	Name                string      `json:"name,omitempty"`
	ID                  string      `json:"id,omitempty"`
	Address             string      `json:"address,omitempty"`
	Port                int         `json:"port,omitempty"`
	Payload             interface{} `json:"payload,omitempty"`
	RegistrationTimeUTC int64       `json:"registrationTimeUTC,omitempty"`
	Tag                 string      `json:"tag,omitempty"`
}
