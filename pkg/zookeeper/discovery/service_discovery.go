package discovery

import (
	"sync"

	"github.com/flomesh-io/fsm/pkg/zookeeper"
)

// NewServiceDiscovery the constructor of service discovery
func NewServiceDiscovery(client *zookeeper.Client, basePath string, ops FuncOps) *ServiceDiscovery {
	return &ServiceDiscovery{
		client:   client,
		mutex:    &sync.Mutex{},
		basePath: basePath,
		services: &sync.Map{},
		listener: zookeeper.NewEventListener(client),
		ops:      ops,
	}
}

// QueryForInstances query instances in zookeeper by name
func (sd *ServiceDiscovery) QueryForInstances(serviceName string) ([]ServiceInstance, error) {
	if instanceIds, err := sd.client.GetChildren(sd.ops.PathForService(sd.basePath, serviceName)); err != nil {
		return nil, err
	} else {
		var instance ServiceInstance
		var instances []ServiceInstance
		for _, instanceId := range instanceIds {
			if instance, err = sd.QueryForInstance(serviceName, instanceId); err != nil {
				return nil, err
			}
			instances = append(instances, instance)
		}
		return instances, nil
	}
}

// QueryForInstance query instances in zookeeper by name and id
func (sd *ServiceDiscovery) QueryForInstance(serviceName, instanceId string) (ServiceInstance, error) {
	instance := sd.ops.NewInstance(serviceName, instanceId)
	instancePath := sd.ops.PathForInstance(sd.basePath, serviceName, instanceId)
	if data, _, err := sd.client.GetContent(instancePath); err != nil {
		return nil, err
	} else if err = instance.Unmarshal(instancePath, data); err != nil {
		return nil, err
	}
	return instance, nil
}

// QueryForNames query all service name in zookeeper
func (sd *ServiceDiscovery) QueryForNames() ([]string, error) {
	return sd.client.GetChildren(sd.basePath)
}

// ListenServiceEvent add a listener in a service
func (sd *ServiceDiscovery) ListenServiceEvent(serviceName string, listener zookeeper.DataListener) {
	sd.listener.ListenServiceEvent(nil, sd.ops.PathForService(sd.basePath, serviceName), listener)
}

// ListenServiceInstanceEvent add a listener in an instance
func (sd *ServiceDiscovery) ListenServiceInstanceEvent(serviceName, instanceId string, listener zookeeper.DataListener) {
	sd.listener.ListenServiceNodeEvent(sd.ops.PathForInstance(sd.basePath, serviceName, instanceId), listener)
}

func (sd *ServiceDiscovery) Close() {
	if sd.listener != nil {
		sd.listener.Close()
	}
	if sd.client != nil {
		sd.client.Close()
	}
}
