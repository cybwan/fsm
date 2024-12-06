package discovery

import (
	"path"
	"sync"

	"github.com/flomesh-io/fsm/pkg/zookeeper"
)

// NewServiceDiscovery the constructor of service discovery
func NewServiceDiscovery(client *zookeeper.Client, basePath, category string, ops FuncOps) *ServiceDiscovery {
	return &ServiceDiscovery{
		client:   client,
		mutex:    &sync.Mutex{},
		basePath: basePath,
		category: category,
		services: &sync.Map{},
		ops:      ops,
	}
}

// QueryForInstances query instances in zookeeper by name
func (sd *ServiceDiscovery) QueryForInstances(serviceName string) ([]ServiceInstance, error) {
	categoryServiceName := path.Join(serviceName, sd.category)
	if instanceIds, err := sd.client.GetChildren(sd.ops.PathForService(sd.basePath, categoryServiceName)); err != nil {
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
	categoryServiceName := path.Join(serviceName, sd.category)
	instance := sd.ops.NewInstance(categoryServiceName, instanceId)
	instancePath := sd.ops.PathForInstance(sd.basePath, categoryServiceName, instanceId)
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

func (sd *ServiceDiscovery) Close() {
	if sd.client != nil {
		sd.client.Close()
	}
}
