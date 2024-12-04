package discovery

import (
	"sync"

	"github.com/flomesh-io/fsm/pkg/zookeeper"
)

// NewServiceDiscovery the constructor of service discovery
func NewServiceDiscovery(client *zookeeper.Client, basePath string,
	newInstanceFunc func(serviceName, instanceId string) ServiceInstance,
	pathForServiceFunc func(basePath, serviceName string) (servicePath string),
	pathForInstanceFunc func(basePath, serviceName, instanceId string) (instancePath string),
	serviceInstanceIdFunc func(basePath, instancePath string) (serviceName, instanceId string, err error)) *ServiceDiscovery {
	return &ServiceDiscovery{
		client:                client,
		mutex:                 &sync.Mutex{},
		basePath:              basePath,
		services:              &sync.Map{},
		listener:              zookeeper.NewZkEventListener(client),
		newInstanceFunc:       newInstanceFunc,
		pathForServiceFunc:    pathForServiceFunc,
		pathForInstanceFunc:   pathForInstanceFunc,
		serviceInstanceIdFunc: serviceInstanceIdFunc,
	}
}

// QueryForInstances query instances in zookeeper by name
func (sd *ServiceDiscovery) QueryForInstances(serviceName string) ([]ServiceInstance, error) {
	instanceIds, err := sd.client.GetChildren(sd.pathForServiceFunc(sd.basePath, serviceName))
	if err != nil {
		return nil, err
	}
	var (
		instance  ServiceInstance
		instances []ServiceInstance
	)
	for _, instanceId := range instanceIds {
		instance, err = sd.QueryForInstance(serviceName, instanceId)
		if err != nil {
			return nil, err
		}
		instances = append(instances, instance)
	}
	return instances, nil
}

// QueryForInstance query instances in zookeeper by name and id
func (sd *ServiceDiscovery) QueryForInstance(serviceName, instanceId string) (ServiceInstance, error) {
	instance := sd.newInstanceFunc(serviceName, instanceId)
	instancePath := sd.pathForInstanceFunc(sd.basePath, serviceName, instanceId)

	data, _, err := sd.client.GetContent(instancePath)
	if err != nil {
		return nil, err
	}

	if err = instance.Unmarshal(data); err != nil {
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
	sd.listener.ListenServiceEvent(nil, sd.pathForServiceFunc(sd.basePath, serviceName), listener)
}

// ListenServiceInstanceEvent add a listener in an instance
func (sd *ServiceDiscovery) ListenServiceInstanceEvent(serviceName, instanceId string, listener zookeeper.DataListener) {
	sd.listener.ListenServiceNodeEvent(sd.pathForInstanceFunc(sd.basePath, serviceName, instanceId), listener)
}

func (sd *ServiceDiscovery) Close() {
	if sd.listener != nil {
		sd.listener.Close()
	}
	if sd.client != nil {
		sd.client.Close()
	}
}
