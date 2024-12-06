package discovery

import (
	"github.com/dubbogo/go-zookeeper/zk"
	"github.com/pkg/errors"

	"github.com/flomesh-io/fsm/pkg/zookeeper"
)

// DataChange implement DataListener's DataChange function
func (sd *ServiceDiscovery) DataChange(eventType zookeeper.Event) bool {
	instancePath := eventType.Path
	if name, id, err := sd.ops.ServiceInstanceId(sd.basePath, instancePath); err != nil {
		log.Error().Msgf("[ServiceDiscovery] data change error = {%v}", err)
		return true
	} else {
		sd.updateInternalService(name, id)
		return true
	}
}

// registerService register service to zookeeper
func (sd *ServiceDiscovery) registerService(instance ServiceInstance) error {
	instancePath := sd.ops.PathForInstance(sd.basePath, instance.ServiceName(), instance.InstanceId())
	data, err := instance.Marshal()
	if err != nil {
		return err
	}

	if err = sd.client.Delete(instancePath); err != nil {
		log.Info().Msgf("Failed when trying to delete node %s, will continue with the registration process. "+
			"This is designed to avoid previous ephemeral node hold the position,"+
			" so it's normal for this action to fail because the node might not exist or has been deleted, error msg is %s.", instancePath, err.Error())
	}

	if err = sd.client.CreateTempWithValue(instancePath, data); errors.Is(err, zk.ErrNodeExists) {
		_, state, _ := sd.client.GetContent(instancePath)
		if state != nil {
			_, err = sd.client.SetContent(instancePath, data, state.Version+1)
			if err != nil {
				log.Debug().Msgf("Try to update the node data failed. In most cases, it's not a problem. ")
			}
		}
		return nil
	}
	if err != nil {
		return err
	}
	return nil
}

// RegisterService register service to zookeeper, and ensure cache is consistent with zookeeper
func (sd *ServiceDiscovery) RegisterService(instance ServiceInstance) error {
	value, loaded := sd.services.LoadOrStore(instance.InstanceId(), &entry{})
	entry, ok := value.(*entry)
	if !ok {
		return errors.New("[ServiceDiscovery] services value not entry")
	}

	entry.Lock()
	defer entry.Unlock()

	entry.instance = instance
	if err := sd.registerService(instance); err != nil {
		return err
	}
	if !loaded {
		sd.ListenServiceInstanceEvent(instance.ServiceName(), instance.InstanceId(), sd)
	}
	return nil
}

// UpdateService update service in zookeeper, and ensure cache is consistent with zookeeper
func (sd *ServiceDiscovery) UpdateService(instance ServiceInstance) error {
	value, ok := sd.services.Load(instance.InstanceId())
	if !ok {
		return errors.Errorf("[ServiceDiscovery] Service{%s} not registered", instance.InstanceId())
	}
	entry, ok := value.(*entry)
	if !ok {
		return errors.New("[ServiceDiscovery] services value not entry")
	}

	data, err := instance.Marshal()
	if err != nil {
		return err
	}

	entry.Lock()
	defer entry.Unlock()

	entry.instance = instance
	instancePath := sd.ops.PathForInstance(sd.basePath, instance.ServiceName(), instance.InstanceId())

	if _, err = sd.client.SetContent(instancePath, data, -1); err != nil {
		return err
	}
	return nil
}

// updateInternalService update service in cache
func (sd *ServiceDiscovery) updateInternalService(name, id string) {
	value, ok := sd.services.Load(id)
	if !ok {
		return
	}
	entry, ok := value.(*entry)
	if !ok {
		return
	}
	entry.Lock()
	defer entry.Unlock()
	instance, err := sd.QueryForInstance(name, id)
	if err != nil {
		log.Info().Msgf("[zkServiceDiscovery] UpdateInternalService{%s} error = err{%v}", id, err)
		return
	}
	entry.instance = instance
}

// UnregisterService un-register service in zookeeper and delete service in cache
func (sd *ServiceDiscovery) UnregisterService(instance ServiceInstance) error {
	if _, ok := sd.services.Load(instance.InstanceId()); !ok {
		return nil
	}
	sd.services.Delete(instance.InstanceId())
	return sd.unregisterService(instance)
}

// unregisterService un-register service in zookeeper
func (sd *ServiceDiscovery) unregisterService(instance ServiceInstance) error {
	instancePath := sd.ops.PathForInstance(sd.basePath, instance.ServiceName(), instance.InstanceId())
	return sd.client.Delete(instancePath)
}

// ReRegisterServices re-register all cache services to zookeeper
func (sd *ServiceDiscovery) ReRegisterServices() {
	sd.services.Range(func(key, value interface{}) bool {
		entry, ok := value.(*entry)
		if !ok {
			return true
		}
		entry.Lock()
		defer entry.Unlock()
		instance := entry.instance
		err := sd.registerService(instance)
		if err != nil {
			log.Error().Msgf("[zkServiceDiscovery] registerService{%s} error = err{%v}", instance.InstanceId(), errors.WithStack(err))
			return true
		}
		sd.ListenServiceInstanceEvent(instance.ServiceName(), instance.InstanceId(), sd)
		return true
	})
}
