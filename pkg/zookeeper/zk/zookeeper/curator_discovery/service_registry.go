package curator_discovery

import (
	"encoding/json"
	"errors"

	"github.com/dubbogo/go-zookeeper/zk"
	perrors "github.com/pkg/errors"
)

// registerService register service to zookeeper
func (sd *ServiceDiscovery) registerService(instance *ServiceInstance) error {
	path := sd.pathForInstance(instance.Name, instance.ID)
	data, err := json.Marshal(instance)
	if err != nil {
		return err
	}

	err = sd.client.Delete(path)
	if err != nil {
		log.Info().Msgf("Failed when trying to delete node %s, will continue with the registration process. "+
			"This is designed to avoid previous ephemeral node hold the position,"+
			" so it's normal for this action to fail because the node might not exist or has been deleted, error msg is %s.", path, err.Error())
	}

	err = sd.client.CreateTempWithValue(path, data)
	if errors.Is(err, zk.ErrNodeExists) {
		_, state, _ := sd.client.GetContent(path)
		if state != nil {
			_, err = sd.client.SetContent(path, data, state.Version+1)
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
func (sd *ServiceDiscovery) RegisterService(instance *ServiceInstance) error {
	value, loaded := sd.services.LoadOrStore(instance.ID, &Entry{})
	entry, ok := value.(*Entry)
	if !ok {
		return perrors.New("[ServiceDiscovery] services value not entry")
	}
	entry.Lock()
	defer entry.Unlock()
	entry.instance = instance
	err := sd.registerService(instance)
	if err != nil {
		return err
	}
	if !loaded {
		sd.ListenServiceInstanceEvent(instance.Name, instance.ID, sd)
	}
	return nil
}

// UpdateService update service in zookeeper, and ensure cache is consistent with zookeeper
func (sd *ServiceDiscovery) UpdateService(instance *ServiceInstance) error {
	value, ok := sd.services.Load(instance.ID)
	if !ok {
		return perrors.Errorf("[ServiceDiscovery] Service{%s} not registered", instance.ID)
	}
	entry, ok := value.(*Entry)
	if !ok {
		return perrors.New("[ServiceDiscovery] services value not entry")
	}
	data, err := json.Marshal(instance)
	if err != nil {
		return err
	}

	entry.Lock()
	defer entry.Unlock()
	entry.instance = instance
	path := sd.pathForInstance(instance.Name, instance.ID)

	_, err = sd.client.SetContent(path, data, -1)
	if err != nil {
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
	entry, ok := value.(*Entry)
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
func (sd *ServiceDiscovery) UnregisterService(instance *ServiceInstance) error {
	_, ok := sd.services.Load(instance.ID)
	if !ok {
		return nil
	}
	sd.services.Delete(instance.ID)
	return sd.unregisterService(instance)
}

// unregisterService un-register service in zookeeper
func (sd *ServiceDiscovery) unregisterService(instance *ServiceInstance) error {
	path := sd.pathForInstance(instance.Name, instance.ID)
	return sd.client.Delete(path)
}

// ReRegisterServices re-register all cache services to zookeeper
func (sd *ServiceDiscovery) ReRegisterServices() {
	sd.services.Range(func(key, value interface{}) bool {
		entry, ok := value.(*Entry)
		if !ok {
			return true
		}
		entry.Lock()
		defer entry.Unlock()
		instance := entry.instance
		err := sd.registerService(instance)
		if err != nil {
			log.Error().Msgf("[zkServiceDiscovery] registerService{%s} error = err{%v}", instance.ID, perrors.WithStack(err))
			return true
		}
		sd.ListenServiceInstanceEvent(instance.Name, instance.ID, sd)
		return true
	})
}
