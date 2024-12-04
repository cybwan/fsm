package discovery

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"

	perrors "github.com/pkg/errors"

	"github.com/flomesh-io/fsm/pkg/zookeeper/zk/kv"
)

// Entry contain a service instance
type Entry struct {
	sync.Mutex
	instance *ServiceInstance
}

// NewServiceDiscovery the constructor of service discovery
func NewServiceDiscovery(client *kv.ZookeeperClient, basePath string) *ServiceDiscovery {
	return &ServiceDiscovery{
		client:   client,
		mutex:    &sync.Mutex{},
		basePath: basePath,
		services: &sync.Map{},
		listener: kv.NewZkEventListener(client),
	}
}

// QueryForInstances query instances in zookeeper by name
func (sd *ServiceDiscovery) QueryForInstances(name string) ([]*ServiceInstance, error) {
	ids, err := sd.client.GetChildren(sd.pathForName(name))
	if err != nil {
		return nil, err
	}
	var (
		instance  *ServiceInstance
		instances []*ServiceInstance
	)
	for _, id := range ids {
		instance, err = sd.QueryForInstance(name, id)
		if err != nil {
			return nil, err
		}
		instances = append(instances, instance)
	}
	return instances, nil
}

// QueryForInstance query instances in zookeeper by name and id
func (sd *ServiceDiscovery) QueryForInstance(name string, id string) (*ServiceInstance, error) {
	path := sd.pathForInstance(name, id)
	qid, _ := url.QueryUnescape(id)
	data, _, err := sd.client.GetContent(path)
	if err != nil {
		return nil, err
	}
	fmt.Printf("QueryForInstance name:%s \nid:%s\n data:%s\n", name, qid, string(data))
	//fmt.Println("QueryForInstance path:", qpath, "data:", string(data))
	instance := &ServiceInstance{}
	err = json.Unmarshal(data, instance)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

// QueryForNames query all service name in zookeeper
func (sd *ServiceDiscovery) QueryForNames() ([]string, error) {
	return sd.client.GetChildren(sd.basePath)
}

// ListenServiceEvent add a listener in a service
func (sd *ServiceDiscovery) ListenServiceEvent(name string, listener kv.DataListener) {
	sd.listener.ListenServiceEvent(nil, sd.pathForName(name), listener)
}

// ListenServiceInstanceEvent add a listener in an instance
func (sd *ServiceDiscovery) ListenServiceInstanceEvent(name, id string, listener kv.DataListener) {
	sd.listener.ListenServiceNodeEvent(sd.pathForInstance(name, id), listener)
}

// getNameAndID get service name and instance id by path
func (sd *ServiceDiscovery) getNameAndID(path string) (string, string, error) {
	path = strings.TrimPrefix(path, sd.basePath)
	path = strings.TrimPrefix(path, string(os.PathSeparator))
	pathSlice := strings.Split(path, string(os.PathSeparator))
	if len(pathSlice) < 2 {
		return "", "", perrors.Errorf("[ServiceDiscovery] path{%s} dont contain name and id", path)
	}
	name := pathSlice[0]
	id := pathSlice[1]
	return name, id, nil
}

// nolint
func (sd *ServiceDiscovery) pathForInstance(name, id string) string {
	return path.Join(sd.basePath, name, id)
}

// nolint
func (sd *ServiceDiscovery) prefixPathForInstance(name string) string {
	return path.Join(sd.basePath, name)
}

// nolint
func (sd *ServiceDiscovery) pathForName(name string) string {
	return path.Join(sd.basePath, name)
}

func (sd *ServiceDiscovery) Close() {
	if sd.listener != nil {
		sd.listener.Close()
	}
	if sd.client != nil {
		sd.client.Close()
	}
}
