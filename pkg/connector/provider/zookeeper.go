package provider

import (
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	ctv1 "github.com/flomesh-io/fsm/pkg/apis/connector/v1alpha1"
	"github.com/flomesh-io/fsm/pkg/connector"
	"github.com/flomesh-io/fsm/pkg/zookeeper"
	"github.com/flomesh-io/fsm/pkg/zookeeper/discovery"
	"github.com/flomesh-io/fsm/pkg/zookeeper/discovery/nebula"
)

type ZookeeperDiscoveryClient struct {
	connectController connector.ConnectController
	namingClient      *discovery.ServiceDiscovery
	zkAddr            string
	basePath          string
	category          string
	adaptor           string
	lock              sync.Mutex
}

func (dc *ZookeeperDiscoveryClient) zookeeperClient() *discovery.ServiceDiscovery {
	dc.lock.Lock()
	defer dc.lock.Unlock()

	if dc.namingClient != nil {
		zkAddr := dc.connectController.GetHTTPAddr()
		basePath := dc.connectController.GetZookeeperBasePath()
		category := dc.connectController.GetZookeeperCategory()
		adaptor := dc.connectController.GetZookeeperAdaptor()

		if !strings.EqualFold(dc.zkAddr, zkAddr) ||
			!strings.EqualFold(dc.basePath, basePath) ||
			!strings.EqualFold(dc.category, category) ||
			!strings.EqualFold(dc.adaptor, adaptor) {
			dc.namingClient.Close()
			dc.namingClient = nil

			dc.zkAddr = zkAddr
			dc.basePath = basePath
			dc.category = category
			dc.adaptor = adaptor
		}
	}

	if dc.namingClient == nil {
		client, err := zookeeper.NewClient(
			"zookeeperClient",
			[]string{dc.zkAddr},
			true,
			zookeeper.WithZkTimeOut(time.Second*15))
		if err != nil {
			log.Fatal().Err(err).Msg("failed to connect zookeeper")
		}
		dc.namingClient = discovery.NewServiceDiscovery(client, dc.basePath, dc.category, new(nebula.Ops))
	}

	dc.connectController.WaitLimiter()

	return dc.namingClient
}

func (dc *ZookeeperDiscoveryClient) selectServices() ([]string, error) {
	return dc.zookeeperClient().QueryForNames()
}

func (dc *ZookeeperDiscoveryClient) selectInstances(svc string) ([]discovery.ServiceInstance, error) {
	result, err := dc.connectController.CacheCatalogInstances(svc, func() (interface{}, error) {
		return dc.zookeeperClient().QueryForInstances(svc)
	})
	if result != nil {
		return result.([]discovery.ServiceInstance), err
	}
	return nil, err
}

func (dc *ZookeeperDiscoveryClient) IsInternalServices() bool {
	return dc.connectController.AsInternalServices()
}

func (dc *ZookeeperDiscoveryClient) CatalogInstances(service string, _ *connector.QueryOptions) ([]*connector.AgentService, error) {
	instances, err := dc.selectInstances(service)
	if err != nil {
		return nil, err
	}
	agentServices := make([]*connector.AgentService, 0)
	if len(instances) > 0 {
		for _, ins := range instances {
			ins := ins
			if clusterSet, clusterSetExist := ins.Metadata(connector.ClusterSetKey); clusterSetExist {
				if strings.EqualFold(clusterSet, dc.connectController.GetClusterSet()) {
					continue
				}
			}
			if filterMetadatas := dc.connectController.GetC2KFilterMetadatas(); len(filterMetadatas) > 0 {
				matched := true
				for _, meta := range filterMetadatas {
					if metaSet, metaExist := ins.Metadata(meta.Key); metaExist {
						if strings.EqualFold(metaSet, meta.Value) {
							continue
						}
					} else if len(meta.Value) == 0 {
						continue
					}
					matched = false
					break
				}
				if !matched {
					continue
				}
			}
			if excludeMetadatas := dc.connectController.GetC2KExcludeMetadatas(); len(excludeMetadatas) > 0 {
				matched := false
				for _, meta := range excludeMetadatas {
					if metaSet, metaExist := ins.Metadata(meta.Key); metaExist {
						if strings.EqualFold(metaSet, meta.Value) {
							matched = true
							break
						}
					}
				}
				if matched {
					continue
				}
			}
			if filterIPRanges := dc.connectController.GetC2KFilterIPRanges(); len(filterIPRanges) > 0 {
				include := false
				for _, cidr := range filterIPRanges {
					if cidr.Contains(ins.InstanceAddr()) {
						include = true
						break
					}
				}
				if !include {
					continue
				}
			}
			if excludeIPRanges := dc.connectController.GetC2KExcludeIPRanges(); len(excludeIPRanges) > 0 {
				exclude := false
				for _, cidr := range excludeIPRanges {
					if cidr.Contains(ins.InstanceAddr()) {
						exclude = true
						break
					}
				}
				if exclude {
					continue
				}
			}
			agentService := new(connector.AgentService)
			// todo
			//agentService.FromZookeeper(&ins)
			agentService.ClusterId = dc.connectController.GetClusterId()
			agentServices = append(agentServices, agentService)
		}
	}
	return agentServices, nil
}

func (dc *ZookeeperDiscoveryClient) CatalogServices(*connector.QueryOptions) ([]connector.MicroService, error) {
	serviceList, err := dc.selectServices()
	if err != nil {
		return nil, err
	}
	var catalogServices []connector.MicroService
	if len(serviceList) > 0 {
		for _, svc := range serviceList {
			if errMsgs := validation.IsDNS1035Label(svc); len(errMsgs) > 0 {
				log.Info().Msgf("invalid format, ignore service: %s, errors:%s", svc, strings.Join(errMsgs, "; "))
				continue
			}
			instances, _ := dc.selectInstances(svc)
			if len(instances) == 0 {
				continue
			}
			for _, svcIns := range instances {
				if clusterSet, clusterSetExist := svcIns.Metadata(connector.ClusterSetKey); clusterSetExist {
					if strings.EqualFold(clusterSet, dc.connectController.GetClusterSet()) {
						continue
					}
				}
				if filterMetadatas := dc.connectController.GetC2KFilterMetadatas(); len(filterMetadatas) > 0 {
					matched := true
					for _, meta := range filterMetadatas {
						if metaSet, metaExist := svcIns.Metadata(meta.Key); metaExist {
							if strings.EqualFold(metaSet, meta.Value) {
								continue
							}
						} else if len(meta.Value) == 0 {
							continue
						}
						matched = false
						break
					}
					if !matched {
						continue
					}
				}
				if excludeMetadatas := dc.connectController.GetC2KExcludeMetadatas(); len(excludeMetadatas) > 0 {
					matched := false
					for _, meta := range excludeMetadatas {
						if metaSet, metaExist := svcIns.Metadata(meta.Key); metaExist {
							if strings.EqualFold(metaSet, meta.Value) {
								matched = true
								break
							}
						}
					}
					if matched {
						continue
					}
				}
				if filterIPRanges := dc.connectController.GetC2KFilterIPRanges(); len(filterIPRanges) > 0 {
					include := false
					for _, cidr := range filterIPRanges {
						if cidr.Contains(svcIns.InstanceAddr()) {
							include = true
							break
						}
					}
					if !include {
						continue
					}
				}
				if excludeIPRanges := dc.connectController.GetC2KExcludeIPRanges(); len(excludeIPRanges) > 0 {
					exclude := false
					for _, cidr := range excludeIPRanges {
						if cidr.Contains(svcIns.InstanceAddr()) {
							exclude = true
							break
						}
					}
					if exclude {
						continue
					}
				}
				catalogServices = append(catalogServices, connector.MicroService{Service: svc})
				break
			}
		}
	}
	return catalogServices, nil
}

// RegisteredInstances is used to query catalog entries for a given service
func (dc *ZookeeperDiscoveryClient) RegisteredInstances(service string, _ *connector.QueryOptions) ([]*connector.CatalogService, error) {
	//instances, err := dc.selectInstances(service)
	//if err != nil {
	//	return nil, err
	//}
	//catalogServices := make([]*connector.CatalogService, 0)
	//if len(instances) > 0 {
	//	for _, instance := range instances {
	//		instance := instance
	//		if connectUID, connectUIDExist := instance.Metadata[connector.ConnectUIDKey]; connectUIDExist {
	//			if strings.EqualFold(connectUID, dc.connectController.GetConnectorUID()) {
	//				catalogService := new(connector.CatalogService)
	//				catalogService.FromZookeeper(&instance)
	//				catalogServices = append(catalogServices, catalogService)
	//			}
	//		}
	//	}
	//}
	//return catalogServices, nil
	return nil, nil
}

func (dc *ZookeeperDiscoveryClient) RegisteredServices(*connector.QueryOptions) ([]connector.MicroService, error) {
	serviceList, err := dc.selectServices()
	if err != nil {
		return nil, err
	}
	var registeredServices []connector.MicroService
	if len(serviceList) > 0 {
		for _, svc := range serviceList {
			svc := strings.ToLower(svc)
			if strings.Contains(svc, "_") {
				log.Info().Msgf("invalid format, ignore service: %s", svc)
				continue
			}
			instances, _ := dc.selectInstances(svc)
			if len(instances) == 0 {
				continue
			}
			for _, instance := range instances {
				instance := instance
				if connectUID, connectUIDExist := instance.Metadata(connector.ConnectUIDKey); connectUIDExist {
					if strings.EqualFold(connectUID, dc.connectController.GetConnectorUID()) {
						registeredServices = append(registeredServices, connector.MicroService{Service: svc})
						break
					}
				}
			}
		}
	}
	return registeredServices, nil
}

func (dc *ZookeeperDiscoveryClient) Deregister(dereg *connector.CatalogDeregistration) error {
	//ins := dereg.ToZookeeper()
	//if ins == nil {
	//	return nil
	//}
	//port, _ := strconv.Atoi(fmt.Sprintf("%d", ins.Port))
	//return dc.connectController.CacheDeregisterInstance(dc.getServiceInstanceID(ins.ServiceName, ins.Ip, port, 0), func() error {
	//	_, err := dc.zookeeperClient().DeregisterInstance(*ins)
	//	return err
	//})
	return nil
}

func (dc *ZookeeperDiscoveryClient) Register(reg *connector.CatalogRegistration) error {
	//k2cGroupId := dc.connectController.GetZookeeperGroupId()
	//if len(k2cGroupId) == 0 {
	//	k2cGroupId = constant.DEFAULT_GROUP
	//}
	//
	//k2cClusterId := dc.connectController.GetZookeeperClusterId()
	//if len(k2cClusterId) == 0 {
	//	k2cClusterId = connector.NACOS_DEFAULT_CLUSTER
	//}
	//ins := reg.ToZookeeper(k2cClusterId, k2cGroupId, float64(1))
	//appendMetadataSet := dc.connectController.GetAppendMetadataSet().ToSlice()
	//if len(appendMetadataSet) > 0 {
	//	rMetadata := ins.Metadata
	//	for _, item := range appendMetadataSet {
	//		metadata := item.(ctv1.Metadata)
	//		rMetadata[metadata.Key] = metadata.Value
	//	}
	//}
	//port, _ := strconv.Atoi(fmt.Sprintf("%d", ins.Port))
	//return dc.connectController.CacheRegisterInstance(dc.getServiceInstanceID(ins.ServiceName, ins.Ip, port, 0), ins, func() error {
	//	_, err := dc.zookeeperClient().RegisterInstance(*ins)
	//	return err
	//})
	return nil
}

func (dc *ZookeeperDiscoveryClient) EnableNamespaces() bool {
	return false
}

// EnsureNamespaceExists ensures a namespace with name ns exists.
func (dc *ZookeeperDiscoveryClient) EnsureNamespaceExists(ns string) (bool, error) {
	return false, nil
}

// RegisteredNamespace returns the cloud namespace that a service should be
// registered in based on the namespace options. It returns an
// empty string if namespaces aren't enabled.
func (dc *ZookeeperDiscoveryClient) RegisteredNamespace(kubeNS string) string {
	return ""
}

func (dc *ZookeeperDiscoveryClient) MicroServiceProvider() ctv1.DiscoveryServiceProvider {
	return ctv1.ZookeeperDiscoveryService
}

func (dc *ZookeeperDiscoveryClient) Close() {
}

func GetZookeeperDiscoveryClient(connectController connector.ConnectController) (*ZookeeperDiscoveryClient, error) {
	zookeeperDiscoveryClient := new(ZookeeperDiscoveryClient)
	zookeeperDiscoveryClient.connectController = connectController
	zookeeperDiscoveryClient.zkAddr = connectController.GetHTTPAddr()
	zookeeperDiscoveryClient.basePath = connectController.GetZookeeperBasePath()
	zookeeperDiscoveryClient.category = connectController.GetZookeeperCategory()
	zookeeperDiscoveryClient.adaptor = connectController.GetZookeeperAdaptor()
	return zookeeperDiscoveryClient, nil
}
