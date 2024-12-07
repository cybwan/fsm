package nebula

import (
	"net/url"
	"strconv"

	"github.com/gorilla/schema"

	"github.com/flomesh-io/fsm/pkg/connector"
)

const (
	PickFirstLoadBalance        LoadBalance = "pick_first"
	RoundRobinLoadBalance       LoadBalance = "round_robin"
	WeightRoundRobinLoadBalance LoadBalance = "weight_round_robin"
	ConsistentHashLoadBalance   LoadBalance = "consistent_hash"
)

type LoadBalance string

type InstanceSetting struct {
	Async       bool
	Cluster     string
	LoadBalance LoadBalance
	Connections uint32
	Requests    uint32
	Reties      uint32
	Timeout     uint32
}

type InstanceService struct {
	Type string
}

type InstanceReal struct {
	IP   string
	Port uint16
}

type InstanceAccess struct {
	Protected bool
}

type ServiceInstance struct {
	serviceName string
	instanceId  string

	Schema   string
	HostName string
	IPAddr   string
	Port     int
	Node     string

	Application string
	Project     string
	Owner       string
	Ops         string
	Category    string
	Timestamp   uint64
	GRPC        string
	PID         uint32
	Interface   string
	Methods     []string
	Group       bool
	Weight      uint32
	Deprecated  bool
	Master      bool

	Default InstanceSetting
	Service InstanceService
	Real    InstanceReal
	Access  InstanceAccess

	Accesslog bool
	Anyhost   bool
	Dynamic   bool
	Token     bool
	Side      string
	Version   string

	Fsm struct {
		Connector struct {
			Service struct {
				Cluster struct {
					Set string
				}
				Connector struct {
					Uid string
				}
			}
		}
	}
}

func NewServiceInstance(serviceName, instanceId string) *ServiceInstance {
	return &ServiceInstance{
		serviceName: serviceName,
		instanceId:  instanceId,
		Access: InstanceAccess{
			Protected: false,
		},
		Default: InstanceSetting{
			Connections: 20,
			Requests:    2000,
			LoadBalance: PickFirstLoadBalance,
		},
		Weight:     100,
		Deprecated: false,
		Master:     true,
	}
}

func (ins *ServiceInstance) ServiceName() string {
	return ins.serviceName
}

func (ins *ServiceInstance) ServiceSchema() string {
	return ins.Schema
}

func (ins *ServiceInstance) InstanceId() string {
	return ins.instanceId
}

func (ins *ServiceInstance) InstanceAddr() string {
	return ins.IPAddr
}

func (ins *ServiceInstance) InstancePort() int {
	return ins.Port
}

func (ins *ServiceInstance) Metadata(key string) (string, bool) {
	switch key {
	case connector.ClusterSetKey:
		return ins.Fsm.Connector.Service.Cluster.Set, true
	case connector.ConnectUIDKey:
		return ins.Fsm.Connector.Service.Connector.Uid, true
	default:
		return "", false
	}
}

func (ins *ServiceInstance) Metadatas() map[string]string {
	return nil
}

func (ins *ServiceInstance) Marshal() ([]byte, error) {
	return nil, nil
}

func (ins *ServiceInstance) Unmarshal(_ string, data []byte) error {
	var err error
	var instancePath string
	var instanceUrl *url.URL
	decoder := schema.NewDecoder()
	if instancePath, err = url.QueryUnescape(ins.instanceId); err != nil {
		return err
	}
	if instanceUrl, err = url.Parse(instancePath); err != nil {
		return err
	}
	if err = decoder.Decode(ins, instanceUrl.Query()); err != nil {
		return err
	}

	ins.Schema = instanceUrl.Scheme
	ins.HostName = instanceUrl.Hostname()
	ins.IPAddr = instanceUrl.Host
	ins.Port, _ = strconv.Atoi(instanceUrl.Port())
	ins.Node = string(data)

	return nil
}
