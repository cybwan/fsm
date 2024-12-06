package nebula

import (
	"net/url"
	"strconv"

	"github.com/gorilla/schema"

	"github.com/flomesh-io/fsm/pkg/zookeeper"
)

const (
	PickFirstLoadBalance        LoadBalance = "pick_first"
	RoundRobinLoadBalance       LoadBalance = "round_robin"
	WeightRoundRobinLoadBalance LoadBalance = "weight_round_robin"
	ConsistentHashLoadBalance   LoadBalance = "consistent_hash"
)

type LoadBalance string

type InstanceSetting struct {
	Async       bool        `json:"async"`
	Cluster     string      `json:"cluster"`
	LoadBalance LoadBalance `json:"loadbalance,omitempty"`
	Connections uint32      `json:"connections,omitempty"`
	Requests    uint32      `json:"requests,omitempty"`
	Reties      uint32      `json:"reties,omitempty"`
	Timeout     uint32      `json:"timeout,omitempty"`
}

type InstanceService struct {
	Type string `json:"type"`
}

type InstanceReal struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

type InstanceAccess struct {
	Protected bool `json:"protected"`
}

type ServiceInstance struct {
	serviceName string
	instanceId  string

	Schema   string
	HostName string
	IPAddr   string
	Port     int
	Node     string

	Application string             `json:"application"`
	Project     string             `json:"project"`
	Owner       string             `json:"owner"`
	Ops         string             `json:"ops,omitempty"`
	Category    zookeeper.Category `json:"category"`
	Timestamp   uint64             `json:"timestamp"`
	GRPC        string             `json:"grpc"`
	PID         uint32             `json:"pid"`
	Interface   string             `json:"interface"`
	Methods     []string           `json:"methods"`
	Group       bool               `json:"group,omitempty"`
	Weight      uint32             `json:"weight,omitempty"`
	Deprecated  bool               `json:"deprecated"`
	Master      bool               `json:"master"`

	Default InstanceSetting `json:"default"`
	Service InstanceService `json:"service,omitempty"`
	Real    InstanceReal    `json:"real"`
	Access  InstanceAccess  `json:"access,omitempty"`

	Accesslog bool   `json:"accesslog"`
	Anyhost   bool   `json:"anyhost"`
	Dynamic   bool   `json:"dynamic"`
	Token     bool   `json:"token"`
	Side      string `json:"side"`
	Version   string `json:"version"`
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

func (ins *ServiceInstance) InstanceId() string {
	return ins.instanceId
}

func (ins *ServiceInstance) Marshal() ([]byte, error) {
	return nil, nil
}

func (ins *ServiceInstance) Unmarshal(instancePath string, data []byte) error {
	var err error
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
