package nebula

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/flomesh-io/fsm/pkg/connector"
	"github.com/flomesh-io/fsm/pkg/zookeeper/discovery/nebula/urlenc"
)

const (
	PickFirstLoadBalance        = "pick_first"
	RoundRobinLoadBalance       = "round_robin"
	WeightRoundRobinLoadBalance = "weight_round_robin"
	ConsistentHashLoadBalance   = "consistent_hash"
)

type ServiceInstance struct {
	serviceName string
	instanceId  string

	Schema string `urlenc:"-"`
	Addr   string `urlenc:"-"`
	IP     string `urlenc:"-"`
	Port   int    `urlenc:"-"`
	Node   string `urlenc:"-"`

	Interface string `urlenc:"interface"`
	Methods   string `urlenc:"methods"`

	Application string `urlenc:"application"`
	Project     string `urlenc:"project"`
	Owner       string `urlenc:"owner"`
	Ops         string `urlenc:"ops,omitempty"`
	Category    string `urlenc:"category"`
	Timestamp   uint64 `urlenc:"timestamp"`
	GRPC        string `urlenc:"grpc"`
	PID         uint32 `urlenc:"pid"`
	Group       bool   `urlenc:"group,omitempty"`
	Weight      uint32 `urlenc:"weight"`
	Deprecated  bool   `urlenc:"deprecated"`
	Master      bool   `urlenc:"master"`

	DefaultAsync       bool   `urlenc:"default.async"`
	DefaultCluster     string `urlenc:"default.cluster"`
	DefaultConnections uint32 `urlenc:"default.connections"`
	DefaultLoadBalance string `urlenc:"default.loadbalance"`
	DefaultRequests    uint32 `urlenc:"default.requests"`
	DefaultReties      uint32 `urlenc:"default.reties"`
	DefaultTimeout     uint32 `urlenc:"default.timeout"`

	ServiceType     string `urlenc:"service.type"`
	RealIP          string `urlenc:"real.ip"`
	RealPort        uint16 `urlenc:"real.port"`
	AccessProtected bool   `urlenc:"access.protected"`

	Accesslog bool   `urlenc:"accesslog"`
	Anyhost   bool   `urlenc:"anyhost"`
	Dynamic   bool   `urlenc:"dynamic"`
	Token     bool   `urlenc:"token"`
	Side      string `urlenc:"side"`
	Version   string `urlenc:"version"`

	FsmConnectorServiceClusterSet   string `urlenc:"fsm.connector.service.cluster.set,omitempty"`
	FsmConnectorServiceConnectorUid string `urlenc:"fsm.connector.service.connector.uid,omitempty"`
}

func NewServiceInstance(serviceName, instanceId string) *ServiceInstance {
	return &ServiceInstance{
		serviceName:        serviceName,
		instanceId:         instanceId,
		AccessProtected:    false,
		DefaultConnections: 20,
		DefaultRequests:    2000,
		DefaultLoadBalance: PickFirstLoadBalance,
		Weight:             100,
		Deprecated:         false,
		Master:             true,
	}
}

func (ins *ServiceInstance) ServiceName() string {
	return ins.serviceName
}

func (ins *ServiceInstance) ServiceSchema() string {
	return ins.Schema
}

func (ins *ServiceInstance) ServiceInterface() string {
	return ins.Interface
}

func (ins *ServiceInstance) ServiceMethods() []string {
	var methods []string
	if len(ins.Methods) > 0 {
		segs := strings.Split(ins.Methods, `,`)
		if len(segs) > 0 {
			for _, method := range segs {
				if len(method) > 0 {
					methods = append(methods, method)
				}
			}
		}
	}
	return methods
}

func (ins *ServiceInstance) InstanceId() string {
	return ins.instanceId
}

func (ins *ServiceInstance) InstanceIP() string {
	return ins.IP
}

func (ins *ServiceInstance) InstancePort() int {
	return ins.Port
}

func (ins *ServiceInstance) Metadata(key string) (string, bool) {
	switch key {
	case connector.ClusterSetKey:
		return ins.FsmConnectorServiceClusterSet, true
	case connector.ConnectUIDKey:
		return ins.FsmConnectorServiceConnectorUid, true
	default:
		return "", false
	}
}

func (ins *ServiceInstance) Metadatas() map[string]string {
	metadata := map[string]string{
		"application": ins.Application,
		"project":     ins.Project,
		"owner":       ins.Owner,
		"ops":         ins.Ops,
		"category":    ins.Category,
		"timestamp":   fmt.Sprintf("%d", ins.Timestamp),
		"grpc":        ins.GRPC,
		"pid":         fmt.Sprintf("%d", ins.PID),
		"group":       fmt.Sprintf("%t", ins.Group),
		"weight":      fmt.Sprintf("%d", ins.Weight),
		"deprecated":  fmt.Sprintf("%t", ins.Deprecated),
		"master":      fmt.Sprintf("%t", ins.Master),

		"default.async":       fmt.Sprintf("%t", ins.DefaultAsync),
		"default.cluster":     ins.DefaultCluster,
		"default.connections": fmt.Sprintf("%d", ins.DefaultConnections),
		"default.loadbalance": ins.DefaultLoadBalance,
		"default.requests":    fmt.Sprintf("%d", ins.DefaultRequests),
		"default.reties":      fmt.Sprintf("%d", ins.DefaultReties),
		"default.timeout":     fmt.Sprintf("%d", ins.DefaultTimeout),

		"service.type":     ins.ServiceType,
		"real.ip":          ins.RealIP,
		"real.port":        fmt.Sprintf("%d", ins.RealPort),
		"access.protected": fmt.Sprintf("%t", ins.AccessProtected),

		"accesslog": fmt.Sprintf("%t", ins.Accesslog),
		"anyhost":   fmt.Sprintf("%t", ins.Anyhost),
		"dynamic":   fmt.Sprintf("%t", ins.Dynamic),
		"token":     fmt.Sprintf("%t", ins.Token),
		"side":      ins.Side,
		"version":   ins.Version,

		"fsm.connector.service.cluster.set,omitempty":   ins.FsmConnectorServiceClusterSet,
		"fsm.connector.service.connector.uid,omitempty": ins.FsmConnectorServiceConnectorUid,
	}

	return metadata
}

func (ins *ServiceInstance) Marshal() ([]byte, error) {
	if bytes, err := urlenc.Encode(ins); err != nil {
		return nil, err
	} else {
		instanceUrl := url.URL{
			Scheme:   ins.Schema,
			Host:     ins.Addr,
			RawQuery: string(bytes),
		}
		if len(instanceUrl.Host) == 0 {
			instanceUrl.Host = fmt.Sprintf("%s:%d", ins.IP, ins.Port)
		}
		return []byte(url.QueryEscape(instanceUrl.String())), nil
	}
}

func (ins *ServiceInstance) Unmarshal(_ string, data []byte) error {
	var err error
	var instancePath string
	var instanceUrl *url.URL

	if instancePath, err = url.QueryUnescape(ins.instanceId); err != nil {
		return err
	}
	if instanceUrl, err = url.Parse(instancePath); err != nil {
		return err
	}
	if err = urlenc.Decode([]byte(instanceUrl.RawQuery), ins); err != nil {
		fmt.Println(err.Error())
		return err
	}
	ins.Schema = instanceUrl.Scheme
	ins.Addr = instanceUrl.Host
	ins.IP = instanceUrl.Hostname()
	ins.Port, _ = strconv.Atoi(instanceUrl.Port())
	ins.Node = string(data)
	return nil
}
