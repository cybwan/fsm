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
		ins.instanceId = url.QueryEscape(instanceUrl.String())
		return []byte(ins.instanceId), nil
	}
}

func (ins *ServiceInstance) Unmarshal(instanceId string, data []byte) error {
	var err error
	var instancePath string
	var instanceUrl *url.URL

	if len(instanceId) > 0 {
		if instancePath, err = url.QueryUnescape(instanceId); err != nil {
			return err
		}
	} else {
		if instancePath, err = url.QueryUnescape(ins.instanceId); err != nil {
			return err
		}
	}

	if instanceUrl, err = url.Parse(instancePath); err != nil {
		return err
	}
	if len(instanceUrl.RawQuery) > 0 {
		if err = urlenc.Decode([]byte(instanceUrl.RawQuery), ins); err != nil {
			fmt.Println(err.Error())
			return err
		}
	}
	ins.Schema = instanceUrl.Scheme
	ins.Addr = instanceUrl.Host
	ins.IP = instanceUrl.Hostname()
	ins.Port, _ = strconv.Atoi(instanceUrl.Port())
	ins.Node = string(data)
	return nil
}

func (ins *ServiceInstance) InstanceIP() string {
	return ins.IP
}

func (ins *ServiceInstance) InstancePort() int {
	return ins.Port
}

func (ins *ServiceInstance) GetMetadata(key string) (string, bool) {
	switch key {
	case connector.ClusterSetKey:
		return ins.FsmConnectorServiceClusterSet, true
	case connector.ConnectUIDKey:
		return ins.FsmConnectorServiceConnectorUid, true
	case "interface":
		return ins.Interface, true
	case "methods":
		return ins.Methods, true
	case "application":
		return ins.Application, true
	case "project":
		return ins.Project, true
	case "owner":
		return ins.Owner, true
	case "ops":
		return ins.Ops, true
	case "category":
		return ins.Category, true
	case "timestamp":
		return fmt.Sprintf("%d", ins.Timestamp), true
	case "grpc":
		return ins.GRPC, true
	case "pid":
		return fmt.Sprintf("%d", ins.PID), true
	case "group":
		return fmt.Sprintf("%t", ins.Group), true
	case "weight":
		return fmt.Sprintf("%d", ins.Weight), true
	case "deprecated":
		return fmt.Sprintf("%t", ins.Deprecated), true
	case "master":
		return fmt.Sprintf("%t", ins.Master), true
	case "default.async":
		return fmt.Sprintf("%t", ins.DefaultAsync), true
	case "default.cluster":
		return ins.DefaultCluster, true
	case "default.connections":
		return fmt.Sprintf("%d", ins.DefaultConnections), true
	case "default.loadbalance":
		return ins.DefaultLoadBalance, true
	case "default.requests":
		return fmt.Sprintf("%d", ins.DefaultRequests), true
	case "default.reties":
		return fmt.Sprintf("%d", ins.DefaultReties), true
	case "default.timeout":
		return fmt.Sprintf("%d", ins.DefaultTimeout), true
	case "service.type":
		return ins.ServiceType, true
	case "real.ip":
		return ins.RealIP, true
	case "real.port":
		return fmt.Sprintf("%d", ins.RealPort), true
	case "access.protected":
		return fmt.Sprintf("%t", ins.AccessProtected), true
	case "accesslog":
		return fmt.Sprintf("%t", ins.Accesslog), true
	case "anyhost":
		return fmt.Sprintf("%t", ins.Anyhost), true
	case "dynamic":
		return fmt.Sprintf("%t", ins.Dynamic), true
	case "token":
		return fmt.Sprintf("%t", ins.Token), true
	case "side":
		return ins.Side, true
	case "version":
		return ins.Version, true
	default:
		return "", false
	}
}

func (ins *ServiceInstance) SetMetadata(key, value string) bool {
	switch key {
	case connector.ClusterSetKey:
		ins.FsmConnectorServiceClusterSet = value
		return true
	case connector.ConnectUIDKey:
		ins.FsmConnectorServiceConnectorUid = value
		return true
	case "interface":
		ins.Interface = value
		return true
	case "methods":
		ins.Methods = value
		return true
	case "application":
		ins.Application = value
		return true
	case "project":
		ins.Project = value
		return true
	case "owner":
		ins.Owner = value
		return true
	case "ops":
		ins.Ops = value
		return true
	case "category":
		ins.Category = value
		return true
	case "timestamp":
		if timestamp, err := strconv.ParseUint(value, 10, 64); err == nil {
			ins.Timestamp = timestamp
			return true
		} else {
			return false
		}
	case "grpc":
		ins.GRPC = value
		return true
	case "pid":
		if pid, err := strconv.Atoi(value); err == nil {
			ins.PID = uint32(pid)
			return true
		} else {
			return false
		}
	case "group":
		if group, err := strconv.ParseBool(value); err == nil {
			ins.Group = group
			return true
		} else {
			return false
		}
	case "weight":
		if weight, err := strconv.Atoi(value); err == nil {
			ins.Weight = uint32(weight)
			return true
		} else {
			return false
		}
	case "deprecated":
		if deprecated, err := strconv.ParseBool(value); err == nil {
			ins.Deprecated = deprecated
			return true
		} else {
			return false
		}
	case "master":
		if master, err := strconv.ParseBool(value); err == nil {
			ins.Master = master
			return true
		} else {
			return false
		}
	case "default.async":
		if async, err := strconv.ParseBool(value); err == nil {
			ins.DefaultAsync = async
			return true
		} else {
			return false
		}
	case "default.cluster":
		ins.DefaultCluster = value
		return true
	case "default.connections":
		if connections, err := strconv.Atoi(value); err == nil {
			ins.DefaultConnections = uint32(connections)
			return true
		} else {
			return false
		}
	case "default.loadbalance":
		ins.DefaultLoadBalance = value
		return true
	case "default.requests":
		if requests, err := strconv.Atoi(value); err == nil {
			ins.DefaultRequests = uint32(requests)
			return true
		} else {
			return false
		}
	case "default.reties":
		if reties, err := strconv.Atoi(value); err == nil {
			ins.DefaultReties = uint32(reties)
			return true
		} else {
			return false
		}
	case "default.timeout":
		if timeout, err := strconv.Atoi(value); err == nil {
			ins.DefaultTimeout = uint32(timeout)
			return true
		} else {
			return false
		}
	case "service.type":
		ins.ServiceType = value
		return true
	case "real.ip":
		ins.RealIP = value
		return true
	case "real.port":
		if port, err := strconv.Atoi(value); err == nil {
			ins.RealPort = uint16(port)
			return true
		} else {
			return false
		}
	case "access.protected":
		if protected, err := strconv.ParseBool(value); err == nil {
			ins.AccessProtected = protected
			return true
		} else {
			return false
		}
	case "accesslog":
		if accesslog, err := strconv.ParseBool(value); err == nil {
			ins.Accesslog = accesslog
			return true
		} else {
			return false
		}
	case "anyhost":
		if anyhost, err := strconv.ParseBool(value); err == nil {
			ins.Anyhost = anyhost
			return true
		} else {
			return false
		}
	case "dynamic":
		if dynamic, err := strconv.ParseBool(value); err == nil {
			ins.Dynamic = dynamic
			return true
		} else {
			return false
		}
	case "token":
		if token, err := strconv.ParseBool(value); err == nil {
			ins.Token = token
			return true
		} else {
			return false
		}
	case "side":
		ins.Side = value
		return true
	case "version":
		ins.Version = value
		return true
	default:
		return false
	}
}

func (ins *ServiceInstance) Metadatas() map[string]string {
	metadata := map[string]string{
		"interface":   ins.Interface,
		"methods":     ins.Methods,
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

		"fsm.connector.service.cluster.set":   ins.FsmConnectorServiceClusterSet,
		"fsm.connector.service.connector.uid": ins.FsmConnectorServiceConnectorUid,
	}

	return metadata
}
