package nebula

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/flomesh-io/fsm/pkg/zookeeper/discovery"
)

type Ops struct {
}

func (op *Ops) NewInstance(serviceName, instanceId string) discovery.ServiceInstance {
	return NewServiceInstance(serviceName, instanceId)
}

func (op *Ops) PathForService(basePath, serviceName string) string {
	return path.Join(basePath, serviceName)
}

func (op *Ops) PathForInstance(basePath, serviceName, instanceId string) string {
	return path.Join(basePath, serviceName, instanceId)
}

func (op *Ops) KtoCName(serviceName string) string {
	if strings.EqualFold(serviceName, "greeter") {
		return "com.orientsec.demo.Greeter"
	}
	return ""
}

func (op *Ops) CToKName(serviceName string) string {
	if strings.EqualFold(serviceName, "com.orientsec.demo.Greeter") {
		return "greeter"
	}
	return ""
}

func (op *Ops) ServiceInstanceId(basePath, instancePath string) (string, string, error) {
	instancePath = strings.TrimPrefix(instancePath, basePath)
	instancePath = strings.TrimPrefix(instancePath, string(os.PathSeparator))
	pathSlice := strings.Split(instancePath, string(os.PathSeparator))
	if len(pathSlice) < 2 {
		return "", "", fmt.Errorf("[ServiceDiscovery] path{%s} dont contain name and id", instancePath)
	}
	serviceName := pathSlice[0]
	instanceId := pathSlice[1]
	return serviceName, instanceId, nil
}
