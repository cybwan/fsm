package dubbo

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
	serviceInstance := ServiceInstance{
		serviceName: serviceName,
		instanceId:  instanceId,
	}
	return &serviceInstance
}

func (op *Ops) PathForService(basePath, serviceName string) string {
	return path.Join(basePath, serviceName)
}

func (op *Ops) PathForInstance(basePath, serviceName, instanceId string) string {
	return path.Join(basePath, serviceName, instanceId)
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
