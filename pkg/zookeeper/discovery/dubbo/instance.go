package dubbo

type ServiceInstance struct {
	serviceName string
	instanceId  string
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
	return nil
}
