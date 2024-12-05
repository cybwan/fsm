package nebula

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

func (ins *ServiceInstance) Unmarshal(data []byte) error {
	return nil
}
