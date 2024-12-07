package dubbo

type ServiceInstance struct {
	serviceName string
	instanceId  string
}

func (ins *ServiceInstance) ServiceSchema() string {
	//TODO implement me
	panic("implement me")
}

func (ins *ServiceInstance) InstanceAddr() string {
	//TODO implement me
	panic("implement me")
}

func (ins *ServiceInstance) InstancePort() int {
	//TODO implement me
	panic("implement me")
}

func (ins *ServiceInstance) Metadata(key string) (string, bool) {
	//TODO implement me
	panic("implement me")
}

func (ins *ServiceInstance) Metadatas() map[string]string {
	//TODO implement me
	panic("implement me")
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
