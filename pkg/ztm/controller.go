package ztm

// AgentController is the controller interface for ztm agent
type AgentController interface {
	BroadcastListener(stopCh <-chan struct{})

	Refresh()

	GetAgentName() string
	GetAgentUID() string

	GetClusterSet() string
	SetClusterSet(name, group, zone, region string)
}
