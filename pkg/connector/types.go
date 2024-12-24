package connector

import (
	"github.com/flomesh-io/fsm/pkg/constants"
	"github.com/flomesh-io/fsm/pkg/logger"
)

var (
	log = logger.New("connector")
)

const (
	ProtocolHTTP = MicroSvcProtocol(constants.ProtocolHTTP)
	ProtocolGRPC = MicroSvcProtocol(constants.ProtocolGRPC)
)

// MicroSvcProtocol defines string as microservice protocol
type MicroSvcProtocol string

func (p *MicroSvcProtocol) Get() string {
	return string(*p)
}

func (p *MicroSvcProtocol) Set(protocol string) {
	*p = MicroSvcProtocol(protocol)
}

func (p *MicroSvcProtocol) Empty() bool {
	return len(*p) == 0
}

// MicroSvcPort defines int as microservice port
type MicroSvcPort int

func (p *MicroSvcPort) Get() int {
	return int(*p)
}

func (p *MicroSvcPort) Set(port int) {
	*p = MicroSvcPort(port)
}

// MicroSvcAddress defines string as microservice address
type MicroSvcAddress string

func (a *MicroSvcAddress) Get() string {
	return string(*a)
}

func (a *MicroSvcAddress) Set(addr string) {
	*a = MicroSvcAddress(addr)
}

type NamespaceService struct {
	Namespace string
	Service   string
}

type MicroService struct {
	NamespaceService

	Protocol   MicroSvcProtocol
	Address    MicroSvcAddress
	Port       MicroSvcPort
	ViaAddress MicroSvcAddress
	ViaPort    MicroSvcPort
}

func (s *MicroService) SetHTTPPort(port int) {
	s.Port = MicroSvcPort(port)
	s.Protocol = ProtocolHTTP
}

func (s *MicroService) SetGRPCPort(port int) {
	s.Port = MicroSvcPort(port)
	s.Protocol = ProtocolGRPC
}
