package connector

import (
	"encoding/base64"
	"encoding/json"
	"net"
)

// MicroSvcName defines string as microservice name
type MicroSvcName string

// MicroSvcDomainName defines string as microservice domain name
type MicroSvcDomainName string

// MicroEndpointAddr defines string as micro endpoint addr
type MicroEndpointAddr string

// To4 converts the IPv4 address ip to a 4-byte representation.
// If ip is not an IPv4 address, To4 returns nil.
func (addr MicroEndpointAddr) To4() net.IP {
	return net.ParseIP(string(addr)).To4()
}

// To16 converts the IP address ip to a 16-byte representation.
// If ip is not an IP address (it is the wrong length), To16 returns nil.
func (addr MicroEndpointAddr) To16() net.IP {
	return net.ParseIP(string(addr)).To16()
}

// MicroSvcPort defines int as micro service port
type MicroSvcPort int

// MicroSvcAppProtocol defines app protocol
type MicroSvcAppProtocol string

// MicroEndpointMeta defines micro endpoint meta
type MicroEndpointMeta struct {
	Ports             map[MicroSvcPort]MicroSvcAppProtocol
	Address           MicroEndpointAddr
	ClusterSet        string
	ClusterId         string
	InternalSync      bool
	WithGateway       bool
	WithMultiGateways bool
	ViaGateway        string
	BindFgwPorts      map[MicroSvcPort]MicroSvcAppProtocol
}

// MicroSvcMeta defines micro service meta
type MicroSvcMeta struct {
	Ports       map[MicroSvcPort]MicroSvcAppProtocol
	Endpoints   map[MicroEndpointAddr]*MicroEndpointMeta
	HealthCheck bool
}

func (m *MicroSvcMeta) Decode(str string) {
	if bytes, err := base64.StdEncoding.DecodeString(str); err == nil {
		_ = json.Unmarshal(bytes, m)
	}
}

func (m *MicroSvcMeta) Encode() string {
	if bytes, err := json.Marshal(m); err == nil {
		return base64.StdEncoding.EncodeToString(bytes)
	}
	return ""
}

func (m *MicroSvcMeta) Unmarshal(str string) {
	_ = json.Unmarshal([]byte(str), m)
}

func (m *MicroSvcMeta) Marshal() string {
	if bytes, err := json.Marshal(m); err == nil {
		return string(bytes)
	}
	return ""
}
