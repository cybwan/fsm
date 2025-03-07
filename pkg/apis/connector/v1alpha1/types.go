package v1alpha1

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// +kubebuilder:validation:Enum=ExternalOnly;InternalOnly;ExternalFirst
type NodePortSyncType string

const (
	// ExternalOnly only sync NodePort services with a node's ExternalIP address.
	// Doesn't sync if an ExternalIP doesn't exist.
	ExternalOnly NodePortSyncType = "ExternalOnly"

	// InternalOnly sync NodePort services using.
	InternalOnly NodePortSyncType = "InternalOnly"

	// ExternalFirst sync with an ExternalIP first, if it doesn't exist, use the
	// node's InternalIP address instead.
	ExternalFirst NodePortSyncType = "ExternalFirst"
)

// +kubebuilder:validation:Enum=ExternalIP;ClusterIP
type AddrSelector string

const (
	ExternalIP AddrSelector = "ExternalIP"
	ClusterIP  AddrSelector = "ClusterIP"
)

// +kubebuilder:validation:Enum=proxy;forward
type WithGatewayMode string

const (
	Proxy   WithGatewayMode = "proxy"
	Forward WithGatewayMode = "forward"
)

type K2CGateway struct {
	// +kubebuilder:default=false
	// +optional
	Enable bool `json:"enable,omitempty"`

	// +kubebuilder:default=forward
	// +optional
	GatewayMode WithGatewayMode `json:"gatewayMode,omitempty"`
}

type C2KGateway struct {
	// +kubebuilder:default=false
	// +optional
	Enable bool `json:"enable,omitempty"`

	// +kubebuilder:default=true
	// +optional
	MultiGateways bool `json:"multiGateways,omitempty"`
}

type Connector interface {
	runtime.Object
	metav1.Object
	GetProvider() DiscoveryServiceProvider
	GetReplicas() *int32
	GetResources() *corev1.ResourceRequirements
	GetImagePullSecrets() []corev1.LocalObjectReference
	GetLeaderElection() *bool
}

type DiscoveryServiceProvider string

const (
	//ConsulDiscoveryService defines consul discovery service name
	ConsulDiscoveryService DiscoveryServiceProvider = "consul"

	//EurekaDiscoveryService defines eureka discovery service name
	EurekaDiscoveryService DiscoveryServiceProvider = "eureka"

	//NacosDiscoveryService defines nacos discovery service name
	NacosDiscoveryService DiscoveryServiceProvider = "nacos"

	//ZookeeperDiscoveryService defines zookeeper discovery service name
	ZookeeperDiscoveryService DiscoveryServiceProvider = "zookeeper"

	//MachineDiscoveryService defines machine discovery service name
	MachineDiscoveryService DiscoveryServiceProvider = "machine"

	//GatewayDiscoveryService defines gateway integrated service name
	GatewayDiscoveryService DiscoveryServiceProvider = "gateway"
)

type Metadata struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Limiter struct {
	Limit uint32 `json:"limit"`
	Burst uint32 `json:"burst"`
}

type NamespacedService struct {
	// +optional
	Namespace string `json:"namespace"`

	Service string `json:"service"`
}

type NamespacedServiceOrder []NamespacedService

func (s NamespacedServiceOrder) Len() int { return len(s) }
func (s NamespacedServiceOrder) Less(i, j int) bool {
	if c := strings.Compare(s[i].Namespace, s[j].Namespace); c == 0 {
		return strings.Compare(s[i].Service, s[j].Service) < 0
	} else {
		return c < 0
	}
}
func (s NamespacedServiceOrder) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// ConnectorStatus is the type used to represent the status of a Connector resource.
type ConnectorStatus struct {
	// CurrentStatus defines the current status of a Connector resource.
	// +optional
	CurrentStatus string `json:"currentStatus,omitempty"`

	// Reason defines the reason for the current status of a Connector resource.
	// +optional
	Reason string `json:"reason,omitempty"`

	ToK8SServiceCnt int `json:"toK8SServiceCnt"`

	FromK8SServiceCnt int `json:"fromK8SServiceCnt"`

	CatalogServicesHash uint64 `json:"catalogServicesHash"`
	// +optional
	// +listType=atomic
	CatalogServices []NamespacedService `json:"catalogServices"`
}
