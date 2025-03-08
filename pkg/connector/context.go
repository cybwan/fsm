package connector

import (
	"context"

	mapset "github.com/deckarep/golang-set"
	corev1 "k8s.io/api/core/v1"
)

// C2KContext is the c2k context for connector controller
type C2KContext struct {

	// EndpointsKeyToName maps from Kube controller keys to Kube endpoints names.
	// Controller keys are in the form <kube namespace>/<kube endpoints name>
	// e.g. default/foo, and are the keys Kube uses to inform that something
	// changed.
	EndpointsKeyToName map[string]string

	// SourceServices holds cloud services that should be synced to Kube.
	// It maps from cloud service name to k8s service name.
	SourceServices map[string]string

	// RawServices holds catalog services: k8sSvcName -> cloudSvcName
	RawServices map[string]string

	// CatalogServices holds catalog services: cloudSvcName -> cloudNamespace
	CatalogServices     map[string]string
	CatalogServicesHash uint64

	// KubeServiceKeyToName maps from Kube controller keys to Kube service names.
	// Controller keys are in the form <kube namespace>/<kube svc name>
	// e.g. default/foo, and are the keys Kube uses to inform that something
	// changed.
	KubeServiceKeyToName map[KubeSvcKey]KubeSvcName

	// SyncedKubeServiceCache holds all Kube services that were created by this sync process. Keys are Kube service names.
	SyncedKubeServiceCache map[KubeSvcName]*corev1.Service
	SyncedKubeServiceHash  map[KubeSvcName]uint64
}

// K2CContext is the k2c context for connector controller
type K2CContext struct {
	//
	// Resource Context
	//

	// ServiceMap holds services we should sync to cloud. Keys are the
	// in the form <kube namespace>/<kube svc name>.
	ServiceMap ConcurrentMap[string, *corev1.Service]

	// EndpointsMap uses the same keys as serviceMap but maps to the endpoints
	// of each service.
	EndpointsMap ConcurrentMap[string, *corev1.Endpoints]

	// IngressServiceMap uses the same keys as serviceMap but maps to the ingress
	// of each service if it exists.
	IngressServiceMap ConcurrentMap[string, ConcurrentMap[string, string]]

	// ServiceHostnameMap maps the name of a service to the hostName and port that
	// is provided by the Ingress resource for the service.
	ServiceHostnameMap ConcurrentMap[string, ServiceAddress]

	// registeredServiceMap holds the services in cloud that we've registered from kube.
	// It's populated via cloud's API and lets us diff what is actually in
	// cloud vs. what we expect to be there.
	RegisteredServiceMap ConcurrentMap[string, []*CatalogRegistration]

	//
	// Syncer Context
	//

	// ServiceNames is all namespaces mapped to a set of valid cloud service names
	ServiceNames ConcurrentMap[string, mapset.Set]

	// Namespaces is all namespaces mapped to a map of cloud service ids mapped to their CatalogRegistrations
	Namespaces ConcurrentMap[string, ConcurrentMap[string, *CatalogRegistration]]

	//deregistrations
	Deregs ConcurrentMap[string, *CatalogDeregistration]

	// Watchers is all namespaces mapped to a map of cloud service
	// names mapped to a cancel function for watcher routines
	Watchers ConcurrentMap[string, ConcurrentMap[string, context.CancelFunc]]
}

// K2GContext is the k2g context for connector controller
type K2GContext struct {
	//
	// Resource Context
	//

	// ServiceMap holds services we should sync to gateway. Keys are the
	// in the form <kube namespace>/<kube svc name>.
	ServiceMap map[string]*corev1.Service

	//
	// Syncer Context
	//
	Services map[string]*corev1.Service
	Deregs   map[string]*corev1.Service
}

func NewC2KContext() *C2KContext {
	return &C2KContext{
		EndpointsKeyToName:     make(map[string]string),
		SourceServices:         make(map[string]string),
		RawServices:            make(map[string]string),
		KubeServiceKeyToName:   make(map[KubeSvcKey]KubeSvcName),
		SyncedKubeServiceCache: make(map[KubeSvcName]*corev1.Service),
		SyncedKubeServiceHash:  make(map[KubeSvcName]uint64),
	}
}

func NewK2CContext() *K2CContext {
	return &K2CContext{
		ServiceMap:           NewConcurrentMap[*corev1.Service](),
		EndpointsMap:         NewConcurrentMap[*corev1.Endpoints](),
		RegisteredServiceMap: NewConcurrentMap[[]*CatalogRegistration](),
		ServiceNames:         NewConcurrentMap[mapset.Set](),
		Namespaces:           NewConcurrentMap[ConcurrentMap[string, *CatalogRegistration]](),
		IngressServiceMap:    NewConcurrentMap[ConcurrentMap[string, string]](),
		ServiceHostnameMap:   NewConcurrentMap[ServiceAddress](),
		Deregs:               NewConcurrentMap[*CatalogDeregistration](),
		Watchers:             NewConcurrentMap[ConcurrentMap[string, context.CancelFunc]](),
	}
}

func NewK2GContext() *K2GContext {
	return &K2GContext{
		ServiceMap: make(map[string]*corev1.Service),
		Services:   make(map[string]*corev1.Service),
		Deregs:     make(map[string]*corev1.Service),
	}
}
