/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	time "time"

	connectorv1alpha1 "github.com/flomesh-io/fsm/pkg/apis/connector/v1alpha1"
	versioned "github.com/flomesh-io/fsm/pkg/gen/client/connector/clientset/versioned"
	internalinterfaces "github.com/flomesh-io/fsm/pkg/gen/client/connector/informers/externalversions/internalinterfaces"
	v1alpha1 "github.com/flomesh-io/fsm/pkg/gen/client/connector/listers/connector/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// NacosConnectorInformer provides access to a shared informer and lister for
// NacosConnectors.
type NacosConnectorInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.NacosConnectorLister
}

type nacosConnectorInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewNacosConnectorInformer constructs a new informer for NacosConnector type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewNacosConnectorInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredNacosConnectorInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredNacosConnectorInformer constructs a new informer for NacosConnector type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredNacosConnectorInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.ConnectorV1alpha1().NacosConnectors().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.ConnectorV1alpha1().NacosConnectors().Watch(context.TODO(), options)
			},
		},
		&connectorv1alpha1.NacosConnector{},
		resyncPeriod,
		indexers,
	)
}

func (f *nacosConnectorInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredNacosConnectorInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *nacosConnectorInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&connectorv1alpha1.NacosConnector{}, f.defaultInformer)
}

func (f *nacosConnectorInformer) Lister() v1alpha1.NacosConnectorLister {
	return v1alpha1.NewNacosConnectorLister(f.Informer().GetIndexer())
}