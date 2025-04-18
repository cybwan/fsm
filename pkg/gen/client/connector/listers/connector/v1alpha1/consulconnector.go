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
// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	connectorv1alpha1 "github.com/flomesh-io/fsm/pkg/apis/connector/v1alpha1"
	labels "k8s.io/apimachinery/pkg/labels"
	listers "k8s.io/client-go/listers"
	cache "k8s.io/client-go/tools/cache"
)

// ConsulConnectorLister helps list ConsulConnectors.
// All objects returned here must be treated as read-only.
type ConsulConnectorLister interface {
	// List lists all ConsulConnectors in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*connectorv1alpha1.ConsulConnector, err error)
	// ConsulConnectors returns an object that can list and get ConsulConnectors.
	ConsulConnectors(namespace string) ConsulConnectorNamespaceLister
	ConsulConnectorListerExpansion
}

// consulConnectorLister implements the ConsulConnectorLister interface.
type consulConnectorLister struct {
	listers.ResourceIndexer[*connectorv1alpha1.ConsulConnector]
}

// NewConsulConnectorLister returns a new ConsulConnectorLister.
func NewConsulConnectorLister(indexer cache.Indexer) ConsulConnectorLister {
	return &consulConnectorLister{listers.New[*connectorv1alpha1.ConsulConnector](indexer, connectorv1alpha1.Resource("consulconnector"))}
}

// ConsulConnectors returns an object that can list and get ConsulConnectors.
func (s *consulConnectorLister) ConsulConnectors(namespace string) ConsulConnectorNamespaceLister {
	return consulConnectorNamespaceLister{listers.NewNamespaced[*connectorv1alpha1.ConsulConnector](s.ResourceIndexer, namespace)}
}

// ConsulConnectorNamespaceLister helps list and get ConsulConnectors.
// All objects returned here must be treated as read-only.
type ConsulConnectorNamespaceLister interface {
	// List lists all ConsulConnectors in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*connectorv1alpha1.ConsulConnector, err error)
	// Get retrieves the ConsulConnector from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*connectorv1alpha1.ConsulConnector, error)
	ConsulConnectorNamespaceListerExpansion
}

// consulConnectorNamespaceLister implements the ConsulConnectorNamespaceLister
// interface.
type consulConnectorNamespaceLister struct {
	listers.ResourceIndexer[*connectorv1alpha1.ConsulConnector]
}
