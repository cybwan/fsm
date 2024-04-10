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
// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

import (
	policyattachmentv1alpha1 "github.com/flomesh-io/fsm/pkg/apis/policyattachment/v1alpha1"
	v1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

// LoadBalancerPolicySpecApplyConfiguration represents an declarative configuration of the LoadBalancerPolicySpec type for use
// with apply.
type LoadBalancerPolicySpecApplyConfiguration struct {
	TargetRef   *v1alpha2.PolicyTargetReference            `json:"targetRef,omitempty"`
	Ports       []PortLoadBalancerApplyConfiguration       `json:"ports,omitempty"`
	DefaultType *policyattachmentv1alpha1.LoadBalancerType `json:"type,omitempty"`
}

// LoadBalancerPolicySpecApplyConfiguration constructs an declarative configuration of the LoadBalancerPolicySpec type for use with
// apply.
func LoadBalancerPolicySpec() *LoadBalancerPolicySpecApplyConfiguration {
	return &LoadBalancerPolicySpecApplyConfiguration{}
}

// WithTargetRef sets the TargetRef field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TargetRef field is set to the value of the last call.
func (b *LoadBalancerPolicySpecApplyConfiguration) WithTargetRef(value v1alpha2.PolicyTargetReference) *LoadBalancerPolicySpecApplyConfiguration {
	b.TargetRef = &value
	return b
}

// WithPorts adds the given value to the Ports field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Ports field.
func (b *LoadBalancerPolicySpecApplyConfiguration) WithPorts(values ...*PortLoadBalancerApplyConfiguration) *LoadBalancerPolicySpecApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithPorts")
		}
		b.Ports = append(b.Ports, *values[i])
	}
	return b
}

// WithDefaultType sets the DefaultType field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DefaultType field is set to the value of the last call.
func (b *LoadBalancerPolicySpecApplyConfiguration) WithDefaultType(value policyattachmentv1alpha1.LoadBalancerType) *LoadBalancerPolicySpecApplyConfiguration {
	b.DefaultType = &value
	return b
}