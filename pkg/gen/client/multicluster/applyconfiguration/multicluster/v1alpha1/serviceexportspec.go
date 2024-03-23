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
	apis "github.com/flomesh-io/fsm/pkg/apis"
)

// ServiceExportSpecApplyConfiguration represents an declarative configuration of the ServiceExportSpec type for use
// with apply.
type ServiceExportSpecApplyConfiguration struct {
	PathRewrite        *PathRewriteApplyConfiguration        `json:"pathRewrite,omitempty"`
	SessionSticky      *bool                                 `json:"sessionSticky,omitempty"`
	LoadBalancer       *apis.AlgoBalancer                    `json:"loadBalancer,omitempty"`
	Rules              []ServiceExportRuleApplyConfiguration `json:"rules,omitempty"`
	TargetClusters     []string                              `json:"targetClusters,omitempty"`
	ServiceAccountName *string                               `json:"serviceAccountName,omitempty"`
}

// ServiceExportSpecApplyConfiguration constructs an declarative configuration of the ServiceExportSpec type for use with
// apply.
func ServiceExportSpec() *ServiceExportSpecApplyConfiguration {
	return &ServiceExportSpecApplyConfiguration{}
}

// WithPathRewrite sets the PathRewrite field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the PathRewrite field is set to the value of the last call.
func (b *ServiceExportSpecApplyConfiguration) WithPathRewrite(value *PathRewriteApplyConfiguration) *ServiceExportSpecApplyConfiguration {
	b.PathRewrite = value
	return b
}

// WithSessionSticky sets the SessionSticky field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SessionSticky field is set to the value of the last call.
func (b *ServiceExportSpecApplyConfiguration) WithSessionSticky(value bool) *ServiceExportSpecApplyConfiguration {
	b.SessionSticky = &value
	return b
}

// WithLoadBalancer sets the LoadBalancer field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the LoadBalancer field is set to the value of the last call.
func (b *ServiceExportSpecApplyConfiguration) WithLoadBalancer(value apis.AlgoBalancer) *ServiceExportSpecApplyConfiguration {
	b.LoadBalancer = &value
	return b
}

// WithRules adds the given value to the Rules field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Rules field.
func (b *ServiceExportSpecApplyConfiguration) WithRules(values ...*ServiceExportRuleApplyConfiguration) *ServiceExportSpecApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithRules")
		}
		b.Rules = append(b.Rules, *values[i])
	}
	return b
}

// WithTargetClusters adds the given value to the TargetClusters field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the TargetClusters field.
func (b *ServiceExportSpecApplyConfiguration) WithTargetClusters(values ...string) *ServiceExportSpecApplyConfiguration {
	for i := range values {
		b.TargetClusters = append(b.TargetClusters, values[i])
	}
	return b
}

// WithServiceAccountName sets the ServiceAccountName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ServiceAccountName field is set to the value of the last call.
func (b *ServiceExportSpecApplyConfiguration) WithServiceAccountName(value string) *ServiceExportSpecApplyConfiguration {
	b.ServiceAccountName = &value
	return b
}