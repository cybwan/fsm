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

// ConsulSyncToK8SSpecApplyConfiguration represents an declarative configuration of the ConsulSyncToK8SSpec type for use
// with apply.
type ConsulSyncToK8SSpecApplyConfiguration struct {
	Enable          *bool                        `json:"enable,omitempty"`
	ClusterId       *string                      `json:"clusterId,omitempty"`
	PassingOnly     *bool                        `json:"passingOnly,omitempty"`
	FilterTag       *string                      `json:"filterTag,omitempty"`
	PrefixTag       *string                      `json:"prefixTag,omitempty"`
	SuffixTag       *string                      `json:"suffixTag,omitempty"`
	FilterMetadatas []MetadataApplyConfiguration `json:"filterMetadatas,omitempty"`
	PrefixMetadata  *string                      `json:"prefixMetadata,omitempty"`
	SuffixMetadata  *string                      `json:"suffixMetadata,omitempty"`
	WithGateway     *bool                        `json:"withGateway,omitempty"`
}

// ConsulSyncToK8SSpecApplyConfiguration constructs an declarative configuration of the ConsulSyncToK8SSpec type for use with
// apply.
func ConsulSyncToK8SSpec() *ConsulSyncToK8SSpecApplyConfiguration {
	return &ConsulSyncToK8SSpecApplyConfiguration{}
}

// WithEnable sets the Enable field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Enable field is set to the value of the last call.
func (b *ConsulSyncToK8SSpecApplyConfiguration) WithEnable(value bool) *ConsulSyncToK8SSpecApplyConfiguration {
	b.Enable = &value
	return b
}

// WithClusterId sets the ClusterId field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ClusterId field is set to the value of the last call.
func (b *ConsulSyncToK8SSpecApplyConfiguration) WithClusterId(value string) *ConsulSyncToK8SSpecApplyConfiguration {
	b.ClusterId = &value
	return b
}

// WithPassingOnly sets the PassingOnly field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the PassingOnly field is set to the value of the last call.
func (b *ConsulSyncToK8SSpecApplyConfiguration) WithPassingOnly(value bool) *ConsulSyncToK8SSpecApplyConfiguration {
	b.PassingOnly = &value
	return b
}

// WithFilterTag sets the FilterTag field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the FilterTag field is set to the value of the last call.
func (b *ConsulSyncToK8SSpecApplyConfiguration) WithFilterTag(value string) *ConsulSyncToK8SSpecApplyConfiguration {
	b.FilterTag = &value
	return b
}

// WithPrefixTag sets the PrefixTag field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the PrefixTag field is set to the value of the last call.
func (b *ConsulSyncToK8SSpecApplyConfiguration) WithPrefixTag(value string) *ConsulSyncToK8SSpecApplyConfiguration {
	b.PrefixTag = &value
	return b
}

// WithSuffixTag sets the SuffixTag field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SuffixTag field is set to the value of the last call.
func (b *ConsulSyncToK8SSpecApplyConfiguration) WithSuffixTag(value string) *ConsulSyncToK8SSpecApplyConfiguration {
	b.SuffixTag = &value
	return b
}

// WithFilterMetadatas adds the given value to the FilterMetadatas field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the FilterMetadatas field.
func (b *ConsulSyncToK8SSpecApplyConfiguration) WithFilterMetadatas(values ...*MetadataApplyConfiguration) *ConsulSyncToK8SSpecApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithFilterMetadatas")
		}
		b.FilterMetadatas = append(b.FilterMetadatas, *values[i])
	}
	return b
}

// WithPrefixMetadata sets the PrefixMetadata field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the PrefixMetadata field is set to the value of the last call.
func (b *ConsulSyncToK8SSpecApplyConfiguration) WithPrefixMetadata(value string) *ConsulSyncToK8SSpecApplyConfiguration {
	b.PrefixMetadata = &value
	return b
}

// WithSuffixMetadata sets the SuffixMetadata field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SuffixMetadata field is set to the value of the last call.
func (b *ConsulSyncToK8SSpecApplyConfiguration) WithSuffixMetadata(value string) *ConsulSyncToK8SSpecApplyConfiguration {
	b.SuffixMetadata = &value
	return b
}

// WithWithGateway sets the WithGateway field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the WithGateway field is set to the value of the last call.
func (b *ConsulSyncToK8SSpecApplyConfiguration) WithWithGateway(value bool) *ConsulSyncToK8SSpecApplyConfiguration {
	b.WithGateway = &value
	return b
}