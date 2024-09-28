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
// Code generated by client-gen. DO NOT EDIT.

package v1alpha2

import (
	"context"
	"time"

	v1alpha2 "github.com/flomesh-io/fsm/pkg/apis/policyattachment/v1alpha2"
	scheme "github.com/flomesh-io/fsm/pkg/gen/client/policyattachment/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// BackendLBPoliciesGetter has a method to return a BackendLBPolicyInterface.
// A group's client should implement this interface.
type BackendLBPoliciesGetter interface {
	BackendLBPolicies(namespace string) BackendLBPolicyInterface
}

// BackendLBPolicyInterface has methods to work with BackendLBPolicy resources.
type BackendLBPolicyInterface interface {
	Create(ctx context.Context, backendLBPolicy *v1alpha2.BackendLBPolicy, opts v1.CreateOptions) (*v1alpha2.BackendLBPolicy, error)
	Update(ctx context.Context, backendLBPolicy *v1alpha2.BackendLBPolicy, opts v1.UpdateOptions) (*v1alpha2.BackendLBPolicy, error)
	UpdateStatus(ctx context.Context, backendLBPolicy *v1alpha2.BackendLBPolicy, opts v1.UpdateOptions) (*v1alpha2.BackendLBPolicy, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha2.BackendLBPolicy, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha2.BackendLBPolicyList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha2.BackendLBPolicy, err error)
	BackendLBPolicyExpansion
}

// backendLBPolicies implements BackendLBPolicyInterface
type backendLBPolicies struct {
	client rest.Interface
	ns     string
}

// newBackendLBPolicies returns a BackendLBPolicies
func newBackendLBPolicies(c *GatewayV1alpha2Client, namespace string) *backendLBPolicies {
	return &backendLBPolicies{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the backendLBPolicy, and returns the corresponding backendLBPolicy object, and an error if there is any.
func (c *backendLBPolicies) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha2.BackendLBPolicy, err error) {
	result = &v1alpha2.BackendLBPolicy{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("backendlbpolicies").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of BackendLBPolicies that match those selectors.
func (c *backendLBPolicies) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha2.BackendLBPolicyList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha2.BackendLBPolicyList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("backendlbpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested backendLBPolicies.
func (c *backendLBPolicies) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("backendlbpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a backendLBPolicy and creates it.  Returns the server's representation of the backendLBPolicy, and an error, if there is any.
func (c *backendLBPolicies) Create(ctx context.Context, backendLBPolicy *v1alpha2.BackendLBPolicy, opts v1.CreateOptions) (result *v1alpha2.BackendLBPolicy, err error) {
	result = &v1alpha2.BackendLBPolicy{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("backendlbpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(backendLBPolicy).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a backendLBPolicy and updates it. Returns the server's representation of the backendLBPolicy, and an error, if there is any.
func (c *backendLBPolicies) Update(ctx context.Context, backendLBPolicy *v1alpha2.BackendLBPolicy, opts v1.UpdateOptions) (result *v1alpha2.BackendLBPolicy, err error) {
	result = &v1alpha2.BackendLBPolicy{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("backendlbpolicies").
		Name(backendLBPolicy.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(backendLBPolicy).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *backendLBPolicies) UpdateStatus(ctx context.Context, backendLBPolicy *v1alpha2.BackendLBPolicy, opts v1.UpdateOptions) (result *v1alpha2.BackendLBPolicy, err error) {
	result = &v1alpha2.BackendLBPolicy{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("backendlbpolicies").
		Name(backendLBPolicy.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(backendLBPolicy).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the backendLBPolicy and deletes it. Returns an error if one occurs.
func (c *backendLBPolicies) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("backendlbpolicies").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *backendLBPolicies) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("backendlbpolicies").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched backendLBPolicy.
func (c *backendLBPolicies) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha2.BackendLBPolicy, err error) {
	result = &v1alpha2.BackendLBPolicy{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("backendlbpolicies").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
