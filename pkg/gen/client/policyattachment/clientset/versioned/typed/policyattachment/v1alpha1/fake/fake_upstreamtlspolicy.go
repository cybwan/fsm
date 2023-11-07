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

package fake

import (
	"context"

	v1alpha1 "github.com/flomesh-io/fsm/pkg/apis/policyattachment/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeUpstreamTLSPolicies implements UpstreamTLSPolicyInterface
type FakeUpstreamTLSPolicies struct {
	Fake *FakeGatewayV1alpha1
	ns   string
}

var upstreamtlspoliciesResource = schema.GroupVersionResource{Group: "gateway.flomesh.io", Version: "v1alpha1", Resource: "upstreamtlspolicies"}

var upstreamtlspoliciesKind = schema.GroupVersionKind{Group: "gateway.flomesh.io", Version: "v1alpha1", Kind: "UpstreamTLSPolicy"}

// Get takes name of the upstreamTLSPolicy, and returns the corresponding upstreamTLSPolicy object, and an error if there is any.
func (c *FakeUpstreamTLSPolicies) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.UpstreamTLSPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(upstreamtlspoliciesResource, c.ns, name), &v1alpha1.UpstreamTLSPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.UpstreamTLSPolicy), err
}

// List takes label and field selectors, and returns the list of UpstreamTLSPolicies that match those selectors.
func (c *FakeUpstreamTLSPolicies) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.UpstreamTLSPolicyList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(upstreamtlspoliciesResource, upstreamtlspoliciesKind, c.ns, opts), &v1alpha1.UpstreamTLSPolicyList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.UpstreamTLSPolicyList{ListMeta: obj.(*v1alpha1.UpstreamTLSPolicyList).ListMeta}
	for _, item := range obj.(*v1alpha1.UpstreamTLSPolicyList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested upstreamTLSPolicies.
func (c *FakeUpstreamTLSPolicies) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(upstreamtlspoliciesResource, c.ns, opts))

}

// Create takes the representation of a upstreamTLSPolicy and creates it.  Returns the server's representation of the upstreamTLSPolicy, and an error, if there is any.
func (c *FakeUpstreamTLSPolicies) Create(ctx context.Context, upstreamTLSPolicy *v1alpha1.UpstreamTLSPolicy, opts v1.CreateOptions) (result *v1alpha1.UpstreamTLSPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(upstreamtlspoliciesResource, c.ns, upstreamTLSPolicy), &v1alpha1.UpstreamTLSPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.UpstreamTLSPolicy), err
}

// Update takes the representation of a upstreamTLSPolicy and updates it. Returns the server's representation of the upstreamTLSPolicy, and an error, if there is any.
func (c *FakeUpstreamTLSPolicies) Update(ctx context.Context, upstreamTLSPolicy *v1alpha1.UpstreamTLSPolicy, opts v1.UpdateOptions) (result *v1alpha1.UpstreamTLSPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(upstreamtlspoliciesResource, c.ns, upstreamTLSPolicy), &v1alpha1.UpstreamTLSPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.UpstreamTLSPolicy), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeUpstreamTLSPolicies) UpdateStatus(ctx context.Context, upstreamTLSPolicy *v1alpha1.UpstreamTLSPolicy, opts v1.UpdateOptions) (*v1alpha1.UpstreamTLSPolicy, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(upstreamtlspoliciesResource, "status", c.ns, upstreamTLSPolicy), &v1alpha1.UpstreamTLSPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.UpstreamTLSPolicy), err
}

// Delete takes name of the upstreamTLSPolicy and deletes it. Returns an error if one occurs.
func (c *FakeUpstreamTLSPolicies) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(upstreamtlspoliciesResource, c.ns, name, opts), &v1alpha1.UpstreamTLSPolicy{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeUpstreamTLSPolicies) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(upstreamtlspoliciesResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.UpstreamTLSPolicyList{})
	return err
}

// Patch applies the patch and returns the patched upstreamTLSPolicy.
func (c *FakeUpstreamTLSPolicies) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.UpstreamTLSPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(upstreamtlspoliciesResource, c.ns, name, pt, data, subresources...), &v1alpha1.UpstreamTLSPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.UpstreamTLSPolicy), err
}
