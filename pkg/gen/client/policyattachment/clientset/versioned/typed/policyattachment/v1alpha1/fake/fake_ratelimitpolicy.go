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
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeRateLimitPolicies implements RateLimitPolicyInterface
type FakeRateLimitPolicies struct {
	Fake *FakeGatewayV1alpha1
	ns   string
}

var ratelimitpoliciesResource = v1alpha1.SchemeGroupVersion.WithResource("ratelimitpolicies")

var ratelimitpoliciesKind = v1alpha1.SchemeGroupVersion.WithKind("RateLimitPolicy")

// Get takes name of the rateLimitPolicy, and returns the corresponding rateLimitPolicy object, and an error if there is any.
func (c *FakeRateLimitPolicies) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.RateLimitPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(ratelimitpoliciesResource, c.ns, name), &v1alpha1.RateLimitPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.RateLimitPolicy), err
}

// List takes label and field selectors, and returns the list of RateLimitPolicies that match those selectors.
func (c *FakeRateLimitPolicies) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.RateLimitPolicyList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(ratelimitpoliciesResource, ratelimitpoliciesKind, c.ns, opts), &v1alpha1.RateLimitPolicyList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.RateLimitPolicyList{ListMeta: obj.(*v1alpha1.RateLimitPolicyList).ListMeta}
	for _, item := range obj.(*v1alpha1.RateLimitPolicyList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested rateLimitPolicies.
func (c *FakeRateLimitPolicies) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(ratelimitpoliciesResource, c.ns, opts))

}

// Create takes the representation of a rateLimitPolicy and creates it.  Returns the server's representation of the rateLimitPolicy, and an error, if there is any.
func (c *FakeRateLimitPolicies) Create(ctx context.Context, rateLimitPolicy *v1alpha1.RateLimitPolicy, opts v1.CreateOptions) (result *v1alpha1.RateLimitPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(ratelimitpoliciesResource, c.ns, rateLimitPolicy), &v1alpha1.RateLimitPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.RateLimitPolicy), err
}

// Update takes the representation of a rateLimitPolicy and updates it. Returns the server's representation of the rateLimitPolicy, and an error, if there is any.
func (c *FakeRateLimitPolicies) Update(ctx context.Context, rateLimitPolicy *v1alpha1.RateLimitPolicy, opts v1.UpdateOptions) (result *v1alpha1.RateLimitPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(ratelimitpoliciesResource, c.ns, rateLimitPolicy), &v1alpha1.RateLimitPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.RateLimitPolicy), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeRateLimitPolicies) UpdateStatus(ctx context.Context, rateLimitPolicy *v1alpha1.RateLimitPolicy, opts v1.UpdateOptions) (*v1alpha1.RateLimitPolicy, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(ratelimitpoliciesResource, "status", c.ns, rateLimitPolicy), &v1alpha1.RateLimitPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.RateLimitPolicy), err
}

// Delete takes name of the rateLimitPolicy and deletes it. Returns an error if one occurs.
func (c *FakeRateLimitPolicies) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(ratelimitpoliciesResource, c.ns, name, opts), &v1alpha1.RateLimitPolicy{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeRateLimitPolicies) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(ratelimitpoliciesResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.RateLimitPolicyList{})
	return err
}

// Patch applies the patch and returns the patched rateLimitPolicy.
func (c *FakeRateLimitPolicies) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.RateLimitPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(ratelimitpoliciesResource, c.ns, name, pt, data, subresources...), &v1alpha1.RateLimitPolicy{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.RateLimitPolicy), err
}
