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

	v1alpha1 "github.com/flomesh-io/fsm/pkg/apis/policy/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeTrafficWarmups implements TrafficWarmupInterface
type FakeTrafficWarmups struct {
	Fake *FakePolicyV1alpha1
	ns   string
}

var trafficwarmupsResource = v1alpha1.SchemeGroupVersion.WithResource("trafficwarmups")

var trafficwarmupsKind = v1alpha1.SchemeGroupVersion.WithKind("TrafficWarmup")

// Get takes name of the trafficWarmup, and returns the corresponding trafficWarmup object, and an error if there is any.
func (c *FakeTrafficWarmups) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.TrafficWarmup, err error) {
	emptyResult := &v1alpha1.TrafficWarmup{}
	obj, err := c.Fake.
		Invokes(testing.NewGetActionWithOptions(trafficwarmupsResource, c.ns, name, options), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.TrafficWarmup), err
}

// List takes label and field selectors, and returns the list of TrafficWarmups that match those selectors.
func (c *FakeTrafficWarmups) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.TrafficWarmupList, err error) {
	emptyResult := &v1alpha1.TrafficWarmupList{}
	obj, err := c.Fake.
		Invokes(testing.NewListActionWithOptions(trafficwarmupsResource, trafficwarmupsKind, c.ns, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.TrafficWarmupList{ListMeta: obj.(*v1alpha1.TrafficWarmupList).ListMeta}
	for _, item := range obj.(*v1alpha1.TrafficWarmupList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested trafficWarmups.
func (c *FakeTrafficWarmups) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchActionWithOptions(trafficwarmupsResource, c.ns, opts))

}

// Create takes the representation of a trafficWarmup and creates it.  Returns the server's representation of the trafficWarmup, and an error, if there is any.
func (c *FakeTrafficWarmups) Create(ctx context.Context, trafficWarmup *v1alpha1.TrafficWarmup, opts v1.CreateOptions) (result *v1alpha1.TrafficWarmup, err error) {
	emptyResult := &v1alpha1.TrafficWarmup{}
	obj, err := c.Fake.
		Invokes(testing.NewCreateActionWithOptions(trafficwarmupsResource, c.ns, trafficWarmup, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.TrafficWarmup), err
}

// Update takes the representation of a trafficWarmup and updates it. Returns the server's representation of the trafficWarmup, and an error, if there is any.
func (c *FakeTrafficWarmups) Update(ctx context.Context, trafficWarmup *v1alpha1.TrafficWarmup, opts v1.UpdateOptions) (result *v1alpha1.TrafficWarmup, err error) {
	emptyResult := &v1alpha1.TrafficWarmup{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateActionWithOptions(trafficwarmupsResource, c.ns, trafficWarmup, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.TrafficWarmup), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeTrafficWarmups) UpdateStatus(ctx context.Context, trafficWarmup *v1alpha1.TrafficWarmup, opts v1.UpdateOptions) (result *v1alpha1.TrafficWarmup, err error) {
	emptyResult := &v1alpha1.TrafficWarmup{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceActionWithOptions(trafficwarmupsResource, "status", c.ns, trafficWarmup, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.TrafficWarmup), err
}

// Delete takes name of the trafficWarmup and deletes it. Returns an error if one occurs.
func (c *FakeTrafficWarmups) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(trafficwarmupsResource, c.ns, name, opts), &v1alpha1.TrafficWarmup{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeTrafficWarmups) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionActionWithOptions(trafficwarmupsResource, c.ns, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.TrafficWarmupList{})
	return err
}

// Patch applies the patch and returns the patched trafficWarmup.
func (c *FakeTrafficWarmups) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.TrafficWarmup, err error) {
	emptyResult := &v1alpha1.TrafficWarmup{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceActionWithOptions(trafficwarmupsResource, c.ns, name, pt, data, opts, subresources...), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.TrafficWarmup), err
}
