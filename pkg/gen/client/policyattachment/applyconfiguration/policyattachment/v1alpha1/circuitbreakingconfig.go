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

// CircuitBreakingConfigApplyConfiguration represents an declarative configuration of the CircuitBreakingConfig type for use
// with apply.
type CircuitBreakingConfigApplyConfiguration struct {
	MinRequestAmount        *int32   `json:"minRequestAmount,omitempty"`
	StatTimeWindow          *int32   `json:"statTimeWindow,omitempty"`
	SlowTimeThreshold       *float32 `json:"slowTimeThreshold,omitempty"`
	SlowAmountThreshold     *int32   `json:"slowAmountThreshold,omitempty"`
	SlowRatioThreshold      *float32 `json:"slowRatioThreshold,omitempty"`
	ErrorAmountThreshold    *int32   `json:"errorAmountThreshold,omitempty"`
	ErrorRatioThreshold     *float32 `json:"errorRatioThreshold,omitempty"`
	DegradedTimeWindow      *int32   `json:"degradedTimeWindow,omitempty"`
	DegradedStatusCode      *int32   `json:"degradedStatusCode,omitempty"`
	DegradedResponseContent *string  `json:"degradedResponseContent,omitempty"`
}

// CircuitBreakingConfigApplyConfiguration constructs an declarative configuration of the CircuitBreakingConfig type for use with
// apply.
func CircuitBreakingConfig() *CircuitBreakingConfigApplyConfiguration {
	return &CircuitBreakingConfigApplyConfiguration{}
}

// WithMinRequestAmount sets the MinRequestAmount field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the MinRequestAmount field is set to the value of the last call.
func (b *CircuitBreakingConfigApplyConfiguration) WithMinRequestAmount(value int32) *CircuitBreakingConfigApplyConfiguration {
	b.MinRequestAmount = &value
	return b
}

// WithStatTimeWindow sets the StatTimeWindow field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the StatTimeWindow field is set to the value of the last call.
func (b *CircuitBreakingConfigApplyConfiguration) WithStatTimeWindow(value int32) *CircuitBreakingConfigApplyConfiguration {
	b.StatTimeWindow = &value
	return b
}

// WithSlowTimeThreshold sets the SlowTimeThreshold field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SlowTimeThreshold field is set to the value of the last call.
func (b *CircuitBreakingConfigApplyConfiguration) WithSlowTimeThreshold(value float32) *CircuitBreakingConfigApplyConfiguration {
	b.SlowTimeThreshold = &value
	return b
}

// WithSlowAmountThreshold sets the SlowAmountThreshold field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SlowAmountThreshold field is set to the value of the last call.
func (b *CircuitBreakingConfigApplyConfiguration) WithSlowAmountThreshold(value int32) *CircuitBreakingConfigApplyConfiguration {
	b.SlowAmountThreshold = &value
	return b
}

// WithSlowRatioThreshold sets the SlowRatioThreshold field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SlowRatioThreshold field is set to the value of the last call.
func (b *CircuitBreakingConfigApplyConfiguration) WithSlowRatioThreshold(value float32) *CircuitBreakingConfigApplyConfiguration {
	b.SlowRatioThreshold = &value
	return b
}

// WithErrorAmountThreshold sets the ErrorAmountThreshold field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ErrorAmountThreshold field is set to the value of the last call.
func (b *CircuitBreakingConfigApplyConfiguration) WithErrorAmountThreshold(value int32) *CircuitBreakingConfigApplyConfiguration {
	b.ErrorAmountThreshold = &value
	return b
}

// WithErrorRatioThreshold sets the ErrorRatioThreshold field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ErrorRatioThreshold field is set to the value of the last call.
func (b *CircuitBreakingConfigApplyConfiguration) WithErrorRatioThreshold(value float32) *CircuitBreakingConfigApplyConfiguration {
	b.ErrorRatioThreshold = &value
	return b
}

// WithDegradedTimeWindow sets the DegradedTimeWindow field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DegradedTimeWindow field is set to the value of the last call.
func (b *CircuitBreakingConfigApplyConfiguration) WithDegradedTimeWindow(value int32) *CircuitBreakingConfigApplyConfiguration {
	b.DegradedTimeWindow = &value
	return b
}

// WithDegradedStatusCode sets the DegradedStatusCode field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DegradedStatusCode field is set to the value of the last call.
func (b *CircuitBreakingConfigApplyConfiguration) WithDegradedStatusCode(value int32) *CircuitBreakingConfigApplyConfiguration {
	b.DegradedStatusCode = &value
	return b
}

// WithDegradedResponseContent sets the DegradedResponseContent field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DegradedResponseContent field is set to the value of the last call.
func (b *CircuitBreakingConfigApplyConfiguration) WithDegradedResponseContent(value string) *CircuitBreakingConfigApplyConfiguration {
	b.DegradedResponseContent = &value
	return b
}