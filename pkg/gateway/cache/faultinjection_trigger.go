package cache

import (
	gwpav1alpha1 "github.com/flomesh-io/fsm/pkg/apis/policyattachment/v1alpha1"
)

// FaultInjectionPoliciesTrigger is responsible for processing FaultInjectionPolicy objects
type FaultInjectionPoliciesTrigger struct{}

// Insert adds a FaultInjectionPolicy to the cache and returns true if the target service is routable
func (p *FaultInjectionPoliciesTrigger) Insert(obj interface{}, cache *GatewayCache) bool {
	policy, ok := obj.(*gwpav1alpha1.FaultInjectionPolicy)
	if !ok {
		log.Error().Msgf("unexpected object type %T", obj)
		return false
	}

	return cache.isEffectiveTargetRef(policy, policy.Spec.TargetRef)
}

// Delete removes a FaultInjectionPolicy from the cache and returns true if the policy was found
func (p *FaultInjectionPoliciesTrigger) Delete(obj interface{}, cache *GatewayCache) bool {
	policy, ok := obj.(*gwpav1alpha1.FaultInjectionPolicy)
	if !ok {
		log.Error().Msgf("unexpected object type %T", obj)
		return false
	}

	return cache.isEffectiveTargetRef(policy, policy.Spec.TargetRef)
}
