package cache

import (
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// HTTPRoutesTrigger is responsible for processing HTTPRoute objects
type HTTPRoutesTrigger struct{}

// Insert adds a HTTPRoute to the cache and returns true if the route is effective
func (p *HTTPRoutesTrigger) Insert(obj interface{}, cache *GatewayCache) bool {
	route, ok := obj.(*gwv1.HTTPRoute)
	if !ok {
		log.Error().Msgf("unexpected object type %T", obj)
		return false
	}

	return cache.isEffectiveRoute(route.Spec.ParentRefs)
}

// Delete removes a HTTPRoute from the cache and returns true if the route was found
func (p *HTTPRoutesTrigger) Delete(obj interface{}, cache *GatewayCache) bool {
	route, ok := obj.(*gwv1.HTTPRoute)
	if !ok {
		log.Error().Msgf("unexpected object type %T", obj)
		return false
	}

	return cache.isEffectiveRoute(route.Spec.ParentRefs)
}
