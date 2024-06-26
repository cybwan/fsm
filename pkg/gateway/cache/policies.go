package cache

import (
	gwpkg "github.com/flomesh-io/fsm/pkg/gateway/types"
	"github.com/flomesh-io/fsm/pkg/k8s/informers"

	"github.com/flomesh-io/fsm/pkg/gateway/policy/utils/retry"

	"github.com/flomesh-io/fsm/pkg/gateway/policy/utils/sessionsticky"

	"github.com/flomesh-io/fsm/pkg/gateway/policy/utils/loadbalancer"

	"github.com/flomesh-io/fsm/pkg/gateway/policy/utils/circuitbreaking"

	"github.com/flomesh-io/fsm/pkg/gateway/policy/utils/healthcheck"
	"github.com/flomesh-io/fsm/pkg/gateway/policy/utils/upstreamtls"

	"github.com/flomesh-io/fsm/pkg/constants"

	"github.com/flomesh-io/fsm/pkg/gateway/policy"

	"sigs.k8s.io/controller-runtime/pkg/client"

	gwpav1alpha1 "github.com/flomesh-io/fsm/pkg/apis/policyattachment/v1alpha1"
	gwutils "github.com/flomesh-io/fsm/pkg/gateway/utils"
)

func (c *GatewayCache) policyAttachments() globalPolicyAttachments {
	return globalPolicyAttachments{
		rateLimits:      c.rateLimits(),
		accessControls:  c.accessControls(),
		faultInjections: c.faultInjections(),
	}
}

func (c *GatewayProcessor) getPortPolicyEnrichers() []policy.PortPolicyEnricher {
	return []policy.PortPolicyEnricher{
		&policy.RateLimitPortEnricher{Data: c.policies.rateLimits[gwpkg.PolicyMatchTypePort], ReferenceGrants: c.referenceGrants},
		&policy.AccessControlPortEnricher{Data: c.policies.accessControls[gwpkg.PolicyMatchTypePort], ReferenceGrants: c.referenceGrants},
	}
}

func getHostnamePolicyEnrichers(routePolicies routePolicies) []policy.HostnamePolicyEnricher {
	return []policy.HostnamePolicyEnricher{
		&policy.RateLimitHostnameEnricher{Data: routePolicies.hostnamesRateLimits},
		&policy.AccessControlHostnameEnricher{Data: routePolicies.hostnamesAccessControls},
		&policy.FaultInjectionHostnameEnricher{Data: routePolicies.hostnamesFaultInjections},
	}
}

func getHTTPRoutePolicyEnrichers(routePolicies routePolicies) []policy.HTTPRoutePolicyEnricher {
	return []policy.HTTPRoutePolicyEnricher{
		&policy.RateLimitHTTPRouteEnricher{Data: routePolicies.httpRouteRateLimits},
		&policy.AccessControlHTTPRouteEnricher{Data: routePolicies.httpRouteAccessControls},
		&policy.FaultInjectionHTTPRouteEnricher{Data: routePolicies.httpRouteFaultInjections},
	}
}

func getGRPCRoutePolicyEnrichers(routePolicies routePolicies) []policy.GRPCRoutePolicyEnricher {
	return []policy.GRPCRoutePolicyEnricher{
		&policy.RateLimitGRPCRouteEnricher{Data: routePolicies.grpcRouteRateLimits},
		&policy.AccessControlGRPCRouteEnricher{Data: routePolicies.grpcRouteAccessControls},
		&policy.FaultInjectionGRPCRouteEnricher{Data: routePolicies.grpcRouteFaultInjections},
	}
}

func (c *GatewayProcessor) getServicePolicyEnrichers() []policy.ServicePolicyEnricher {
	return []policy.ServicePolicyEnricher{
		&policy.SessionStickyPolicyEnricher{Data: c.sessionStickies()},
		&policy.LoadBalancerPolicyEnricher{Data: c.loadBalancers()},
		&policy.CircuitBreakingPolicyEnricher{Data: c.circuitBreakings()},
		&policy.HealthCheckPolicyEnricher{Data: c.healthChecks()},
		&policy.UpstreamTLSPolicyEnricher{Data: c.upstreamTLS()},
		&policy.RetryPolicyEnricher{Data: c.retryConfigs()},
	}
}

func (c *GatewayCache) rateLimits() map[gwpkg.PolicyMatchType][]gwpav1alpha1.RateLimitPolicy {
	rateLimits := make(map[gwpkg.PolicyMatchType][]gwpav1alpha1.RateLimitPolicy)
	for _, matchType := range []gwpkg.PolicyMatchType{
		gwpkg.PolicyMatchTypePort,
		gwpkg.PolicyMatchTypeHostnames,
		gwpkg.PolicyMatchTypeHTTPRoute,
		gwpkg.PolicyMatchTypeGRPCRoute,
	} {
		rateLimits[matchType] = make([]gwpav1alpha1.RateLimitPolicy, 0)
	}

	for _, p := range c.getResourcesFromCache(informers.RateLimitPoliciesResourceType, true) {
		p := p.(*gwpav1alpha1.RateLimitPolicy)

		if gwutils.IsAcceptedPolicyAttachment(p.Status.Conditions) {
			spec := p.Spec
			targetRef := spec.TargetRef

			switch {
			case gwutils.IsTargetRefToGVK(targetRef, constants.GatewayGVK) && len(spec.Ports) > 0:
				rateLimits[gwpkg.PolicyMatchTypePort] = append(rateLimits[gwpkg.PolicyMatchTypePort], *p)
			case (gwutils.IsTargetRefToGVK(targetRef, constants.HTTPRouteGVK) || gwutils.IsTargetRefToGVK(targetRef, constants.GRPCRouteGVK)) && len(spec.Hostnames) > 0:
				rateLimits[gwpkg.PolicyMatchTypeHostnames] = append(rateLimits[gwpkg.PolicyMatchTypeHostnames], *p)
			case gwutils.IsTargetRefToGVK(targetRef, constants.HTTPRouteGVK) && len(spec.HTTPRateLimits) > 0:
				rateLimits[gwpkg.PolicyMatchTypeHTTPRoute] = append(rateLimits[gwpkg.PolicyMatchTypeHTTPRoute], *p)
			case gwutils.IsTargetRefToGVK(targetRef, constants.GRPCRouteGVK) && len(spec.GRPCRateLimits) > 0:
				rateLimits[gwpkg.PolicyMatchTypeGRPCRoute] = append(rateLimits[gwpkg.PolicyMatchTypeGRPCRoute], *p)
			}
		}
	}

	return rateLimits
}

func (c *GatewayCache) accessControls() map[gwpkg.PolicyMatchType][]gwpav1alpha1.AccessControlPolicy {
	accessControls := make(map[gwpkg.PolicyMatchType][]gwpav1alpha1.AccessControlPolicy)
	for _, matchType := range []gwpkg.PolicyMatchType{
		gwpkg.PolicyMatchTypePort,
		gwpkg.PolicyMatchTypeHostnames,
		gwpkg.PolicyMatchTypeHTTPRoute,
		gwpkg.PolicyMatchTypeGRPCRoute,
	} {
		accessControls[matchType] = make([]gwpav1alpha1.AccessControlPolicy, 0)
	}

	for _, p := range c.getResourcesFromCache(informers.AccessControlPoliciesResourceType, true) {
		p := p.(*gwpav1alpha1.AccessControlPolicy)

		if gwutils.IsAcceptedPolicyAttachment(p.Status.Conditions) {
			spec := p.Spec
			targetRef := spec.TargetRef

			switch {
			case gwutils.IsTargetRefToGVK(targetRef, constants.GatewayGVK) && len(spec.Ports) > 0:
				accessControls[gwpkg.PolicyMatchTypePort] = append(accessControls[gwpkg.PolicyMatchTypePort], *p)
			case (gwutils.IsTargetRefToGVK(targetRef, constants.HTTPRouteGVK) || gwutils.IsTargetRefToGVK(targetRef, constants.GRPCRouteGVK)) && len(spec.Hostnames) > 0:
				accessControls[gwpkg.PolicyMatchTypeHostnames] = append(accessControls[gwpkg.PolicyMatchTypeHostnames], *p)
			case gwutils.IsTargetRefToGVK(targetRef, constants.HTTPRouteGVK) && len(spec.HTTPAccessControls) > 0:
				accessControls[gwpkg.PolicyMatchTypeHTTPRoute] = append(accessControls[gwpkg.PolicyMatchTypeHTTPRoute], *p)
			case gwutils.IsTargetRefToGVK(targetRef, constants.GRPCRouteGVK) && len(spec.GRPCAccessControls) > 0:
				accessControls[gwpkg.PolicyMatchTypeGRPCRoute] = append(accessControls[gwpkg.PolicyMatchTypeGRPCRoute], *p)
			}
		}
	}

	return accessControls
}

func (c *GatewayCache) faultInjections() map[gwpkg.PolicyMatchType][]gwpav1alpha1.FaultInjectionPolicy {
	faultInjections := make(map[gwpkg.PolicyMatchType][]gwpav1alpha1.FaultInjectionPolicy)
	for _, matchType := range []gwpkg.PolicyMatchType{
		gwpkg.PolicyMatchTypeHostnames,
		gwpkg.PolicyMatchTypeHTTPRoute,
		gwpkg.PolicyMatchTypeGRPCRoute,
	} {
		faultInjections[matchType] = make([]gwpav1alpha1.FaultInjectionPolicy, 0)
	}

	for _, p := range c.getResourcesFromCache(informers.FaultInjectionPoliciesResourceType, true) {
		p := p.(*gwpav1alpha1.FaultInjectionPolicy)

		if gwutils.IsAcceptedPolicyAttachment(p.Status.Conditions) {
			spec := p.Spec
			targetRef := spec.TargetRef

			switch {
			case (gwutils.IsTargetRefToGVK(targetRef, constants.HTTPRouteGVK) || gwutils.IsTargetRefToGVK(targetRef, constants.GRPCRouteGVK)) && len(spec.Hostnames) > 0:
				faultInjections[gwpkg.PolicyMatchTypeHostnames] = append(faultInjections[gwpkg.PolicyMatchTypeHostnames], *p)
			case gwutils.IsTargetRefToGVK(targetRef, constants.HTTPRouteGVK) && len(spec.HTTPFaultInjections) > 0:
				faultInjections[gwpkg.PolicyMatchTypeHTTPRoute] = append(faultInjections[gwpkg.PolicyMatchTypeHTTPRoute], *p)
			case gwutils.IsTargetRefToGVK(targetRef, constants.GRPCRouteGVK) && len(spec.GRPCFaultInjections) > 0:
				faultInjections[gwpkg.PolicyMatchTypeGRPCRoute] = append(faultInjections[gwpkg.PolicyMatchTypeGRPCRoute], *p)
			}
		}
	}

	return faultInjections
}

func filterPoliciesByRoute(referenceGrants []client.Object, policies globalPolicyAttachments, route client.Object) routePolicies {
	result := routePolicies{
		hostnamesRateLimits:      make([]gwpav1alpha1.RateLimitPolicy, 0),
		httpRouteRateLimits:      make([]gwpav1alpha1.RateLimitPolicy, 0),
		grpcRouteRateLimits:      make([]gwpav1alpha1.RateLimitPolicy, 0),
		hostnamesAccessControls:  make([]gwpav1alpha1.AccessControlPolicy, 0),
		httpRouteAccessControls:  make([]gwpav1alpha1.AccessControlPolicy, 0),
		grpcRouteAccessControls:  make([]gwpav1alpha1.AccessControlPolicy, 0),
		hostnamesFaultInjections: make([]gwpav1alpha1.FaultInjectionPolicy, 0),
		httpRouteFaultInjections: make([]gwpav1alpha1.FaultInjectionPolicy, 0),
		grpcRouteFaultInjections: make([]gwpav1alpha1.FaultInjectionPolicy, 0),
	}

	if len(policies.rateLimits[gwpkg.PolicyMatchTypeHostnames]) > 0 {
		for _, rateLimit := range policies.rateLimits[gwpkg.PolicyMatchTypeHostnames] {
			rateLimit := rateLimit
			if gwutils.IsRefToTarget(referenceGrants, &rateLimit, rateLimit.Spec.TargetRef, route) {
				result.hostnamesRateLimits = append(result.hostnamesRateLimits, rateLimit)
			}
		}
	}

	if len(policies.rateLimits[gwpkg.PolicyMatchTypeHTTPRoute]) > 0 {
		for _, rateLimit := range policies.rateLimits[gwpkg.PolicyMatchTypeHTTPRoute] {
			rateLimit := rateLimit
			if gwutils.IsRefToTarget(referenceGrants, &rateLimit, rateLimit.Spec.TargetRef, route) {
				result.httpRouteRateLimits = append(result.httpRouteRateLimits, rateLimit)
			}
		}
	}

	if len(policies.rateLimits[gwpkg.PolicyMatchTypeGRPCRoute]) > 0 {
		for _, rateLimit := range policies.rateLimits[gwpkg.PolicyMatchTypeGRPCRoute] {
			rateLimit := rateLimit
			if gwutils.IsRefToTarget(referenceGrants, &rateLimit, rateLimit.Spec.TargetRef, route) {
				result.grpcRouteRateLimits = append(result.grpcRouteRateLimits, rateLimit)
			}
		}
	}

	if len(policies.accessControls[gwpkg.PolicyMatchTypeHostnames]) > 0 {
		for _, ac := range policies.accessControls[gwpkg.PolicyMatchTypeHostnames] {
			ac := ac
			if gwutils.IsRefToTarget(referenceGrants, &ac, ac.Spec.TargetRef, route) {
				result.hostnamesAccessControls = append(result.hostnamesAccessControls, ac)
			}
		}
	}

	if len(policies.accessControls[gwpkg.PolicyMatchTypeHTTPRoute]) > 0 {
		for _, ac := range policies.accessControls[gwpkg.PolicyMatchTypeHTTPRoute] {
			ac := ac
			if gwutils.IsRefToTarget(referenceGrants, &ac, ac.Spec.TargetRef, route) {
				result.httpRouteAccessControls = append(result.httpRouteAccessControls, ac)
			}
		}
	}

	if len(policies.accessControls[gwpkg.PolicyMatchTypeGRPCRoute]) > 0 {
		for _, ac := range policies.accessControls[gwpkg.PolicyMatchTypeGRPCRoute] {
			ac := ac
			if gwutils.IsRefToTarget(referenceGrants, &ac, ac.Spec.TargetRef, route) {
				result.grpcRouteAccessControls = append(result.grpcRouteAccessControls, ac)
			}
		}
	}

	if len(policies.faultInjections[gwpkg.PolicyMatchTypeHostnames]) > 0 {
		for _, fj := range policies.faultInjections[gwpkg.PolicyMatchTypeHostnames] {
			fj := fj
			if gwutils.IsRefToTarget(referenceGrants, &fj, fj.Spec.TargetRef, route) {
				result.hostnamesFaultInjections = append(result.hostnamesFaultInjections, fj)
			}
		}
	}

	if len(policies.faultInjections[gwpkg.PolicyMatchTypeHTTPRoute]) > 0 {
		for _, fj := range policies.faultInjections[gwpkg.PolicyMatchTypeHTTPRoute] {
			fj := fj
			if gwutils.IsRefToTarget(referenceGrants, &fj, fj.Spec.TargetRef, route) {
				result.httpRouteFaultInjections = append(result.httpRouteFaultInjections, fj)
			}
		}
	}

	if len(policies.faultInjections[gwpkg.PolicyMatchTypeGRPCRoute]) > 0 {
		for _, fj := range policies.faultInjections[gwpkg.PolicyMatchTypeGRPCRoute] {
			fj := fj
			if gwutils.IsRefToTarget(referenceGrants, &fj, fj.Spec.TargetRef, route) {
				result.grpcRouteFaultInjections = append(result.grpcRouteFaultInjections, fj)
			}
		}
	}

	return result
}

func (c *GatewayProcessor) sessionStickies() map[string]*gwpav1alpha1.SessionStickyConfig {
	sessionStickies := make(map[string]*gwpav1alpha1.SessionStickyConfig)

	for _, sessionSticky := range c.getResourcesFromCache(informers.SessionStickyPoliciesResourceType, true) {
		sessionSticky := sessionSticky.(*gwpav1alpha1.SessionStickyPolicy)

		if gwutils.IsAcceptedPolicyAttachment(sessionSticky.Status.Conditions) {
			for _, p := range sessionSticky.Spec.Ports {
				if svcPortName := c.targetRefToServicePortName(sessionSticky, sessionSticky.Spec.TargetRef, int32(p.Port)); svcPortName != nil {
					cfg := sessionsticky.ComputeSessionStickyConfig(p.Config, sessionSticky.Spec.DefaultConfig)

					if cfg == nil {
						continue
					}

					if _, ok := sessionStickies[svcPortName.String()]; ok {
						log.Warn().Msgf("Policy is already defined for service port %s, SessionStickyPolicy %s/%s:%d will be dropped", svcPortName.String(), sessionSticky.Namespace, sessionSticky.Name, p.Port)
						continue
					}

					sessionStickies[svcPortName.String()] = cfg
				}
			}
		}
	}

	return sessionStickies
}

func (c *GatewayProcessor) loadBalancers() map[string]*gwpav1alpha1.LoadBalancerType {
	loadBalancers := make(map[string]*gwpav1alpha1.LoadBalancerType)

	for _, lb := range c.getResourcesFromCache(informers.LoadBalancerPoliciesResourceType, true) {
		lb := lb.(*gwpav1alpha1.LoadBalancerPolicy)

		if gwutils.IsAcceptedPolicyAttachment(lb.Status.Conditions) {
			for _, p := range lb.Spec.Ports {
				if svcPortName := c.targetRefToServicePortName(lb, lb.Spec.TargetRef, int32(p.Port)); svcPortName != nil {
					t := loadbalancer.ComputeLoadBalancerType(p.Type, lb.Spec.DefaultType)

					if t == nil {
						continue
					}

					if _, ok := loadBalancers[svcPortName.String()]; ok {
						log.Warn().Msgf("Policy is already defined for service port %s, LoadBalancerPolicy %s/%s:%d will be dropped", svcPortName.String(), lb.Namespace, lb.Name, p.Port)
						continue
					}

					loadBalancers[svcPortName.String()] = t
				}
			}
		}
	}

	return loadBalancers
}

func (c *GatewayProcessor) circuitBreakings() map[string]*gwpav1alpha1.CircuitBreakingConfig {
	configs := make(map[string]*gwpav1alpha1.CircuitBreakingConfig)

	for _, circuitBreaking := range c.getResourcesFromCache(informers.CircuitBreakingPoliciesResourceType, true) {
		circuitBreaking := circuitBreaking.(*gwpav1alpha1.CircuitBreakingPolicy)

		if gwutils.IsAcceptedPolicyAttachment(circuitBreaking.Status.Conditions) {
			for _, p := range circuitBreaking.Spec.Ports {
				if svcPortName := c.targetRefToServicePortName(circuitBreaking, circuitBreaking.Spec.TargetRef, int32(p.Port)); svcPortName != nil {
					cfg := circuitbreaking.ComputeCircuitBreakingConfig(p.Config, circuitBreaking.Spec.DefaultConfig)

					if cfg == nil {
						continue
					}

					if _, ok := configs[svcPortName.String()]; ok {
						log.Warn().Msgf("Policy is already defined for service port %s, CircuitBreakingPolicy %s/%s:%d will be dropped", svcPortName.String(), circuitBreaking.Namespace, circuitBreaking.Name, p.Port)
						continue
					}

					configs[svcPortName.String()] = cfg
				}
			}
		}
	}

	return configs
}

func (c *GatewayProcessor) healthChecks() map[string]*gwpav1alpha1.HealthCheckConfig {
	configs := make(map[string]*gwpav1alpha1.HealthCheckConfig)

	for _, healthCheck := range c.getResourcesFromCache(informers.HealthCheckPoliciesResourceType, true) {
		healthCheck := healthCheck.(*gwpav1alpha1.HealthCheckPolicy)

		if gwutils.IsAcceptedPolicyAttachment(healthCheck.Status.Conditions) {
			for _, p := range healthCheck.Spec.Ports {
				if svcPortName := c.targetRefToServicePortName(healthCheck, healthCheck.Spec.TargetRef, int32(p.Port)); svcPortName != nil {
					cfg := healthcheck.ComputeHealthCheckConfig(p.Config, healthCheck.Spec.DefaultConfig)

					if cfg == nil {
						continue
					}

					if _, ok := configs[svcPortName.String()]; ok {
						log.Warn().Msgf("Policy is already defined for service port %s, HealthCheckPolicy %s/%s:%d will be dropped", svcPortName.String(), healthCheck.Namespace, healthCheck.Name, p.Port)
						continue
					}

					configs[svcPortName.String()] = cfg
				}
			}
		}
	}

	return configs
}

func (c *GatewayProcessor) upstreamTLS() map[string]*policy.UpstreamTLSConfig {
	configs := make(map[string]*policy.UpstreamTLSConfig)

	for _, upstreamTLS := range c.getResourcesFromCache(informers.UpstreamTLSPoliciesResourceType, true) {
		upstreamTLS := upstreamTLS.(*gwpav1alpha1.UpstreamTLSPolicy)

		if gwutils.IsAcceptedPolicyAttachment(upstreamTLS.Status.Conditions) {
			for _, p := range upstreamTLS.Spec.Ports {
				if svcPortName := c.targetRefToServicePortName(upstreamTLS, upstreamTLS.Spec.TargetRef, int32(p.Port)); svcPortName != nil {
					cfg := upstreamtls.ComputeUpstreamTLSConfig(p.Config, upstreamTLS.Spec.DefaultConfig)

					if cfg == nil {
						continue
					}

					secret, err := c.secretRefToSecret(upstreamTLS, cfg.CertificateRef)
					if err != nil {
						log.Error().Msgf("Failed to resolve Secret: %s", err)
						continue
					}

					if _, ok := configs[svcPortName.String()]; ok {
						log.Warn().Msgf("Policy is already defined for service port %s, UpstreamTLSPolicy %s/%s:%d will be dropped", svcPortName.String(), upstreamTLS.Namespace, upstreamTLS.Name, p.Port)
						continue
					}

					configs[svcPortName.String()] = &policy.UpstreamTLSConfig{
						MTLS:   cfg.MTLS,
						Secret: secret,
					}
				}
			}
		}
	}

	return configs
}

func (c *GatewayProcessor) retryConfigs() map[string]*gwpav1alpha1.RetryConfig {
	configs := make(map[string]*gwpav1alpha1.RetryConfig)

	for _, retryPolicy := range c.getResourcesFromCache(informers.RetryPoliciesResourceType, true) {
		retryPolicy := retryPolicy.(*gwpav1alpha1.RetryPolicy)

		if gwutils.IsAcceptedPolicyAttachment(retryPolicy.Status.Conditions) {
			for _, p := range retryPolicy.Spec.Ports {
				if svcPortName := c.targetRefToServicePortName(retryPolicy, retryPolicy.Spec.TargetRef, int32(p.Port)); svcPortName != nil {
					cfg := retry.ComputeRetryConfig(p.Config, retryPolicy.Spec.DefaultConfig)

					if cfg == nil {
						continue
					}

					if _, ok := configs[svcPortName.String()]; ok {
						log.Warn().Msgf("Policy is already defined for service port %s, RetryPolicy %s/%s:%d will be dropped", svcPortName.String(), retryPolicy.Namespace, retryPolicy.Name, p.Port)
						continue
					}

					configs[svcPortName.String()] = cfg
				}
			}
		}
	}

	return configs
}
