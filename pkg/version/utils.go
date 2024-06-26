package version

import (
	"strings"

	"github.com/blang/semver"
	"k8s.io/client-go/kubernetes"
)

var (
	// ServerVersion is the version of the Kubernetes cluster the operator is running in.
	ServerVersion = semver.Version{Major: 0, Minor: 0, Patch: 0}
)

var (
	// MinK8sVersion is the minimum version of Kubernetes that the operator supports.
	MinK8sVersion = semver.Version{Major: 1, Minor: 19, Patch: 0}

	// MinEndpointSliceVersion is the minimum version of Kubernetes that supports EndpointSlice.
	// stable since Kubernetes v1.21
	// https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/
	MinEndpointSliceVersion = semver.Version{Major: 1, Minor: 21, Patch: 0}

	// MinDualStackSliceVersion is the minimum version of Kubernetes that supports IPv4/IPv6 dual-stack.
	// IPv4/IPv6 dual-stack networking is enabled by default for your Kubernetes cluster starting in 1.21
	// https://kubernetes.io/docs/concepts/services-networking/dual-stack/
	MinDualStackSliceVersion = semver.Version{Major: 1, Minor: 21, Patch: 0}

	// MinK8sVersionForGatewayAPI is the minimum version of Kubernetes that supports Gateway API.
	MinK8sVersionForGatewayAPI = MinK8sVersion

	// MinK8sVersionForCELValidation is the minimum version of Kubernetes that supports CustomResourceValidationExpressions.
	// This feature was introduced since Kubernetes 1.23 but turned off by default.
	// It has been turned on by default since Kubernetes 1.25 and finally graduated to GA in Kubernetes 1.29
	// https://github.com/kubernetes/enhancements/issues/2876
	MinK8sVersionForCELValidation = semver.Version{Major: 1, Minor: 25, Patch: 0}
)

func getServerVersion(kubeClient kubernetes.Interface) (semver.Version, error) {
	serverVersion, err := kubeClient.Discovery().ServerVersion()
	if err != nil {
		log.Error().Msgf("unable to get Server Version: %s", err)
		return semver.Version{Major: 0, Minor: 0, Patch: 0}, err
	}

	gitVersion := serverVersion.GitVersion
	if len(gitVersion) > 1 && strings.HasPrefix(gitVersion, "v") {
		gitVersion = gitVersion[1:]
	}

	return semver.MustParse(gitVersion), nil
}

func detectServerVersion(kubeClient kubernetes.Interface) {
	if ServerVersion.EQ(semver.Version{Major: 0, Minor: 0, Patch: 0}) {
		ver, err := getServerVersion(kubeClient)
		if err != nil {
			log.Error().Msgf("unable to get server version: %s", err)
			panic(err)
		}

		ServerVersion = ver
	}
}

// IsSupportedK8sVersion returns true if the Kubernetes cluster version is supported by the operator.
func IsSupportedK8sVersion(kubeClient kubernetes.Interface) bool {
	detectServerVersion(kubeClient)
	return ServerVersion.GTE(MinK8sVersion)
}

// IsEndpointSliceEnabled returns true if EndpointSlice is enabled in the Kubernetes cluster.
func IsEndpointSliceEnabled(kubeClient kubernetes.Interface) bool {
	detectServerVersion(kubeClient)
	return ServerVersion.GTE(MinEndpointSliceVersion)
}

// IsDualStackEnabled returns true if IPv4/IPv6 dual-stack is enabled in the Kubernetes cluster.
func IsDualStackEnabled(kubeClient kubernetes.Interface) bool {
	detectServerVersion(kubeClient)
	return ServerVersion.GTE(MinDualStackSliceVersion)
}

// IsSupportedK8sVersionForGatewayAPI returns true if the Kubernetes cluster version is supported by the operator.
func IsSupportedK8sVersionForGatewayAPI(kubeClient kubernetes.Interface) bool {
	return IsSupportedK8sVersion(kubeClient)
}

// IsCELValidationEnabled returns true if CustomResourceValidationExpressions are enabled in the Kubernetes cluster.
func IsCELValidationEnabled(kubeClient kubernetes.Interface) bool {
	detectServerVersion(kubeClient)
	return ServerVersion.GTE(MinK8sVersionForCELValidation)
}
