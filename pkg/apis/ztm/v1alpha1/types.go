package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type ZtmMember interface {
	runtime.Object
	metav1.Object
	GetReplicas() *int32
	GetResources() *corev1.ResourceRequirements
}
