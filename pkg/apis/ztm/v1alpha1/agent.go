package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:metadata:labels=app.kubernetes.io/name=flomesh.io
// +kubebuilder:resource:shortName=agent,scope=Cluster
// +kubebuilder:storageversion
// +kubebuilder:subresource:status

// Agent is the type used to represent a ztm agent resource.
type Agent struct {
	// Object's type metadata
	metav1.TypeMeta `json:",inline"`

	// Object's metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the ztm agent specification
	Spec AgentSpec `json:"spec"`

	// Status is the status of the ztm agent configuration.
	// +optional
	Status AgentStatus `json:"status,omitempty"`
}

func (c *Agent) GetReplicas() *int32 {
	return c.Spec.Replicas
}

func (c *Agent) GetResources() *corev1.ResourceRequirements {
	return &c.Spec.Resources
}

// AgentSpec is the type used to represent the ztm agent specification.
type AgentSpec struct {
	// Compute Resources required by connector container.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

	Permit PermitSpec `json:"permit"`

	JoinMeshes []JoinMeshSpec `json:"joinMeshes,omitempty"`
}

type PermitAgentSpec struct {
	PrivateKey  string `json:"privateKey"`
	Certificate string `json:"certificate"`
}

type PermitSpec struct {
	// +kubebuilder:validation:MinItems=1
	Bootstraps []string        `json:"bootstraps"`
	Ca         string          `json:"ca"`
	Agent      PermitAgentSpec `json:"agent"`
}

type JoinMeshSpec struct {
	MeshName string `json:"meshName"`
}

// AgentStatus is the type used to represent the status of a ztm agent resource.
type AgentStatus struct {
	// CurrentStatus defines the current status of a ztm agent resource.
	// +optional
	CurrentStatus string `json:"currentStatus,omitempty"`

	// Reason defines the reason for the current status of ztm agent resource.
	// +optional
	Reason string `json:"reason,omitempty"`
}

// AgentList contains a list of ztm agents.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type AgentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Agent `json:"items"`
}
