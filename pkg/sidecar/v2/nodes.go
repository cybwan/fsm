package v2

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ConditionStatus returns the status of the condition for a given node.
func ConditionStatus(n *corev1.Node, ct corev1.NodeConditionType) corev1.ConditionStatus {
	if n == nil {
		return corev1.ConditionUnknown
	}

	for _, c := range n.Status.Conditions {
		if c.Type == ct {
			return c.Status
		}
	}

	return corev1.ConditionUnknown
}

// isNetworkUnavailable returns true if the given node NodeNetworkUnavailable condition status is true.
func isNetworkUnavailable(n *corev1.Node) bool {
	return ConditionStatus(n, corev1.NodeNetworkUnavailable) == corev1.ConditionTrue
}

func availableNetworkNodes(kubeClient kubernetes.Interface) map[string]*corev1.Node {
	nodeCaches := make(map[string]*corev1.Node)
	if nodes, err := kubeClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{}); err == nil {
		for _, node := range nodes.Items {
			if isNetworkUnavailable(&node) {
				continue
			}
			node := node
			nodeCaches[node.Name] = &node
		}
	}
	return nodeCaches
}
