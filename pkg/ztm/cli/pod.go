package cli

import (
	"context"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// GetZtmAgentPod returns the fsm ztm agent pod spec.
// The pod name is inferred from the 'ZTM_AGENT_POD_NAME' env variable which is set during deployment.
func GetZtmAgentPod(kubeClient kubernetes.Interface) (*corev1.Pod, error) {
	podName := os.Getenv("ZTM_AGENT_POD_NAME")
	if podName == "" {
		return nil, fmt.Errorf("ZTM_AGENT_POD_NAME env variable cannot be empty")
	}

	pod, err := kubeClient.CoreV1().Pods(Cfg.FsmNamespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return pod, nil
}
