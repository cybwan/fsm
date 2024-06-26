package e2e

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/flomesh-io/fsm/pkg/constants"
	. "github.com/flomesh-io/fsm/tests/framework"
)

var _ = FSMDescribe("Ignore Namespaces",
	FSMDescribeInfo{
		Tier:   1,
		Bucket: 1,
	},
	func() {
		Context("Ignore Label", func() {
			const ignoreNs = "ignore"

			It("Tests the ignore label on a namespace disables sidecar injection", func() {
				// Install FSM
				installOpts := Td.GetFSMInstallOpts()
				installOpts.EnablePermissiveMode = true
				Expect(Td.InstallFSM(installOpts)).To(Succeed())

				// Create test NS in mesh with ignore label
				Expect(Td.CreateNs(ignoreNs, map[string]string{constants.IgnoreLabel: "true"})).To(Succeed())

				// Add test NS(with ignore label) to mesh with sidecar injection enabled, it should not succeed
				Expect(Td.AddNsToMesh(true, ignoreNs)).NotTo(Succeed())

				By("Ensuring a pod is not injected with a sidecar when added to namespace the ignore, and sidecar injection labels set")

				// Get simple Pod definitions
				svcAccDef, podDef, svcDef, err := Td.SimplePodApp(
					SimplePodAppDef{
						PodName:   "pod1",
						Namespace: ignoreNs,
						Command:   []string{"/bin/bash", "-c", "--"},
						Args:      []string{"while true; do sleep 30; done;"},
						Image:     "flomesh/alpine-debug",
						Ports:     []int{80},
						OS:        Td.ClusterOS,
					})
				Expect(err).NotTo(HaveOccurred())

				_, err = Td.CreateServiceAccount(ignoreNs, &svcAccDef)
				Expect(err).NotTo(HaveOccurred())
				pod, err := Td.CreatePod(ignoreNs, podDef)
				Expect(err).NotTo(HaveOccurred())
				_, err = Td.CreateService(ignoreNs, svcDef)
				Expect(err).NotTo(HaveOccurred())

				Expect(Td.WaitForPodsRunningReady(ignoreNs, 1, nil)).To(Succeed())

				pod, err = Td.Client.CoreV1().Pods(ignoreNs).Get(context.Background(), pod.Name, v1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())

				Expect(hasSidecar(pod.Spec.Containers)).To(BeFalse())
			})
		})
	})

func hasSidecar(containers []corev1.Container) bool {
	for _, container := range containers {
		if container.Name == constants.SidecarContainerName {
			return true
		}
	}
	return false
}
