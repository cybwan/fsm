package e2e

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/flomesh-io/fsm/tests/framework"
)

var _ = FSMDescribe("Permissive Traffic Policy Mode",
	FSMDescribeInfo{
		Tier:   1,
		Bucket: 5,
	},
	func() {
		Context("Permissive mode HTTP test with a Kubernetes Service for the Source", func() {
			withSourceKubernetesService := true
			testPermissiveMode(withSourceKubernetesService)
		})

		Context("Permissive mode HTTP test without a Kubernetes Service for the Source", func() {
			withSourceKubernetesService := false
			testPermissiveMode(withSourceKubernetesService)
		})
	})

func testPermissiveMode(withSourceKubernetesService bool) {
	const sourceNs = "client"
	const destNs = "server"
	const extSourceNs = "ext-client"
	var meshNs = []string{sourceNs, destNs}

	It("Tests HTTP traffic for client pod -> server pod with permissive mode", func() {
		// Install FSM
		installOpts := Td.GetFSMInstallOpts()
		installOpts.EnablePermissiveMode = true
		Expect(Td.InstallFSM(installOpts)).To(Succeed())
		meshConfig, _ := Td.GetMeshConfig(Td.FsmNamespace)

		// Create test NS in mesh
		for _, n := range meshNs {
			Expect(Td.CreateNs(n, nil)).To(Succeed())
			Expect(Td.AddNsToMesh(true, n)).To(Succeed())
		}

		// Create non mesh test NS
		Expect(Td.CreateNs(extSourceNs, nil)).To(Succeed())

		// Get simple pod definitions for the HTTP server
		svcAccDef, podDef, svcDef, err := Td.SimplePodApp(
			SimplePodAppDef{
				PodName:   "server",
				Namespace: destNs,
				Image:     "flomesh/httpbin:ken",
				Ports:     []int{80},
				OS:        Td.ClusterOS,
			})
		Expect(err).NotTo(HaveOccurred())

		_, err = Td.CreateServiceAccount(destNs, &svcAccDef)
		Expect(err).NotTo(HaveOccurred())
		_, err = Td.CreatePod(destNs, podDef)
		Expect(err).NotTo(HaveOccurred())
		dstSvc, err := Td.CreateService(destNs, svcDef)
		Expect(err).NotTo(HaveOccurred())

		Expect(Td.WaitForPodsRunningReady(destNs, 1, nil)).To(Succeed())

		// Get simple Pod definitions for the client
		svcAccDef, podDef, svcDef, err = Td.SimplePodApp(SimplePodAppDef{
			PodName:   "client",
			Namespace: sourceNs,
			Command:   []string{"/bin/bash", "-c", "--"},
			Args:      []string{"while true; do sleep 30; done;"},
			Image:     "flomesh/alpine-debug",
			Ports:     []int{80},
			OS:        Td.ClusterOS,
		})
		Expect(err).NotTo(HaveOccurred())

		_, err = Td.CreateServiceAccount(sourceNs, &svcAccDef)
		Expect(err).NotTo(HaveOccurred())
		srcPod, err := Td.CreatePod(sourceNs, podDef)
		Expect(err).NotTo(HaveOccurred())

		if withSourceKubernetesService {
			_, err = Td.CreateService(sourceNs, svcDef)
			Expect(err).NotTo(HaveOccurred())
		}

		Expect(Td.WaitForPodsRunningReady(sourceNs, 1, nil)).To(Succeed())

		req := HTTPRequestDef{
			SourceNs:        srcPod.Namespace,
			SourcePod:       srcPod.Name,
			SourceContainer: "client",

			Destination: fmt.Sprintf("%s.%s", dstSvc.Name, dstSvc.Namespace),
		}

		// Get simple Pod definitions for the non mesh client
		svcAccDef, podDef, svcDef, err = Td.SimplePodApp(SimplePodAppDef{
			PodName:   "ext-client",
			Namespace: extSourceNs,
			Command:   []string{"/bin/bash", "-c", "--"},
			Args:      []string{"while true; do sleep 30; done;"},
			Image:     "flomesh/alpine-debug",
			Ports:     []int{80},
			OS:        Td.ClusterOS,
		})
		Expect(err).NotTo(HaveOccurred())

		_, err = Td.CreateServiceAccount(extSourceNs, &svcAccDef)
		Expect(err).NotTo(HaveOccurred())
		extSrcPod, err := Td.CreatePod(extSourceNs, podDef)
		Expect(err).NotTo(HaveOccurred())

		if withSourceKubernetesService {
			_, err = Td.CreateService(extSourceNs, svcDef)
			Expect(err).NotTo(HaveOccurred())
		}

		Expect(Td.WaitForPodsRunningReady(extSourceNs, 1, nil)).To(Succeed())

		extReq := HTTPRequestDef{
			SourceNs:        extSrcPod.Namespace,
			SourcePod:       extSrcPod.Name,
			SourceContainer: "ext-client",

			Destination: fmt.Sprintf("%s.%s", dstSvc.Name, dstSvc.Namespace),
		}

		By("Ensuring traffic is allowed when permissive mode is enabled")

		cond := Td.WaitForRepeatedSuccess(func() bool {
			result := Td.HTTPRequest(req)

			if result.Err != nil || result.StatusCode != 200 {
				Td.T.Logf("> REST req failed (status: %d) %v", result.StatusCode, result.Err)
				return false
			}
			Td.T.Logf("> REST req succeeded: %d", result.StatusCode)
			return true
		}, 5 /*consecutive success threshold*/, 90*time.Second /*timeout*/)
		Expect(cond).To(BeTrue())

		By("Ensuring traffic is not allowed from non mesh clients when permissive mode is enabled")

		cond = Td.WaitForRepeatedSuccess(func() bool {
			result := Td.HTTPRequest(extReq)

			if result.Err == nil || !strings.Contains(result.Err.Error(), "command terminated with exit code") {
				Td.T.Logf("> REST req received unexpected response (status: %d) %v", result.StatusCode, result.Err)
				return false
			}
			Td.T.Logf("> REST req succeeded, got expected error: %v", result.Err)
			return true
		}, 5 /*consecutive success threshold*/, 90*time.Second /*timeout*/)
		Expect(cond).To(BeTrue())

		By("Ensuring traffic is not allowed when permissive mode is disabled")

		meshConfig.Spec.Traffic.EnablePermissiveTrafficPolicyMode = false
		_, err = Td.UpdateFSMConfig(meshConfig)
		Expect(err).NotTo(HaveOccurred())

		cond = Td.WaitForRepeatedSuccess(func() bool {
			result := Td.HTTPRequest(req)

			if result.Err == nil || !strings.Contains(result.Err.Error(), "command terminated with exit code") {
				Td.T.Logf("> REST req received unexpected response (status: %d) %v", result.StatusCode, result.Err)
				return false
			}
			Td.T.Logf("> REST req succeeded, got expected error: %v", result.Err)
			return true
		}, 5 /*consecutive success threshold*/, 90*time.Second /*timeout*/)
		Expect(cond).To(BeTrue())
	})
}
