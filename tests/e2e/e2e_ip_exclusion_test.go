package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/flomesh-io/fsm/tests/framework"
)

var _ = FSMDescribe("Tests traffic via IP range exclusion",
	FSMDescribeInfo{
		Tier:   2,
		Bucket: 2,
	},
	func() {
		Context("Test IP range exclusion", func() {
			testIPExclusion()
		})
	})

func testIPExclusion() {
	const sourceName = "client"
	const destName = "server"
	var ns = []string{sourceName, destName}

	It("Tests HTTP traffic to external server via IP exclusion", func() {
		// Install FSM
		installOpts := Td.GetFSMInstallOpts()
		installOpts.EnablePermissiveMode = false // explicitly set to false to demonstrate IP exclusion
		Expect(Td.InstallFSM(installOpts)).To(Succeed())
		meshConfig, _ := Td.GetMeshConfig(Td.FsmNamespace)

		// Create Test NS
		for _, n := range ns {
			Expect(Td.CreateNs(n, nil)).To(Succeed())
		}
		// Only add source namespace to the mesh, destination is simulating an external cluster
		Expect(Td.AddNsToMesh(true, sourceName)).To(Succeed())

		// Set up the destination HTTP server. It is not part of the mesh
		svcAccDef, podDef, svcDef, err := Td.SimplePodApp(
			SimplePodAppDef{
				PodName:   destName,
				Namespace: destName,
				Image:     fortioImageName,
				Ports:     []int{fortioHTTPPort},
				OS:        Td.ClusterOS,
			})
		Expect(err).NotTo(HaveOccurred())

		_, err = Td.CreateServiceAccount(destName, &svcAccDef)
		Expect(err).NotTo(HaveOccurred())
		_, err = Td.CreatePod(destName, podDef)
		Expect(err).NotTo(HaveOccurred())
		dstSvc, err := Td.CreateService(destName, svcDef)
		Expect(err).NotTo(HaveOccurred())

		// Expect it to be up and running in it's receiver namespace
		Expect(Td.WaitForPodsRunningReady(destName, 1, nil)).To(Succeed())

		// The destination IP will be programmed as an IP exclusion
		destinationIPRange := fmt.Sprintf("%s/32", dstSvc.Spec.ClusterIP)
		meshConfig.Spec.Traffic.OutboundIPRangeExclusionList = []string{destinationIPRange}
		_, err = Td.UpdateFSMConfig(meshConfig)
		Expect(err).NotTo(HaveOccurred())

		srcPod := setupSource(sourceName, false)

		By("Using IP range exclusion to access destination")
		// All ready. Expect client to reach server
		clientToServer := HTTPRequestDef{
			SourceNs:        sourceName,
			SourcePod:       srcPod.Name,
			SourceContainer: srcPod.Name,

			Destination: fmt.Sprintf("%s.%s:%d", dstSvc.Name, dstSvc.Namespace, fortioHTTPPort),
		}

		srcToDestStr := fmt.Sprintf("%s -> %s",
			fmt.Sprintf("%s/%s", sourceName, srcPod.Name),
			clientToServer.Destination)

		cond := Td.WaitForRepeatedSuccess(func() bool {
			result := Td.HTTPRequest(clientToServer)

			if result.Err != nil || result.StatusCode != 200 {
				Td.T.Logf("> (%s) HTTP Req failed %d %v",
					srcToDestStr, result.StatusCode, result.Err)
				return false
			}
			Td.T.Logf("> (%s) HTTP Req succeeded: %d", srcToDestStr, result.StatusCode)
			return true
		}, 5, 90*time.Second)

		Expect(cond).To(BeTrue(), "Failed testing HTTP traffic from source pod %s to destination %s", srcPod.Name, destinationIPRange)
	})
}
