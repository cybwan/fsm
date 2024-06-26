package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/flomesh-io/fsm/tests/framework"
)

var _ = FSMDescribe("Tests traffic via port exclusion",
	FSMDescribeInfo{
		Tier:   2,
		Bucket: 5,
	},
	func() {
		Context("Test global port exclusion", func() {
			testGlobalPortExclusion()
		})

		Context("Test pod level port exclusion", func() {
			testPodLevelPortExclusion()
		})
	})

func testGlobalPortExclusion() {
	const sourceName = "client"
	const destName = "server"
	var ns = []string{sourceName, destName}

	It("Tests HTTP traffic to external server via global port exclusion", func() {
		// Install FSM
		installOpts := Td.GetFSMInstallOpts()
		installOpts.EnablePermissiveMode = false // explicitly set to false to demonstrate port exclusion
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
				Image:     "flomesh/httpbin:ken",
				Ports:     []int{80},
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

		// The destination port will be programmed as an global port exclusion
		destinationPort := int(dstSvc.Spec.Ports[0].Port)
		meshConfig.Spec.Traffic.OutboundPortExclusionList = []int{destinationPort}
		_, err = Td.UpdateFSMConfig(meshConfig)
		Expect(err).NotTo(HaveOccurred())

		srcPod := setupSource(sourceName, false)

		By("Using global port exclusion to access destination")
		// All ready. Expect client to reach server
		clientToServer := HTTPRequestDef{
			SourceNs:        sourceName,
			SourcePod:       srcPod.Name,
			SourceContainer: srcPod.Name,

			Destination: fmt.Sprintf("%s.%s", dstSvc.Name, dstSvc.Namespace),
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

		Expect(cond).To(BeTrue(), "Failed testing HTTP traffic from source pod %s to destination with port %s", srcPod.Name, destinationPort)
	})
}

func testPodLevelPortExclusion() {
	// XXX(3755): use a different namespace due to test pollution
	const sourceName = "client1"
	const destName = "server1"
	var ns = []string{sourceName, destName}

	It("Tests HTTP traffic to external server via pod level port exclusion", func() {
		// Install FSM
		installOpts := Td.GetFSMInstallOpts()
		installOpts.EnablePermissiveMode = false // explicitly set to false to demonstrate port exclusion
		Expect(Td.InstallFSM(installOpts)).To(Succeed())

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

		// Set up the source curl client. It will be a part of the mesh
		svcAccDef, podDef, svcDef, err = Td.SimplePodApp(SimplePodAppDef{
			PodName:   sourceName,
			Namespace: sourceName,
			Image:     fortioImageName,
			Ports:     []int{fortioHTTPPort},
			OS:        Td.ClusterOS,
		})
		Expect(err).NotTo(HaveOccurred())

		_, err = Td.CreateServiceAccount(sourceName, &svcAccDef)
		Expect(err).NotTo(HaveOccurred())

		// The destination port will be programmed as an annotation on the source pod for port exclusion
		destinationPort := fmt.Sprintf("%v", dstSvc.Spec.Ports[0].Port)
		podDef.Annotations = map[string]string{"flomesh.io/outbound-port-exclusion-list": destinationPort}

		srcPod, err := Td.CreatePod(sourceName, podDef)
		Expect(err).NotTo(HaveOccurred())
		_, err = Td.CreateService(sourceName, svcDef)
		Expect(err).NotTo(HaveOccurred())

		// Expect it to be up and running in it's receiver namespace
		Expect(Td.WaitForPodsRunningReady(sourceName, 1, nil)).To(Succeed())

		By("Using pod level port exclusion to access destination")
		// All ready. Expect client to reach server
		clientToServer := HTTPRequestDef{
			SourceNs:        sourceName,
			SourcePod:       srcPod.Name,
			SourceContainer: srcPod.Name,

			Destination: fmt.Sprintf("%s.%s:%s", dstSvc.Name, dstSvc.Namespace, destinationPort),
		}

		srcToDestStr := fmt.Sprintf("%s -> %s",
			fmt.Sprintf("%s/%s", sourceName, srcPod.Name),
			clientToServer.Destination)

		cond := Td.WaitForRepeatedSuccess(func() bool {
			result := Td.FortioHTTPLoadTest(FortioHTTPLoadTestDef{
				HTTPRequestDef: clientToServer,
			})

			if result.Err != nil || result.HasFailedHTTPRequests() {
				Td.T.Logf("> (%s) HTTP Req failed with status codes %v: %v",
					srcToDestStr, result.AllReturnCodes(), result.Err)
				return false
			}
			Td.T.Logf("> (%s) HTTP Req succeeded with status codes: %v", srcToDestStr, result.AllReturnCodes())
			return true
		}, 5, 90*time.Second)

		Expect(cond).To(BeTrue(), "Failed testing HTTP traffic from source pod %s to destination with port %s", srcPod.Name, destinationPort)
	})
}
