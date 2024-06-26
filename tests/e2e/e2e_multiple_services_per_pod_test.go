package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/flomesh-io/fsm/tests/framework"
)

var _ = FSMDescribe("Test access via multiple services matching the same pod",
	FSMDescribeInfo{
		Tier:   2,
		Bucket: 3,
	},
	func() {
		Context("Multiple services matching same pod", func() {
			testMultipleServicePerPod()
		})
	})

// testMultipleServicePerPod tests that multiple services having selectors matching the
// same pod can be individually used to access that pod.
// In addition to the client and server pods, it creates 2 services 'server' and 'server-second'
// that have the same label selector, matching the labels on the destination pod that hosts the HTTP server.
// It tests HTTP traffic as follows:
// 1. 'client' pod -> service 'server' -> 'server' pod
// 2. 'client' pod -> service 'server-second' -> 'server' pod
func testMultipleServicePerPod() {
	const sourceName = "client"
	const destName = "server"
	var ns = []string{sourceName, destName}

	It("Tests traffic to multiple services matching the same pod", func() {
		// Install FSM
		Expect(Td.InstallFSM(Td.GetFSMInstallOpts())).To(Succeed())

		// Create Test NS
		for _, n := range ns {
			Expect(Td.CreateNs(n, nil)).To(Succeed())
			Expect(Td.AddNsToMesh(true, n)).To(Succeed())
		}

		// Create an HTTP server that clients will send requests to
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
		firstSvc, err := Td.CreateService(destName, svcDef)
		Expect(err).NotTo(HaveOccurred())

		// Create a 2nd service, which has the same label selectors as the first service created above.
		// This will be used to verify that multiple services having label selectors matching the
		// same pod can work as expected.
		secondSvcDef := svcDef
		secondSvcDef.Name = fmt.Sprintf("%s-second", svcDef.Name)
		secondSvc, err := Td.CreateService(destName, secondSvcDef)
		Expect(err).NotTo(HaveOccurred())

		// Expect it to be up and running in it's receiver namespace
		Expect(Td.WaitForPodsRunningReady(podDef.Name, 1, nil)).To(Succeed())

		srcPod := setupSource(sourceName, false /* no service for client */)

		By("Creating SMI policies")
		// Deploy allow rule client->server
		httpRG, trafficTarget := Td.CreateSimpleAllowPolicy(
			SimpleAllowPolicy{
				RouteGroupName:    "routes",
				TrafficTargetName: "test-target",

				SourceNamespace:      srcPod.Namespace,
				SourceSVCAccountName: srcPod.Spec.ServiceAccountName,

				DestinationNamespace:      destName,
				DestinationSvcAccountName: svcAccDef.Name,
			})

		// Configs have to be put into a monitored NS
		_, err = Td.CreateHTTPRouteGroup(destName, httpRG)
		Expect(err).NotTo(HaveOccurred())
		_, err = Td.CreateTrafficTarget(destName, trafficTarget)
		Expect(err).NotTo(HaveOccurred())

		// Expect client to reach HTTP server using the first service as FQDN
		clientToFirstService := HTTPRequestDef{
			SourceNs:        sourceName,
			SourcePod:       srcPod.Name,
			SourceContainer: srcPod.Name,

			Destination: fmt.Sprintf("%s.%s", firstSvc.Name, firstSvc.Namespace),
		}

		srcToDestStr := fmt.Sprintf("%s -> %s",
			fmt.Sprintf("%s/%s", sourceName, srcPod.Name),
			clientToFirstService.Destination)

		cond := Td.WaitForRepeatedSuccess(func() bool {
			result := Td.HTTPRequest(clientToFirstService)

			if result.Err != nil || result.StatusCode != 200 {
				Td.T.Logf("> (%s) HTTP Req failed %d %v",
					srcToDestStr, result.StatusCode, result.Err)
				return false
			}
			Td.T.Logf("> (%s) HTTP Req succeeded: %d", srcToDestStr, result.StatusCode)
			return true
		}, 5, 90*time.Second)
		Expect(cond).To(BeTrue(), "Failed testing HTTP traffic: %s", srcToDestStr)

		// Expect client to reach HTTP server using the second service as FQDN
		clientToSecondService := HTTPRequestDef{
			SourceNs:        sourceName,
			SourcePod:       srcPod.Name,
			SourceContainer: srcPod.Name,

			Destination: fmt.Sprintf("%s.%s", secondSvc.Name, secondSvc.Namespace),
		}

		srcToDestStr = fmt.Sprintf("%s -> %s",
			fmt.Sprintf("%s/%s", sourceName, srcPod.Name),
			clientToSecondService.Destination)

		cond = Td.WaitForRepeatedSuccess(func() bool {
			result := Td.HTTPRequest(clientToSecondService)

			if result.Err != nil || result.StatusCode != 200 {
				Td.T.Logf("> (%s) HTTP Req failed %d %v",
					srcToDestStr, result.StatusCode, result.Err)
				return false
			}
			Td.T.Logf("> (%s) HTTP Req succeeded: %d", srcToDestStr, result.StatusCode)
			return true
		}, 5, 90*time.Second)
		Expect(cond).To(BeTrue(), "Failed testing HTTP traffic: %s", srcToDestStr)
	})
}
