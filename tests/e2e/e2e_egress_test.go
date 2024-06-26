package e2e

import (
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/flomesh-io/fsm/tests/framework"
)

var _ = FSMDescribe("HTTP and HTTPS Egress",
	FSMDescribeInfo{
		Tier:   1,
		Bucket: 3,
		OS:     OSCrossPlatform,
	},
	func() {
		Context("Egress", func() {
			const sourceNs = "client"

			It("Allows egress traffic when enabled", func() {
				// Install FSM
				installOpts := Td.GetFSMInstallOpts()
				installOpts.EgressEnabled = true
				Expect(Td.InstallFSM(installOpts)).To(Succeed())

				meshConfig, _ := Td.GetMeshConfig(Td.FsmNamespace)

				// Create Test NS
				Expect(Td.CreateNs(sourceNs, nil)).To(Succeed())
				Expect(Td.AddNsToMesh(true, sourceNs)).To(Succeed())

				// Get simple Pod definitions for the client
				svcAccDef, podDef, svcDef, err := Td.GetOSSpecificSleepPod(sourceNs)
				Expect(err).NotTo(HaveOccurred())

				_, err = Td.CreateServiceAccount(sourceNs, &svcAccDef)
				Expect(err).NotTo(HaveOccurred())
				srcPod, err := Td.CreatePod(sourceNs, podDef)
				Expect(err).NotTo(HaveOccurred())
				_, err = Td.CreateService(sourceNs, svcDef)
				Expect(err).NotTo(HaveOccurred())

				// Expect it to be up and running in it's receiver namespace
				Expect(Td.WaitForPodsRunningReady(sourceNs, 1, nil)).To(Succeed())
				protocols := []string{
					"http://",
					"https://",
				}
				egressURLs := []string{
					"edition.cnn.com",
					"github.com",
				}
				var urls []string
				for _, protocol := range protocols {
					for _, test := range egressURLs {
						urls = append(urls, protocol+test)
					}
				}

				for _, url := range urls {
					cond := Td.WaitForRepeatedSuccess(func() bool {
						result := Td.HTTPRequest(HTTPRequestDef{
							SourceNs:        srcPod.Namespace,
							SourcePod:       srcPod.Name,
							SourceContainer: srcPod.Name,

							Destination: url,
						})

						if result.Err != nil || result.StatusCode != 200 {
							Td.T.Logf("%s > REST req failed (status: %d) %v", url, result.StatusCode, result.Err)
							return false
						}
						Td.T.Logf("%s > REST req succeeded: %d", url, result.StatusCode)
						return true
					}, 5, Td.ReqSuccessTimeout)
					Expect(cond).To(BeTrue())
				}

				By("Disabling Egress")
				meshConfig.Spec.Traffic.EnableEgress = false
				_, err = Td.UpdateFSMConfig(meshConfig)
				Expect(err).NotTo(HaveOccurred())

				for _, url := range urls {
					cond := Td.WaitForRepeatedSuccess(func() bool {
						result := Td.HTTPRequest(HTTPRequestDef{
							SourceNs:        srcPod.Namespace,
							SourcePod:       srcPod.Name,
							SourceContainer: srcPod.Name,

							Destination: url,
						})

						if result.Err == nil || !strings.Contains(result.Err.Error(), "command terminated with exit code 7 ") {
							Td.T.Logf("%s > REST req failed incorrectly (status: %d) %v", url, result.StatusCode, result.Err)
							return false
						}
						Td.T.Logf("%s > REST req failed correctly: %v", url, result.Err)
						return true
					}, 5 /*success count threshold*/, 60*time.Second /*timeout*/)
					Expect(cond).To(BeTrue())
				}
			})
		})
	})
