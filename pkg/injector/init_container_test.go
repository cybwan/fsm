package injector

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/golang/mock/gomock"
	corev1 "k8s.io/api/core/v1"

	configv1alpha3 "github.com/flomesh-io/fsm/pkg/apis/config/v1alpha3"

	"github.com/flomesh-io/fsm/pkg/configurator"
)

var _ = Describe("Test functions creating Sidecar bootstrap configuration", func() {
	const (
		containerName  = "-container-name-"
		containerImage = "-init-container-image-"
	)

	privilegedFalse := false
	runAsNonRootFalse := false
	runAsUserID := int64(0)

	mockCtrl := gomock.NewController(GinkgoT())
	mockConfigurator := configurator.NewMockConfigurator(mockCtrl)

	Context("test GetInitContainerSpec()", func() {
		It("Creates init container without ip range exclusion list", func() {
			mockConfigurator.EXPECT().GetInitContainerImage().Return(containerImage).Times(1)
			mockConfigurator.EXPECT().GetMeshConfig().Return(configv1alpha3.MeshConfig{
				Spec: configv1alpha3.MeshConfigSpec{
					Sidecar: configv1alpha3.SidecarSpec{
						LocalProxyMode: configv1alpha3.LocalProxyModeLocalhost,
					},
				},
			}).Times(1)
			mockConfigurator.EXPECT().IsLocalDNSProxyEnabled().Return(false).AnyTimes()
			mockConfigurator.EXPECT().IsWildcardDNSProxyEnabled().Return(false).AnyTimes()
			mockConfigurator.EXPECT().GetInjectedInitResources().Return(corev1.ResourceRequirements{}).AnyTimes()
			mockConfigurator.EXPECT().GetInjectedHealthcheckResources().Return(corev1.ResourceRequirements{}).AnyTimes()
			privileged := privilegedFalse
			actual := GetInitContainerSpec(containerName, mockConfigurator, nil, nil, nil, nil, privileged, corev1.PullAlways, nil)

			expected := corev1.Container{
				Name:            "-container-name-",
				Image:           "-init-container-image-",
				ImagePullPolicy: corev1.PullAlways,
				Command:         []string{"/bin/sh"},
				Args: []string{
					"-c",
					`iptables-restore --noflush <<EOF
# FSM sidecar interception rules
*nat
:FSM_PROXY_INBOUND - [0:0]
:FSM_PROXY_IN_REDIRECT - [0:0]
:FSM_PROXY_OUTBOUND - [0:0]
:FSM_PROXY_OUT_REDIRECT - [0:0]
-A FSM_PROXY_IN_REDIRECT -p tcp -j REDIRECT --to-port 15003
-A PREROUTING -p tcp -j FSM_PROXY_INBOUND
-A FSM_PROXY_INBOUND -p tcp --dport 15010 -j RETURN
-A FSM_PROXY_INBOUND -p tcp --dport 15901 -j RETURN
-A FSM_PROXY_INBOUND -p tcp --dport 15902 -j RETURN
-A FSM_PROXY_INBOUND -p tcp --dport 15903 -j RETURN
-A FSM_PROXY_INBOUND -p tcp --dport 15904 -j RETURN
-A FSM_PROXY_INBOUND -p tcp -j FSM_PROXY_IN_REDIRECT
-A FSM_PROXY_OUT_REDIRECT -p tcp -j REDIRECT --to-port 15001
-A FSM_PROXY_OUT_REDIRECT -p tcp --dport 15000 -j ACCEPT
-A OUTPUT -p tcp -j FSM_PROXY_OUTBOUND
-A FSM_PROXY_OUTBOUND -o lo ! -d 127.0.0.1/32 -m owner --uid-owner 1500 -j FSM_PROXY_IN_REDIRECT
-A FSM_PROXY_OUTBOUND -o lo -m owner ! --uid-owner 1500 -j RETURN
-A FSM_PROXY_OUTBOUND -m owner --uid-owner 1500 -j RETURN
-A FSM_PROXY_OUTBOUND -d 127.0.0.1/32 -j RETURN
-A FSM_PROXY_OUTBOUND -j FSM_PROXY_OUT_REDIRECT
COMMIT
EOF
`,
				},
				WorkingDir: "",
				Resources:  corev1.ResourceRequirements{},
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{
							"NET_ADMIN",
						},
					},
					Privileged:   &privilegedFalse,
					RunAsNonRoot: &runAsNonRootFalse,
					RunAsUser:    &runAsUserID,
				},
				Env: []corev1.EnvVar{
					{
						Name: "POD_IP",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{
								APIVersion: "v1",
								FieldPath:  "status.podIP",
							},
						},
					},
				},
				Stdin:     false,
				StdinOnce: false,
				TTY:       false,
			}

			Expect(actual).To(Equal(expected))
		})
		It("Sets podIP DNAT rule if set in meshconfig", func() {
			mockConfigurator.EXPECT().GetInitContainerImage().Return(containerImage).Times(1)
			mockConfigurator.EXPECT().GetMeshConfig().Return(configv1alpha3.MeshConfig{
				Spec: configv1alpha3.MeshConfigSpec{
					Sidecar: configv1alpha3.SidecarSpec{
						LocalProxyMode: configv1alpha3.LocalProxyModePodIP,
					},
				},
			}).Times(1)
			mockConfigurator.EXPECT().IsLocalDNSProxyEnabled().Return(false).AnyTimes()
			mockConfigurator.EXPECT().IsWildcardDNSProxyEnabled().Return(false).AnyTimes()
			mockConfigurator.EXPECT().GetInjectedInitResources().Return(corev1.ResourceRequirements{}).AnyTimes()
			mockConfigurator.EXPECT().GetInjectedHealthcheckResources().Return(corev1.ResourceRequirements{}).AnyTimes()
			privileged := privilegedFalse
			actual := GetInitContainerSpec(containerName, mockConfigurator, nil, nil, nil, nil, privileged, corev1.PullAlways, nil)

			expected := corev1.Container{
				Name:            "-container-name-",
				Image:           "-init-container-image-",
				ImagePullPolicy: corev1.PullAlways,
				Command:         []string{"/bin/sh"},
				Args: []string{
					"-c",
					`iptables-restore --noflush <<EOF
# FSM sidecar interception rules
*nat
:FSM_PROXY_INBOUND - [0:0]
:FSM_PROXY_IN_REDIRECT - [0:0]
:FSM_PROXY_OUTBOUND - [0:0]
:FSM_PROXY_OUT_REDIRECT - [0:0]
-A FSM_PROXY_IN_REDIRECT -p tcp -j REDIRECT --to-port 15003
-A PREROUTING -p tcp -j FSM_PROXY_INBOUND
-A FSM_PROXY_INBOUND -p tcp --dport 15010 -j RETURN
-A FSM_PROXY_INBOUND -p tcp --dport 15901 -j RETURN
-A FSM_PROXY_INBOUND -p tcp --dport 15902 -j RETURN
-A FSM_PROXY_INBOUND -p tcp --dport 15903 -j RETURN
-A FSM_PROXY_INBOUND -p tcp --dport 15904 -j RETURN
-A FSM_PROXY_INBOUND -p tcp -j FSM_PROXY_IN_REDIRECT
-A FSM_PROXY_OUT_REDIRECT -p tcp -j REDIRECT --to-port 15001
-A FSM_PROXY_OUT_REDIRECT -p tcp --dport 15000 -j ACCEPT
-A OUTPUT -p tcp -j FSM_PROXY_OUTBOUND
-A FSM_PROXY_OUTBOUND -o lo ! -d 127.0.0.1/32 -m owner --uid-owner 1500 -j FSM_PROXY_IN_REDIRECT
-A FSM_PROXY_OUTBOUND -o lo -m owner ! --uid-owner 1500 -j RETURN
-A FSM_PROXY_OUTBOUND -m owner --uid-owner 1500 -j RETURN
-A FSM_PROXY_OUTBOUND -d 127.0.0.1/32 -j RETURN
-I OUTPUT -p tcp -o lo -d 127.0.0.1/32 -m owner --uid-owner 1500 -j DNAT --to-destination $POD_IP
-A FSM_PROXY_OUTBOUND -j FSM_PROXY_OUT_REDIRECT
COMMIT
EOF
`,
				},
				WorkingDir: "",
				Resources:  corev1.ResourceRequirements{},
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{
							"NET_ADMIN",
						},
					},
					Privileged:   &privilegedFalse,
					RunAsNonRoot: &runAsNonRootFalse,
					RunAsUser:    &runAsUserID,
				},
				Env: []corev1.EnvVar{
					{
						Name: "POD_IP",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{
								APIVersion: "v1",
								FieldPath:  "status.podIP",
							},
						},
					},
				},
				Stdin:     false,
				StdinOnce: false,
				TTY:       false,
			}

			Expect(actual).To(Equal(expected))
		})
	})
})
