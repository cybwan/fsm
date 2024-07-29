//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha3

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertManagerProviderSpec) DeepCopyInto(out *CertManagerProviderSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertManagerProviderSpec.
func (in *CertManagerProviderSpec) DeepCopy() *CertManagerProviderSpec {
	if in == nil {
		return nil
	}
	out := new(CertManagerProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificateSpec) DeepCopyInto(out *CertificateSpec) {
	*out = *in
	if in.IngressGateway != nil {
		in, out := &in.IngressGateway, &out.IngressGateway
		*out = new(IngressGatewayCertSpec)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificateSpec.
func (in *CertificateSpec) DeepCopy() *CertificateSpec {
	if in == nil {
		return nil
	}
	out := new(CertificateSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterPropertySpec) DeepCopyInto(out *ClusterPropertySpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterPropertySpec.
func (in *ClusterPropertySpec) DeepCopy() *ClusterPropertySpec {
	if in == nil {
		return nil
	}
	out := new(ClusterPropertySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterSetSpec) DeepCopyInto(out *ClusterSetSpec) {
	*out = *in
	if in.Properties != nil {
		in, out := &in.Properties, &out.Properties
		*out = make([]ClusterPropertySpec, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterSetSpec.
func (in *ClusterSetSpec) DeepCopy() *ClusterSetSpec {
	if in == nil {
		return nil
	}
	out := new(ClusterSetSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ConnectorGatewaySpec) DeepCopyInto(out *ConnectorGatewaySpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ConnectorGatewaySpec.
func (in *ConnectorGatewaySpec) DeepCopy() *ConnectorGatewaySpec {
	if in == nil {
		return nil
	}
	out := new(ConnectorGatewaySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ConnectorSpec) DeepCopyInto(out *ConnectorSpec) {
	*out = *in
	out.ViaGateway = in.ViaGateway
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ConnectorSpec.
func (in *ConnectorSpec) DeepCopy() *ConnectorSpec {
	if in == nil {
		return nil
	}
	out := new(ConnectorSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EgressGatewaySpec) DeepCopyInto(out *EgressGatewaySpec) {
	*out = *in
	if in.Port != nil {
		in, out := &in.Port, &out.Port
		*out = new(int32)
		**out = **in
	}
	if in.AdminPort != nil {
		in, out := &in.AdminPort, &out.AdminPort
		*out = new(int32)
		**out = **in
	}
	if in.Replicas != nil {
		in, out := &in.Replicas, &out.Replicas
		*out = new(int32)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EgressGatewaySpec.
func (in *EgressGatewaySpec) DeepCopy() *EgressGatewaySpec {
	if in == nil {
		return nil
	}
	out := new(EgressGatewaySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExternalAuthzSpec) DeepCopyInto(out *ExternalAuthzSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExternalAuthzSpec.
func (in *ExternalAuthzSpec) DeepCopy() *ExternalAuthzSpec {
	if in == nil {
		return nil
	}
	out := new(ExternalAuthzSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FLBSpec) DeepCopyInto(out *FLBSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FLBSpec.
func (in *FLBSpec) DeepCopy() *FLBSpec {
	if in == nil {
		return nil
	}
	out := new(FLBSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FeatureFlags) DeepCopyInto(out *FeatureFlags) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FeatureFlags.
func (in *FeatureFlags) DeepCopy() *FeatureFlags {
	if in == nil {
		return nil
	}
	out := new(FeatureFlags)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GatewayAPISpec) DeepCopyInto(out *GatewayAPISpec) {
	*out = *in
	out.ProxyTag = in.ProxyTag
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GatewayAPISpec.
func (in *GatewayAPISpec) DeepCopy() *GatewayAPISpec {
	if in == nil {
		return nil
	}
	out := new(GatewayAPISpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HTTP) DeepCopyInto(out *HTTP) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HTTP.
func (in *HTTP) DeepCopy() *HTTP {
	if in == nil {
		return nil
	}
	out := new(HTTP)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImageSpec) DeepCopyInto(out *ImageSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImageSpec.
func (in *ImageSpec) DeepCopy() *ImageSpec {
	if in == nil {
		return nil
	}
	out := new(ImageSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressGatewayCertSpec) DeepCopyInto(out *IngressGatewayCertSpec) {
	*out = *in
	if in.SubjectAltNames != nil {
		in, out := &in.SubjectAltNames, &out.SubjectAltNames
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	out.Secret = in.Secret
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressGatewayCertSpec.
func (in *IngressGatewayCertSpec) DeepCopy() *IngressGatewayCertSpec {
	if in == nil {
		return nil
	}
	out := new(IngressGatewayCertSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressSpec) DeepCopyInto(out *IngressSpec) {
	*out = *in
	if in.HTTP != nil {
		in, out := &in.HTTP, &out.HTTP
		*out = new(HTTP)
		**out = **in
	}
	if in.TLS != nil {
		in, out := &in.TLS, &out.TLS
		*out = new(TLS)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressSpec.
func (in *IngressSpec) DeepCopy() *IngressSpec {
	if in == nil {
		return nil
	}
	out := new(IngressSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LocalDNSProxy) DeepCopyInto(out *LocalDNSProxy) {
	*out = *in
	in.Wildcard.DeepCopyInto(&out.Wildcard)
	if in.DB != nil {
		in, out := &in.DB, &out.DB
		*out = make([]ResolveDN, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LocalDNSProxy.
func (in *LocalDNSProxy) DeepCopy() *LocalDNSProxy {
	if in == nil {
		return nil
	}
	out := new(LocalDNSProxy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshConfig) DeepCopyInto(out *MeshConfig) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshConfig.
func (in *MeshConfig) DeepCopy() *MeshConfig {
	if in == nil {
		return nil
	}
	out := new(MeshConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *MeshConfig) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshConfigList) DeepCopyInto(out *MeshConfigList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]MeshConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshConfigList.
func (in *MeshConfigList) DeepCopy() *MeshConfigList {
	if in == nil {
		return nil
	}
	out := new(MeshConfigList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *MeshConfigList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshConfigSpec) DeepCopyInto(out *MeshConfigSpec) {
	*out = *in
	in.ClusterSet.DeepCopyInto(&out.ClusterSet)
	in.Sidecar.DeepCopyInto(&out.Sidecar)
	out.RepoServer = in.RepoServer
	in.Traffic.DeepCopyInto(&out.Traffic)
	in.Observability.DeepCopyInto(&out.Observability)
	in.Certificate.DeepCopyInto(&out.Certificate)
	out.FeatureFlags = in.FeatureFlags
	in.PluginChains.DeepCopyInto(&out.PluginChains)
	in.Ingress.DeepCopyInto(&out.Ingress)
	out.GatewayAPI = in.GatewayAPI
	out.ServiceLB = in.ServiceLB
	out.FLB = in.FLB
	in.EgressGateway.DeepCopyInto(&out.EgressGateway)
	out.Image = in.Image
	out.Misc = in.Misc
	out.Connector = in.Connector
	out.Ztm = in.Ztm
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshConfigSpec.
func (in *MeshConfigSpec) DeepCopy() *MeshConfigSpec {
	if in == nil {
		return nil
	}
	out := new(MeshConfigSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshRootCertificate) DeepCopyInto(out *MeshRootCertificate) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshRootCertificate.
func (in *MeshRootCertificate) DeepCopy() *MeshRootCertificate {
	if in == nil {
		return nil
	}
	out := new(MeshRootCertificate)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *MeshRootCertificate) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshRootCertificateList) DeepCopyInto(out *MeshRootCertificateList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]MeshRootCertificate, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshRootCertificateList.
func (in *MeshRootCertificateList) DeepCopy() *MeshRootCertificateList {
	if in == nil {
		return nil
	}
	out := new(MeshRootCertificateList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *MeshRootCertificateList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshRootCertificateSpec) DeepCopyInto(out *MeshRootCertificateSpec) {
	*out = *in
	in.Provider.DeepCopyInto(&out.Provider)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshRootCertificateSpec.
func (in *MeshRootCertificateSpec) DeepCopy() *MeshRootCertificateSpec {
	if in == nil {
		return nil
	}
	out := new(MeshRootCertificateSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshRootCertificateStatus) DeepCopyInto(out *MeshRootCertificateStatus) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshRootCertificateStatus.
func (in *MeshRootCertificateStatus) DeepCopy() *MeshRootCertificateStatus {
	if in == nil {
		return nil
	}
	out := new(MeshRootCertificateStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MiscSpec) DeepCopyInto(out *MiscSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MiscSpec.
func (in *MiscSpec) DeepCopy() *MiscSpec {
	if in == nil {
		return nil
	}
	out := new(MiscSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ObservabilitySpec) DeepCopyInto(out *ObservabilitySpec) {
	*out = *in
	in.Tracing.DeepCopyInto(&out.Tracing)
	in.RemoteLogging.DeepCopyInto(&out.RemoteLogging)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ObservabilitySpec.
func (in *ObservabilitySpec) DeepCopy() *ObservabilitySpec {
	if in == nil {
		return nil
	}
	out := new(ObservabilitySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PluginChainSpec) DeepCopyInto(out *PluginChainSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PluginChainSpec.
func (in *PluginChainSpec) DeepCopy() *PluginChainSpec {
	if in == nil {
		return nil
	}
	out := new(PluginChainSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PluginChainsSpec) DeepCopyInto(out *PluginChainsSpec) {
	*out = *in
	if in.InboundTCPChains != nil {
		in, out := &in.InboundTCPChains, &out.InboundTCPChains
		*out = make([]*PluginChainSpec, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(PluginChainSpec)
				**out = **in
			}
		}
	}
	if in.InboundHTTPChains != nil {
		in, out := &in.InboundHTTPChains, &out.InboundHTTPChains
		*out = make([]*PluginChainSpec, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(PluginChainSpec)
				**out = **in
			}
		}
	}
	if in.OutboundTCPChains != nil {
		in, out := &in.OutboundTCPChains, &out.OutboundTCPChains
		*out = make([]*PluginChainSpec, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(PluginChainSpec)
				**out = **in
			}
		}
	}
	if in.OutboundHTTPChains != nil {
		in, out := &in.OutboundHTTPChains, &out.OutboundHTTPChains
		*out = make([]*PluginChainSpec, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(PluginChainSpec)
				**out = **in
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PluginChainsSpec.
func (in *PluginChainsSpec) DeepCopy() *PluginChainsSpec {
	if in == nil {
		return nil
	}
	out := new(PluginChainsSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ProviderSpec) DeepCopyInto(out *ProviderSpec) {
	*out = *in
	if in.CertManager != nil {
		in, out := &in.CertManager, &out.CertManager
		*out = new(CertManagerProviderSpec)
		**out = **in
	}
	if in.Vault != nil {
		in, out := &in.Vault, &out.Vault
		*out = new(VaultProviderSpec)
		**out = **in
	}
	if in.Tresor != nil {
		in, out := &in.Tresor, &out.Tresor
		*out = new(TresorProviderSpec)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProviderSpec.
func (in *ProviderSpec) DeepCopy() *ProviderSpec {
	if in == nil {
		return nil
	}
	out := new(ProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ProxyTag) DeepCopyInto(out *ProxyTag) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProxyTag.
func (in *ProxyTag) DeepCopy() *ProxyTag {
	if in == nil {
		return nil
	}
	out := new(ProxyTag)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RemoteLoggingSpec) DeepCopyInto(out *RemoteLoggingSpec) {
	*out = *in
	if in.SampledFraction != nil {
		in, out := &in.SampledFraction, &out.SampledFraction
		*out = new(string)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RemoteLoggingSpec.
func (in *RemoteLoggingSpec) DeepCopy() *RemoteLoggingSpec {
	if in == nil {
		return nil
	}
	out := new(RemoteLoggingSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RepoServerSpec) DeepCopyInto(out *RepoServerSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RepoServerSpec.
func (in *RepoServerSpec) DeepCopy() *RepoServerSpec {
	if in == nil {
		return nil
	}
	out := new(RepoServerSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ResolveDN) DeepCopyInto(out *ResolveDN) {
	*out = *in
	if in.IPv4 != nil {
		in, out := &in.IPv4, &out.IPv4
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ResolveDN.
func (in *ResolveDN) DeepCopy() *ResolveDN {
	if in == nil {
		return nil
	}
	out := new(ResolveDN)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SSLPassthrough) DeepCopyInto(out *SSLPassthrough) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SSLPassthrough.
func (in *SSLPassthrough) DeepCopy() *SSLPassthrough {
	if in == nil {
		return nil
	}
	out := new(SSLPassthrough)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretKeyReferenceSpec) DeepCopyInto(out *SecretKeyReferenceSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretKeyReferenceSpec.
func (in *SecretKeyReferenceSpec) DeepCopy() *SecretKeyReferenceSpec {
	if in == nil {
		return nil
	}
	out := new(SecretKeyReferenceSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceLBSpec) DeepCopyInto(out *ServiceLBSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceLBSpec.
func (in *ServiceLBSpec) DeepCopy() *ServiceLBSpec {
	if in == nil {
		return nil
	}
	out := new(ServiceLBSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SidecarSpec) DeepCopyInto(out *SidecarSpec) {
	*out = *in
	in.Resources.DeepCopyInto(&out.Resources)
	in.InitResources.DeepCopyInto(&out.InitResources)
	in.HealthcheckResources.DeepCopyInto(&out.HealthcheckResources)
	if in.CipherSuites != nil {
		in, out := &in.CipherSuites, &out.CipherSuites
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.ECDHCurves != nil {
		in, out := &in.ECDHCurves, &out.ECDHCurves
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	in.LocalDNSProxy.DeepCopyInto(&out.LocalDNSProxy)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SidecarSpec.
func (in *SidecarSpec) DeepCopy() *SidecarSpec {
	if in == nil {
		return nil
	}
	out := new(SidecarSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLS) DeepCopyInto(out *TLS) {
	*out = *in
	if in.SSLPassthrough != nil {
		in, out := &in.SSLPassthrough, &out.SSLPassthrough
		*out = new(SSLPassthrough)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLS.
func (in *TLS) DeepCopy() *TLS {
	if in == nil {
		return nil
	}
	out := new(TLS)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TracingSpec) DeepCopyInto(out *TracingSpec) {
	*out = *in
	if in.SampledFraction != nil {
		in, out := &in.SampledFraction, &out.SampledFraction
		*out = new(string)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TracingSpec.
func (in *TracingSpec) DeepCopy() *TracingSpec {
	if in == nil {
		return nil
	}
	out := new(TracingSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TrafficSpec) DeepCopyInto(out *TrafficSpec) {
	*out = *in
	if in.OutboundIPRangeExclusionList != nil {
		in, out := &in.OutboundIPRangeExclusionList, &out.OutboundIPRangeExclusionList
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.OutboundIPRangeInclusionList != nil {
		in, out := &in.OutboundIPRangeInclusionList, &out.OutboundIPRangeInclusionList
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.OutboundPortExclusionList != nil {
		in, out := &in.OutboundPortExclusionList, &out.OutboundPortExclusionList
		*out = make([]int, len(*in))
		copy(*out, *in)
	}
	if in.InboundPortExclusionList != nil {
		in, out := &in.InboundPortExclusionList, &out.InboundPortExclusionList
		*out = make([]int, len(*in))
		copy(*out, *in)
	}
	out.InboundExternalAuthorization = in.InboundExternalAuthorization
	if in.NetworkInterfaceExclusionList != nil {
		in, out := &in.NetworkInterfaceExclusionList, &out.NetworkInterfaceExclusionList
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TrafficSpec.
func (in *TrafficSpec) DeepCopy() *TrafficSpec {
	if in == nil {
		return nil
	}
	out := new(TrafficSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TresorCASpec) DeepCopyInto(out *TresorCASpec) {
	*out = *in
	out.SecretRef = in.SecretRef
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TresorCASpec.
func (in *TresorCASpec) DeepCopy() *TresorCASpec {
	if in == nil {
		return nil
	}
	out := new(TresorCASpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TresorProviderSpec) DeepCopyInto(out *TresorProviderSpec) {
	*out = *in
	out.CA = in.CA
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TresorProviderSpec.
func (in *TresorProviderSpec) DeepCopy() *TresorProviderSpec {
	if in == nil {
		return nil
	}
	out := new(TresorProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VaultProviderSpec) DeepCopyInto(out *VaultProviderSpec) {
	*out = *in
	out.Token = in.Token
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VaultProviderSpec.
func (in *VaultProviderSpec) DeepCopy() *VaultProviderSpec {
	if in == nil {
		return nil
	}
	out := new(VaultProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VaultTokenSpec) DeepCopyInto(out *VaultTokenSpec) {
	*out = *in
	out.SecretKeyRef = in.SecretKeyRef
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VaultTokenSpec.
func (in *VaultTokenSpec) DeepCopy() *VaultTokenSpec {
	if in == nil {
		return nil
	}
	out := new(VaultTokenSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WildcardDN) DeepCopyInto(out *WildcardDN) {
	*out = *in
	if in.IPv4 != nil {
		in, out := &in.IPv4, &out.IPv4
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WildcardDN.
func (in *WildcardDN) DeepCopy() *WildcardDN {
	if in == nil {
		return nil
	}
	out := new(WildcardDN)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ZtmSpec) DeepCopyInto(out *ZtmSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ZtmSpec.
func (in *ZtmSpec) DeepCopy() *ZtmSpec {
	if in == nil {
		return nil
	}
	out := new(ZtmSpec)
	in.DeepCopyInto(out)
	return out
}
