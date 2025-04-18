package providers

import (
	"context"
	"errors"
	"fmt"
	"time"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmversionedclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/flomesh-io/fsm/pkg/apis/config/v1alpha3"
	"github.com/flomesh-io/fsm/pkg/certificate"
	"github.com/flomesh-io/fsm/pkg/certificate/castorage/k8s"
	"github.com/flomesh-io/fsm/pkg/certificate/pem"
	"github.com/flomesh-io/fsm/pkg/certificate/providers/certmanager"
	"github.com/flomesh-io/fsm/pkg/certificate/providers/tresor"
	"github.com/flomesh-io/fsm/pkg/certificate/providers/vault"
	"github.com/flomesh-io/fsm/pkg/configurator"
	"github.com/flomesh-io/fsm/pkg/constants"
	"github.com/flomesh-io/fsm/pkg/k8s/informers"
	"github.com/flomesh-io/fsm/pkg/messaging"
)

const (
	// Additional values for the root certificate
	rootCertCountry      = "ZH"
	rootCertLocality     = "CN"
	rootCertOrganization = "Flomesh Service Mesh"
)

var getCA = func(i certificate.Issuer) (pem.RootCertificate, error) {
	cert, err := i.IssueCertificate("init-cert", nil, 1*time.Second)
	if err != nil {
		return nil, err
	}

	return cert.GetIssuingCA(), nil
}

// NewCertificateManager returns a new certificate manager with a MRC compat client.
// TODO(4713): Remove and use NewCertificateManagerFromMRC
func NewCertificateManager(ctx context.Context, kubeClient kubernetes.Interface, kubeConfig *rest.Config, cfg configurator.Configurator,
	providerNamespace string, option Options, msgBroker *messaging.Broker, checkInterval time.Duration, trustDomain string) (*certificate.Manager, error) {
	if err := option.Validate(); err != nil {
		return nil, err
	}

	mrcClient := &MRCCompatClient{
		MRCProviderGenerator: MRCProviderGenerator{
			kubeClient:      kubeClient,
			kubeConfig:      kubeConfig,
			KeyBitSize:      cfg.GetCertKeyBitSize(),
			caExtractorFunc: getCA,
		},
		mrc: &v1alpha3.MeshRootCertificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "legacy-compat",
				Namespace: providerNamespace,
			},
			Spec: v1alpha3.MeshRootCertificateSpec{
				Provider:    option.AsProviderSpec(),
				TrustDomain: trustDomain,
			},
			Status: v1alpha3.MeshRootCertificateStatus{
				State: constants.MRCStateActive,
			},
		},
	}
	// TODO(#4745): Remove after deprecating the fsm.vault.token option.
	if vaultOption, ok := option.(VaultOptions); ok {
		mrcClient.DefaultVaultToken = vaultOption.VaultToken
	}

	return certificate.NewManager(ctx, mrcClient, cfg.GetServiceCertValidityPeriod, cfg.GetIngressGatewayCertValidityPeriod, msgBroker, checkInterval)
}

// NewCertificateManagerFromMRC returns a new certificate manager.
func NewCertificateManagerFromMRC(ctx context.Context, kubeClient kubernetes.Interface, kubeConfig *rest.Config, cfg configurator.Configurator,
	providerNamespace string, option Options, msgBroker *messaging.Broker, ic *informers.InformerCollection, checkInterval time.Duration) (*certificate.Manager, error) {
	if err := option.Validate(); err != nil {
		return nil, err
	}

	mrcClient := &MRCComposer{
		MRCProviderGenerator: MRCProviderGenerator{
			kubeClient:      kubeClient,
			kubeConfig:      kubeConfig,
			KeyBitSize:      cfg.GetCertKeyBitSize(),
			caExtractorFunc: getCA,
		},
		informerCollection: ic,
	}
	// TODO(#4745): Remove after deprecating the fsm.vault.token option.
	if vaultOption, ok := option.(VaultOptions); ok {
		mrcClient.DefaultVaultToken = vaultOption.VaultToken
	}

	return certificate.NewManager(ctx, mrcClient, cfg.GetServiceCertValidityPeriod, cfg.GetIngressGatewayCertValidityPeriod, msgBroker, checkInterval)
}

// GetCertIssuerForMRC returns a certificate.Issuer generated from the provided MRC.
func (c *MRCProviderGenerator) GetCertIssuerForMRC(mrc *v1alpha3.MeshRootCertificate) (certificate.Issuer, pem.RootCertificate, error) {
	p := mrc.Spec.Provider
	var issuer certificate.Issuer
	var err error
	switch {
	case p.Tresor != nil:
		issuer, err = c.getTresorFSMCertificateManager(mrc)
	case p.Vault != nil:
		issuer, err = c.getHashiVaultFSMCertificateManager(mrc)
	case p.CertManager != nil:
		issuer, err = c.getCertManagerFSMCertificateManager(mrc)
	default:
		return nil, nil, fmt.Errorf("Unknown certificate provider: %+v", p)
	}

	if err != nil {
		return nil, nil, err
	}

	ca, err := c.caExtractorFunc(issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating init cert: %w", err)
	}

	return issuer, ca, nil
}

// getTresorFSMCertificateManager returns a certificate manager instance with Tresor as the certificate provider
func (c *MRCProviderGenerator) getTresorFSMCertificateManager(mrc *v1alpha3.MeshRootCertificate) (certificate.Issuer, error) {
	var err error
	var rootCert *certificate.Certificate

	// This part synchronizes CA creation using the inherent atomicity of kubernetes API backend
	// Assuming multiple instances of Tresor are instantiated at the same time, only one of them will
	// succeed to issue a "Create" of the secret. All other Creates will fail with "AlreadyExists".
	// Regardless of success or failure, all instances can proceed to load the same CA.
	rootCert, err = tresor.NewCA(constants.CertificationAuthorityCommonName, constants.CertificationAuthorityRootValidityPeriod, rootCertCountry, rootCertLocality, rootCertOrganization)
	if err != nil {
		return nil, errors.New("Failed to create new Certificate Authority with cert issuer tresor")
	}

	if rootCert.GetPrivateKey() == nil {
		return nil, errors.New("Root cert does not have a private key")
	}

	rootCert, err = k8s.GetCertificateFromSecret(mrc.Namespace, mrc.Spec.Provider.Tresor.CA.SecretRef.Name, rootCert, c.kubeClient)
	if err != nil {
		return nil, fmt.Errorf("Failed to synchronize certificate on Secrets API : %w", err)
	}

	if rootCert.GetPrivateKey() == nil {
		return nil, fmt.Errorf("Root cert does not have a private key: %w", certificate.ErrInvalidCertSecret)
	}

	tresorClient, err := tresor.New(
		rootCert,
		rootCertOrganization,
		c.KeyBitSize,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate Tresor as a Certificate Manager: %w", err)
	}

	return tresorClient, nil
}

// getHashiVaultFSMCertificateManager returns a certificate manager instance with Hashi Vault as the certificate provider
func (c *MRCProviderGenerator) getHashiVaultFSMCertificateManager(mrc *v1alpha3.MeshRootCertificate) (certificate.Issuer, error) {
	provider := mrc.Spec.Provider.Vault

	// A Vault address would have the following shape: "http://vault.default.svc.cluster.local:8200"
	vaultAddr := fmt.Sprintf("%s://%s:%d", provider.Protocol, provider.Host, provider.Port)

	// If the DefaultVaultToken is empty, query Vault token secret
	var err error
	vaultToken := c.DefaultVaultToken
	if vaultToken == "" {
		log.Debug().Msgf("Attempting to get Vault token from secret %s", provider.Token.SecretKeyRef.Name)
		vaultToken, err = getHashiVaultFSMToken(&provider.Token.SecretKeyRef, c.kubeClient)
		if err != nil {
			return nil, err
		}
	}

	vaultClient, err := vault.New(
		vaultAddr,
		vaultToken,
		provider.Role,
	)
	if err != nil {
		return nil, fmt.Errorf("error instantiating Hashicorp Vault as a Certificate Manager: %w", err)
	}

	return vaultClient, nil
}

// getHashiVaultFSMToken returns the Hashi Vault token from the secret specified in the provided secret key reference
func getHashiVaultFSMToken(secretKeyRef *v1alpha3.SecretKeyReferenceSpec, kubeClient kubernetes.Interface) (string, error) {
	tokenSecret, err := kubeClient.CoreV1().Secrets(secretKeyRef.Namespace).Get(context.TODO(), secretKeyRef.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error retrieving Hashi Vault token secret %s/%s: %w", secretKeyRef.Namespace, secretKeyRef.Name, err)
	}

	token, ok := tokenSecret.Data[secretKeyRef.Key]
	if !ok {
		return "", fmt.Errorf("key %s not found in Hashi Vault token secret %s/%s", secretKeyRef.Key, secretKeyRef.Namespace, secretKeyRef.Name)
	}

	return string(token), nil
}

// getCertManagerFSMCertificateManager returns a certificate manager instance with cert-manager as the certificate provider
func (c *MRCProviderGenerator) getCertManagerFSMCertificateManager(mrc *v1alpha3.MeshRootCertificate) (certificate.Issuer, error) {
	provider := mrc.Spec.Provider.CertManager
	client, err := cmversionedclient.NewForConfig(c.kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to build cert-manager client set: %w", err)
	}

	cmClient, err := certmanager.New(
		client,
		mrc.Namespace,
		cmmeta.ObjectReference{
			Name:  provider.IssuerName,
			Kind:  provider.IssuerKind,
			Group: provider.IssuerGroup,
		},
		c.KeyBitSize,
	)
	if err != nil {
		return nil, fmt.Errorf("error instantiating Jetstack cert-manager client: %w", err)
	}

	return cmClient, nil
}
