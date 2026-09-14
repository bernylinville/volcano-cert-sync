package volcengine

import (
	"context"
	"fmt"
	"strings"

	"github.com/bernylinville/volcano-cert-sync/internal/cert"
	"github.com/bernylinville/volcano-cert-sync/internal/syncer"
	"github.com/volcengine/volcengine-go-sdk/service/cdn"
	"github.com/volcengine/volcengine-go-sdk/service/mcdn"
)

// MCDNBackend reads MCDN state through the official SDK. A built-in CDN
// domain (vendor=builtin, sub-product=cdn) shares the Volcengine CDN
// platform, so certificate deployment goes through the public CDN
// BatchDeployCert API with a Certificate Center instance. The CDN-hosting
// upload source (AddCertificate with cdn_cert_hosting) is whitelisted per
// account and is not authorized here. Third-party vendor domains are
// rejected by Preflight because the public CDN API does not manage them.
type MCDNBackend struct {
	client            *mcdn.MCDN
	cdnClient         *cdn.CDN
	certificateCenter *CertCenterClient
	publicFingerprint func(context.Context, string) (string, error)
}

func NewMCDNBackend(accessKey, secretKey string, certificateCenter *CertCenterClient) (*MCDNBackend, error) {
	if certificateCenter == nil {
		return nil, fmt.Errorf("certificate center client is required for MCDN")
	}
	sess, err := newSession(accessKey, secretKey)
	if err != nil {
		return nil, err
	}
	return &MCDNBackend{
		client:            mcdn.New(sess),
		cdnClient:         cdn.New(sess),
		certificateCenter: certificateCenter,
		publicFingerprint: publicTLSFingerprint,
	}, nil
}

func (b *MCDNBackend) Preflight(ctx context.Context, targets []syncer.Target) error {
	for _, target := range targets {
		domain, err := b.domain(ctx, target.Domain)
		if err != nil {
			return err
		}
		if !normalizedEquals(stringValue(domain.Vendor), "builtin") || !normalizedEquals(stringValue(domain.SubProduct), "cdn") {
			return fmt.Errorf("MCDN domain %s is not the built-in CDN resource expected by this synchronizer", target.Domain)
		}
		if status := stringValue(domain.Status); status != "" && !strings.EqualFold(status, "started") && !strings.EqualFold(status, "online") {
			return fmt.Errorf("MCDN domain %s is not active (status=%s)", target.Domain, status)
		}
	}
	return nil
}

func (b *MCDNBackend) Inspect(ctx context.Context, target syncer.Target) (syncer.State, error) {
	domain, err := b.domain(ctx, target.Domain)
	if err != nil {
		return syncer.State{}, err
	}
	state := syncer.State{}
	for _, certificate := range domain.Certificates {
		if certificate == nil {
			continue
		}
		if fingerprint := stringValue(certificate.FingerprintSha256); fingerprint != "" {
			state.CloudFingerprint = fingerprint
			break
		}
	}
	publicFingerprint, err := b.publicFingerprint(ctx, target.Domain)
	if err != nil {
		return syncer.State{}, err
	}
	state.PublicFingerprint = publicFingerprint
	return state, nil
}

func (b *MCDNBackend) Deploy(ctx context.Context, certificate *cert.TLSCert, targets []syncer.Target) error {
	if len(targets) == 0 {
		return nil
	}
	// The certificate center import is already authorized for this account
	// (DCDN uses it), so deploy by referencing the imported instance.
	instanceID, err := b.certificateCenter.ImportCertificate(ctx, certificate)
	if err != nil {
		return err
	}
	domains := make([]string, 0, len(targets))
	for _, target := range targets {
		domains = append(domains, target.Domain)
	}
	return deployCertViaCDNCenter(ctx, b.cdnClient, instanceID, domains)
}

func (b *MCDNBackend) domain(ctx context.Context, name string) (*mcdn.DomainForListCdnDomainsOutput, error) {
	exactName := name
	withConfigs := false
	output, err := b.client.ListCdnDomainsWithContext(ctx, &mcdn.ListCdnDomainsInput{
		ExactName:   &exactName,
		WithConfigs: &withConfigs,
	})
	if err != nil {
		return nil, fmt.Errorf("MCDN ListCdnDomains for %s: %w", name, err)
	}
	for _, domain := range output.Domains {
		if domain != nil && normalizedEquals(stringValue(domain.Name), name) {
			return domain, nil
		}
	}
	return nil, fmt.Errorf("MCDN domain %s was not found by an exact lookup", name)
}
