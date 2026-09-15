package volcengine

import (
	"context"
	"fmt"
	"strings"

	"github.com/bernylinville/volcano-cert-sync/internal/cert"
	"github.com/bernylinville/volcano-cert-sync/internal/syncer"
	"github.com/volcengine/volcengine-go-sdk/service/mcdn"
)

// MCDNBackend reads MCDN state through the official SDK. Volcengine
// confirmed there is no public API to deploy certificates to MCDN built-in
// CDN domains (the CDN API rejects them and the console-only action is not
// published), so the automated scope is the Certificate Center import. The
// binding itself is a manual console step that references the uploaded
// instance. Third-party vendor domains are rejected by Preflight because
// they are managed through vendor-specific console flows.
type MCDNBackend struct {
	client            *mcdn.MCDN
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

// Upload imports the certificate into Certificate Center. This is the full
// automated scope for MCDN targets; the domain binding is deployed manually
// from the console using the uploaded instance.
func (b *MCDNBackend) Upload(ctx context.Context, certificate *cert.TLSCert) error {
	_, err := b.certificateCenter.ImportCertificate(ctx, certificate)
	return err
}

// Deploy explains that MCDN built-in domains have no public deploy API.
// A mutating MCDN run must use the upload-only mode instead.
func (b *MCDNBackend) Deploy(ctx context.Context, certificate *cert.TLSCert, targets []syncer.Target) error {
	return fmt.Errorf("MCDN built-in CDN domains have no public deploy API (volcengine confirmation, September 2026); run with --upload-only and bind the Certificate Center instance from the console")
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
