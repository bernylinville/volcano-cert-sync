package volcengine

import (
	"context"
	"fmt"
	"strings"

	"github.com/bernylinville/volcano-cert-sync/internal/cert"
	"github.com/bernylinville/volcano-cert-sync/internal/syncer"
	"github.com/volcengine/volcengine-go-sdk/service/dcdn"
	ve "github.com/volcengine/volcengine-go-sdk/volcengine"
)

// DCDNBackend reconciles a Certificate Center certificate to DCDN domains.
// The provider bind request handles a group together, preserving the intended
// all-or-nothing rollout boundary for domains sharing one source Secret.
type DCDNBackend struct {
	client            *dcdn.DCDN
	certificateCenter *CertCenterClient
	publicFingerprint func(context.Context, string) (string, error)
}

func NewDCDNBackend(accessKey, secretKey string, certificateCenter *CertCenterClient) (*DCDNBackend, error) {
	if certificateCenter == nil {
		return nil, fmt.Errorf("certificate center client is required for DCDN")
	}
	sess, err := newSession(accessKey, secretKey)
	if err != nil {
		return nil, err
	}
	return &DCDNBackend{
		client:            dcdn.New(sess),
		certificateCenter: certificateCenter,
		publicFingerprint: publicTLSFingerprint,
	}, nil
}

func (b *DCDNBackend) Preflight(ctx context.Context, targets []syncer.Target) error {
	for _, target := range targets {
		domain, err := b.domain(ctx, target.Domain)
		if err != nil {
			return err
		}
		if status := stringValue(domain.Status); status != "" && !strings.EqualFold(status, "started") {
			return fmt.Errorf("DCDN domain %s is not started (status=%s)", target.Domain, status)
		}
		if domain.Https == nil || domain.Https.EnableHttps == nil || !*domain.Https.EnableHttps {
			return fmt.Errorf("DCDN domain %s does not have HTTPS enabled", target.Domain)
		}
	}
	return nil
}

func (b *DCDNBackend) Inspect(ctx context.Context, target syncer.Target) (syncer.State, error) {
	domain, err := b.domain(ctx, target.Domain)
	if err != nil {
		return syncer.State{}, err
	}

	state := syncer.State{}
	if domain.Https != nil && domain.Https.CertBind != nil {
		certID := stringValue(domain.Https.CertBind.CertId)
		if certID != "" {
			fingerprint, err := b.certificateCenter.Fingerprint(ctx, certID)
			if err != nil {
				return syncer.State{}, fmt.Errorf("read bound DCDN certificate for %s: %w", target.Domain, err)
			}
			state.CloudFingerprint = fingerprint
		}
	}

	publicFingerprint, err := b.publicFingerprint(ctx, target.Domain)
	if err != nil {
		return syncer.State{}, err
	}
	state.PublicFingerprint = publicFingerprint
	return state, nil
}

func (b *DCDNBackend) Deploy(ctx context.Context, certificate *cert.TLSCert, targets []syncer.Target) error {
	if len(targets) == 0 {
		return nil
	}
	instanceID, err := b.certificateCenter.ImportCertificate(ctx, certificate)
	if err != nil {
		return err
	}

	domains := make([]string, 0, len(targets))
	for _, target := range targets {
		domains = append(domains, target.Domain)
	}
	output, err := b.client.CreateCertBindWithContext(ctx, &dcdn.CreateCertBindInput{
		CertId:      ve.String(instanceID),
		CertSource:  ve.String("volc"),
		DomainNames: stringPointers(domains),
	})
	if err != nil {
		return fmt.Errorf("DCDN CreateCertBind: %w", err)
	}
	if output.Success == nil || !*output.Success {
		return fmt.Errorf("DCDN CreateCertBind did not report success")
	}
	return nil
}

func (b *DCDNBackend) domain(ctx context.Context, name string) (*dcdn.DomainListForListDomainConfigOutput, error) {
	pageNumber := int32(1)
	pageSize := int32(10)
	output, err := b.client.ListDomainConfigWithContext(ctx, &dcdn.ListDomainConfigInput{
		Keyword:    ve.String(name),
		PageNumber: &pageNumber,
		PageSize:   &pageSize,
	})
	if err != nil {
		return nil, fmt.Errorf("DCDN ListDomainConfig for %s: %w", name, err)
	}
	for _, domain := range output.DomainList {
		if domain != nil && normalizedEquals(stringValue(domain.Domain), name) {
			return domain, nil
		}
	}
	return nil, fmt.Errorf("DCDN domain %s was not found by an exact lookup", name)
}
