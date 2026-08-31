package volcengine

import (
	"context"
	"fmt"
	"strings"

	"github.com/bernylinville/volcano-cert-sync/internal/cert"
	"github.com/bernylinville/volcano-cert-sync/internal/syncer"
	"github.com/volcengine/volcengine-go-sdk/service/cdn"
	ve "github.com/volcengine/volcengine-go-sdk/volcengine"
)

// CDNBackend retains explicit support for standard CDN. Production targets use
// DCDN and MCDN today, but a bare legacy target remains safe and observable.
type CDNBackend struct {
	client            *cdn.CDN
	publicFingerprint func(context.Context, string) (string, error)
}

func NewCDNBackend(accessKey, secretKey string) (*CDNBackend, error) {
	sess, err := newSession(accessKey, secretKey)
	if err != nil {
		return nil, err
	}
	return &CDNBackend{client: cdn.New(sess), publicFingerprint: publicTLSFingerprint}, nil
}

func (b *CDNBackend) Preflight(ctx context.Context, targets []syncer.Target) error {
	for _, target := range targets {
		pageNum, pageSize := int64(1), int64(10)
		output, err := b.client.ListCdnDomainsWithContext(ctx, &cdn.ListCdnDomainsInput{
			Domain:     ve.String(target.Domain),
			ExactMatch: ve.Bool(true),
			PageNum:    &pageNum,
			PageSize:   &pageSize,
		})
		if err != nil {
			return fmt.Errorf("CDN ListCdnDomains for %s: %w", target.Domain, err)
		}
		found := false
		for _, item := range output.Data {
			if item != nil && normalizedEquals(stringValue(item.Domain), target.Domain) {
				found = true
				if status := stringValue(item.Status); status != "" && !strings.EqualFold(status, "started") {
					return fmt.Errorf("CDN domain %s is not started (status=%s)", target.Domain, status)
				}
				if item.HTTPS == nil || !*item.HTTPS {
					return fmt.Errorf("CDN domain %s does not have HTTPS enabled", target.Domain)
				}
				break
			}
		}
		if !found {
			return fmt.Errorf("CDN domain %s was not found by an exact lookup", target.Domain)
		}
	}
	return nil
}

func (b *CDNBackend) Inspect(ctx context.Context, target syncer.Target) (syncer.State, error) {
	pageNum, pageSize := int64(1), int64(10)
	configured := true
	output, err := b.client.ListCdnCertInfoWithContext(ctx, &cdn.ListCdnCertInfoInput{
		Configured:       &configured,
		ConfiguredDomain: ve.String(target.Domain),
		PageNum:          &pageNum,
		PageSize:         &pageSize,
	})
	if err != nil {
		return syncer.State{}, fmt.Errorf("CDN ListCdnCertInfo for %s: %w", target.Domain, err)
	}

	state := syncer.State{}
	for _, certificate := range output.CertInfo {
		if certificate == nil || !normalizedEquals(stringValue(certificate.ConfiguredDomain), target.Domain) {
			continue
		}
		if certificate.CertFingerprint != nil {
			state.CloudFingerprint = stringValue(certificate.CertFingerprint.Sha256)
		}
		break
	}
	publicFingerprint, err := b.publicFingerprint(ctx, target.Domain)
	if err != nil {
		return syncer.State{}, err
	}
	state.PublicFingerprint = publicFingerprint
	return state, nil
}

func (b *CDNBackend) Deploy(ctx context.Context, certificate *cert.TLSCert, targets []syncer.Target) error {
	if len(targets) == 0 {
		return nil
	}
	output, err := b.client.AddCertificateWithContext(ctx, &cdn.AddCertificateInput{
		Certificate: ve.String(string(certificate.Certificate)),
		PrivateKey:  ve.String(string(certificate.PrivateKey)),
		Desc:        ve.String("cert-sync-" + certificate.ShortFingerprint()),
		Source:      ve.String("cdn_cert_hosting"),
	})
	if err != nil {
		return fmt.Errorf("CDN AddCertificate: %w", err)
	}
	certID := stringValue(output.CertId)
	if certID == "" {
		return fmt.Errorf("CDN AddCertificate returned no certificate ID")
	}

	domains := make([]string, 0, len(targets))
	for _, target := range targets {
		domains = append(domains, target.Domain)
	}
	deployOutput, err := b.client.BatchDeployCertWithContext(ctx, &cdn.BatchDeployCertInput{
		CertId: ve.String(certID),
		Domain: ve.String(strings.Join(domains, ",")),
	})
	if err != nil {
		return fmt.Errorf("CDN BatchDeployCert: %w", err)
	}
	for _, result := range deployOutput.DeployResult {
		if result != nil && strings.EqualFold(stringValue(result.Status), "fail") {
			return fmt.Errorf("CDN BatchDeployCert failed for %s: %s", stringValue(result.Domain), stringValue(result.ErrorMsg))
		}
	}
	return nil
}
