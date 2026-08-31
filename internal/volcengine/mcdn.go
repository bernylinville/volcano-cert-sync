package volcengine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bernylinville/volcano-cert-sync/internal/cert"
	"github.com/bernylinville/volcano-cert-sync/internal/syncer"
	"github.com/volcengine/volcengine-go-sdk/service/mcdn"
	"github.com/volcengine/volcengine-go-sdk/volcengine/request"
)

// MCDNBackend reads MCDN state through the official SDK. MCDN certificate
// deployment is an account-authorized operation that is not currently exposed
// in the public SDK model, so it requires a captured, reviewed JSON template.
// This prevents an invented payload from modifying a production MCDN domain.
type MCDNBackend struct {
	client            *mcdn.MCDN
	certificateCenter *CertCenterClient
	requestTemplate   string
	publicFingerprint func(context.Context, string) (string, error)
}

func NewMCDNBackend(accessKey, secretKey string, certificateCenter *CertCenterClient, requestTemplate string) (*MCDNBackend, error) {
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
		requestTemplate:   strings.TrimSpace(requestTemplate),
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
	if b.requestTemplate == "" {
		return fmt.Errorf("MCDN_DEPLOY_REQUEST_TEMPLATE is required for a mutating MCDN run; obtain the exact SubmitCertificateDeployTask payload from the authorized console/API owner")
	}

	// Parse every target template before uploading a private key. A malformed
	// template therefore cannot leave an orphaned certificate in the account.
	payloads := make([]map[string]any, 0, len(targets))
	for _, target := range targets {
		domain, err := b.domain(ctx, target.Domain)
		if err != nil {
			return err
		}
		payload, err := renderMCDNRequest(b.requestTemplate, mcdnTemplateValues{domain: domain, target: target})
		if err != nil {
			return fmt.Errorf("prepare MCDN deployment for %s: %w", target.Domain, err)
		}
		payloads = append(payloads, payload)
	}

	instanceID, err := b.certificateCenter.ImportCertificate(ctx, certificate)
	if err != nil {
		return err
	}
	for index, target := range targets {
		payload := replaceMCDNCertificateID(payloads[index], instanceID)
		if err := b.submitCertificateDeployTask(ctx, payload); err != nil {
			return fmt.Errorf("submit MCDN certificate deployment for %s: %w", target.Domain, err)
		}
	}
	return nil
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

func (b *MCDNBackend) submitCertificateDeployTask(ctx context.Context, payload map[string]any) error {
	output := map[string]any{}
	request := b.client.NewRequest(&request.Operation{
		Name:       "SubmitCertificateDeployTask",
		HTTPMethod: "POST",
		HTTPPath:   "/",
	}, &payload, &output)
	request.HTTPRequest.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.SetContext(ctx)
	if err := request.Send(); err != nil {
		return fmt.Errorf("MCDN SubmitCertificateDeployTask: %w", err)
	}
	return nil
}

type mcdnTemplateValues struct {
	domain *mcdn.DomainForListCdnDomainsOutput
	target syncer.Target
}

// renderMCDNRequest validates the authorized JSON template without logging
// it. CERTIFICATE_ID is deliberately substituted only after the template has
// been checked, so invalid configuration never triggers an import.
func renderMCDNRequest(template string, values mcdnTemplateValues) (map[string]any, error) {
	if values.domain == nil {
		return nil, fmt.Errorf("MCDN domain data is required")
	}
	replacer := strings.NewReplacer(
		"{{CERTIFICATE_ID}}", "__CERTIFICATE_ID__",
		"{{RESOURCE_ID}}", stringValue(values.domain.Id),
		"{{CLOUD_ACCOUNT_ID}}", stringValue(values.domain.CloudAccountId),
		"{{DOMAIN}}", values.target.Domain,
		"{{VENDOR}}", stringValue(values.domain.Vendor),
		"{{SUB_PRODUCT}}", stringValue(values.domain.SubProduct),
	)
	rendered := replacer.Replace(strings.TrimSpace(template))
	if strings.Contains(rendered, "{{") || strings.Contains(rendered, "}}") {
		return nil, fmt.Errorf("MCDN request template contains an unsupported placeholder")
	}
	if !strings.Contains(rendered, "__CERTIFICATE_ID__") {
		return nil, fmt.Errorf("MCDN request template must contain {{CERTIFICATE_ID}}")
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(rendered), &payload); err != nil {
		return nil, fmt.Errorf("MCDN request template must be a JSON object: %w", err)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("MCDN request template must not be empty")
	}
	return payload, nil
}

func replaceMCDNCertificateID(payload map[string]any, certificateID string) map[string]any {
	result := make(map[string]any, len(payload))
	for key, value := range payload {
		result[key] = replaceMCDNValue(value, certificateID)
	}
	return result
}

func replaceMCDNValue(value any, certificateID string) any {
	switch typed := value.(type) {
	case string:
		return strings.ReplaceAll(typed, "__CERTIFICATE_ID__", certificateID)
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, nested := range typed {
			result[key] = replaceMCDNValue(nested, certificateID)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, nested := range typed {
			result[index] = replaceMCDNValue(nested, certificateID)
		}
		return result
	default:
		return value
	}
}
