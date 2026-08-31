package volcengine

import (
	"context"
	"fmt"

	"github.com/bernylinville/volcano-cert-sync/internal/cert"
	"github.com/volcengine/volcengine-go-sdk/service/certificateservice"
	ve "github.com/volcengine/volcengine-go-sdk/volcengine"
)

// CertCenterClient imports a source certificate once and reads the fingerprint
// of an existing Certificate Center instance. It is shared by DCDN and MCDN.
type CertCenterClient struct {
	client *certificateservice.CERTIFICATESERVICE
}

func NewCertCenterClient(accessKey, secretKey string) (*CertCenterClient, error) {
	sess, err := newSession(accessKey, secretKey)
	if err != nil {
		return nil, err
	}
	return &CertCenterClient{client: certificateservice.New(sess)}, nil
}

// ImportCertificate imports a certificate only when Certificate Center does
// not already know the same certificate. RepeatId is intentionally accepted:
// it makes reruns idempotent without creating an unbounded certificate list.
func (c *CertCenterClient) ImportCertificate(ctx context.Context, certificate *cert.TLSCert) (string, error) {
	if certificate == nil {
		return "", fmt.Errorf("source certificate is required")
	}

	repeatable := false
	input := &certificateservice.ImportCertificateInput{
		CertificateInfo: &certificateservice.CertificateInfoForImportCertificateInput{
			CertificateChain: ve.String(string(certificate.Certificate)),
			PrivateKey:       ve.String(string(certificate.PrivateKey)),
		},
		Repeatable: &repeatable,
		Tag:        ve.String("cert-sync-" + certificate.ShortFingerprint()),
	}
	output, err := c.client.ImportCertificateWithContext(ctx, input)
	if err != nil {
		return "", fmt.Errorf("certificate center ImportCertificate: %w", err)
	}
	if instanceID := stringValue(output.InstanceId); instanceID != "" {
		return instanceID, nil
	}
	if repeatID := stringValue(output.RepeatId); repeatID != "" {
		return repeatID, nil
	}
	return "", fmt.Errorf("certificate center ImportCertificate returned no instance ID")
}

// Fingerprint retrieves the control-plane fingerprint for a Certificate
// Center instance. The SDK response includes a private key field, so this
// method reads only FingerPrintSha256 and never serializes the response.
func (c *CertCenterClient) Fingerprint(ctx context.Context, instanceID string) (string, error) {
	if instanceID == "" {
		return "", fmt.Errorf("certificate center instance ID is empty")
	}
	output, err := c.client.CertificateGetInstanceWithContext(ctx, &certificateservice.CertificateGetInstanceInput{
		InstanceId: ve.String(instanceID),
	})
	if err != nil {
		return "", fmt.Errorf("certificate center CertificateGetInstance: %w", err)
	}
	if output.CertificateDetail == nil {
		return "", fmt.Errorf("certificate center instance has no certificate detail")
	}
	if fingerprint := stringValue(output.CertificateDetail.FingerPrintSha256); fingerprint != "" {
		return fingerprint, nil
	}
	return "", fmt.Errorf("certificate center instance has no SHA-256 fingerprint")
}
