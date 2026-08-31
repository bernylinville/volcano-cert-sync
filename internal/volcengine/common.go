// Package volcengine contains small, product-specific adapters around the
// official Volcengine SDK. It deliberately keeps credentials and PEM data out
// of log messages and exposes only reconciliation-safe operations.
package volcengine

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	ve "github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

const defaultRegion = "cn-beijing"

func newSession(accessKey, secretKey string) (*session.Session, error) {
	configuration := ve.NewConfig().
		WithCredentials(credentials.NewStaticCredentials(accessKey, secretKey, "")).
		WithRegion(defaultRegion).
		WithMaxRetries(3)

	sess, err := session.NewSession(configuration)
	if err != nil {
		return nil, fmt.Errorf("create Volcengine SDK session: %w", err)
	}
	return sess, nil
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func stringPointers(values []string) []*string {
	result := make([]*string, 0, len(values))
	for _, value := range values {
		value := value
		result = append(result, &value)
	}
	return result
}

// publicTLSFingerprint returns the SHA-256 hash of the DER leaf presented by
// a normal, verified TLS connection. A failed public verification is surfaced
// as an error instead of being bypassed with InsecureSkipVerify.
func publicTLSFingerprint(ctx context.Context, domain string) (string, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: domain,
		},
	}

	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		return "", fmt.Errorf("verify public TLS for %s: %w", domain, err)
	}
	defer connection.Close()

	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		return "", fmt.Errorf("verify public TLS for %s: unexpected connection type", domain)
	}
	state := tlsConnection.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("verify public TLS for %s: server presented no certificate", domain)
	}

	fingerprint := sha256.Sum256(state.PeerCertificates[0].Raw)
	return hex.EncodeToString(fingerprint[:]), nil
}

func normalizedEquals(left, right string) bool {
	normalize := func(value string) string {
		return strings.ToLower(strings.TrimSpace(value))
	}
	return normalize(left) == normalize(right)
}
