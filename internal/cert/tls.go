// Package cert validates Kubernetes TLS Secret data before a private key can
// leave the cluster for certificate hosting.
package cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// TLSCert is an already validated TLS key pair and certificate chain.
// Fingerprint is the SHA-256 hash of the leaf DER certificate, matching the
// fingerprint format returned by Volcengine and TLS endpoints.
type TLSCert struct {
	Certificate []byte
	PrivateKey  []byte
	Leaf        *x509.Certificate
	Fingerprint string
}

// Parse validates non-empty PEM content, parses its certificate chain, proves
// that the private key matches the leaf public key, and rejects certificates
// which are not currently valid. It intentionally never includes PEM content
// in an error.
func Parse(certificatePEM, privateKeyPEM []byte, now time.Time) (*TLSCert, error) {
	if len(bytes.TrimSpace(certificatePEM)) == 0 {
		return nil, fmt.Errorf("tls.crt is empty")
	}
	if len(bytes.TrimSpace(privateKeyPEM)) == 0 {
		return nil, fmt.Errorf("tls.key is empty")
	}

	leaf, err := parseLeaf(certificatePEM)
	if err != nil {
		return nil, err
	}
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	if err := keyMatchesCertificate(leaf, privateKey); err != nil {
		return nil, err
	}
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}

	fingerprint := sha256.Sum256(leaf.Raw)
	return &TLSCert{
		Certificate: certificatePEM,
		PrivateKey:  privateKeyPEM,
		Leaf:        leaf,
		Fingerprint: hex.EncodeToString(fingerprint[:]),
	}, nil
}

func parseLeaf(certificatePEM []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("tls.crt does not start with a PEM certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tls.crt leaf certificate is invalid: %w", err)
	}
	for len(bytes.TrimSpace(rest)) > 0 {
		next, remaining := pem.Decode(rest)
		if next == nil || next.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("tls.crt contains non-certificate PEM data")
		}
		if _, err := x509.ParseCertificate(next.Bytes); err != nil {
			return nil, fmt.Errorf("tls.crt certificate chain is invalid: %w", err)
		}
		rest = remaining
	}
	return leaf, nil
}

func parsePrivateKey(privateKeyPEM []byte) (crypto.PrivateKey, error) {
	block, rest := pem.Decode(privateKeyPEM)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("tls.key must contain exactly one PEM private key")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("tls.key is not a supported RSA, ECDSA, or PKCS#8 private key")
}

func keyMatchesCertificate(certificate *x509.Certificate, key crypto.PrivateKey) error {
	var public crypto.PublicKey
	switch typed := key.(type) {
	case *rsa.PrivateKey:
		public = &typed.PublicKey
	case *ecdsa.PrivateKey:
		public = &typed.PublicKey
	case crypto.Signer:
		public = typed.Public()
	default:
		return fmt.Errorf("tls.key has no public key")
	}

	certificatePublic, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return fmt.Errorf("cannot encode certificate public key: %w", err)
	}
	privatePublic, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return fmt.Errorf("cannot encode private key public component: %w", err)
	}
	if !bytes.Equal(certificatePublic, privatePublic) {
		return fmt.Errorf("tls.key does not match tls.crt")
	}
	return nil
}

// ValidateDomains ensures every explicit cloud target is covered by the leaf
// certificate. x509.VerifyHostname implements wildcard matching correctly.
func (c *TLSCert) ValidateDomains(domains []string) error {
	for _, domain := range domains {
		if err := c.Leaf.VerifyHostname(domain); err != nil {
			return fmt.Errorf("certificate does not cover %s: %w", domain, err)
		}
	}
	return nil
}

// ShortFingerprint is suitable for logs and never reveals certificate content.
func (c *TLSCert) ShortFingerprint() string {
	return ShortFingerprint(c.Fingerprint)
}

// ShortFingerprint normalizes a known fingerprint and returns a concise,
// non-secret correlation value for logs.
func ShortFingerprint(fingerprint string) string {
	fingerprint = strings.ReplaceAll(strings.ToLower(fingerprint), ":", "")
	if len(fingerprint) <= 12 {
		return fingerprint
	}
	return fingerprint[:12]
}

// EqualFingerprint compares common colon-separated/upper-case API output with
// the locally calculated lower-case DER hash.
func EqualFingerprint(left, right string) bool {
	normalize := func(value string) string {
		return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), ":", "")
	}
	return normalize(left) != "" && normalize(left) == normalize(right)
}
