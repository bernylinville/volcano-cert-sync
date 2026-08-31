package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestParseValidatesKeyPairAndFingerprint(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	certificatePEM, privateKeyPEM := testTLSMaterial(t, now.Add(-time.Hour), now.Add(time.Hour), []string{"*.example.com", "example.com"})

	parsed, err := Parse(certificatePEM, privateKeyPEM, now)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(parsed.Fingerprint) != 64 {
		t.Fatalf("fingerprint = %q, want SHA-256 hex", parsed.Fingerprint)
	}
	if err := parsed.ValidateDomains([]string{"api.example.com", "example.com"}); err != nil {
		t.Fatalf("ValidateDomains() error = %v", err)
	}
	if err := parsed.ValidateDomains([]string{"api.other.example"}); err == nil {
		t.Fatal("ValidateDomains() accepted uncovered domain")
	}
}

func TestParseRejectsMismatchedAndExpiredMaterial(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	certificatePEM, _ := testTLSMaterial(t, now.Add(-time.Hour), now.Add(time.Hour), []string{"example.com"})
	_, anotherKey := testTLSMaterial(t, now.Add(-time.Hour), now.Add(time.Hour), []string{"example.com"})
	if _, err := Parse(certificatePEM, anotherKey, now); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Parse() mismatch error = %v, want key mismatch", err)
	}

	expiredCert, expiredKey := testTLSMaterial(t, now.Add(-2*time.Hour), now.Add(-time.Hour), []string{"example.com"})
	if _, err := Parse(expiredCert, expiredKey, now); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Parse() expired error = %v, want expiry validation", err)
	}
}

func TestParseRejectsUnexpectedPEM(t *testing.T) {
	now := time.Now()
	certificatePEM, privateKeyPEM := testTLSMaterial(t, now.Add(-time.Hour), now.Add(time.Hour), []string{"example.com"})
	certificatePEM = append(certificatePEM, []byte("not PEM")...)
	if _, err := Parse(certificatePEM, privateKeyPEM, now); err == nil || !strings.Contains(err.Error(), "non-certificate") {
		t.Fatalf("Parse() malformed chain error = %v, want PEM validation", err)
	}
}

func TestEqualFingerprint(t *testing.T) {
	if !EqualFingerprint("AA:BB:CC", "aabbcc") {
		t.Fatal("EqualFingerprint() did not normalize separators and case")
	}
	if EqualFingerprint("", "aabbcc") {
		t.Fatal("EqualFingerprint() accepted empty value")
	}
	if got := ShortFingerprint("AA:BB:CC:DD:EE:FF:00"); got != "aabbccddeeff" {
		t.Fatalf("ShortFingerprint() = %q", got)
	}
}

func testTLSMaterial(t *testing.T, notBefore, notAfter time.Time, dnsNames []string) ([]byte, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial number error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
