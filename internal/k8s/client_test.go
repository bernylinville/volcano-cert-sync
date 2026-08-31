package k8s

import (
	"context"
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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGetTLSSecretReturnsValidatedCertificate(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	certificatePEM, privateKeyPEM := testSecretTLSMaterial(t, now)
	client := NewClientForClientset(fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "rights", Name: "source-tls"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certificatePEM,
			corev1.TLSPrivateKeyKey: privateKeyPEM,
		},
	}))
	client.now = func() time.Time { return now }

	certificate, err := client.GetTLSSecret(context.Background(), "rights", "source-tls")
	if err != nil {
		t.Fatalf("GetTLSSecret() error = %v", err)
	}
	if certificate.Fingerprint == "" || certificate.Leaf == nil {
		t.Fatalf("GetTLSSecret() = %#v, want parsed certificate", certificate)
	}
}

func TestGetTLSSecretRejectsWrongTypeAndMissingData(t *testing.T) {
	tests := []struct {
		name   string
		secret *corev1.Secret
		want   string
	}{
		{
			name:   "wrong type",
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "rights", Name: "source-tls"}, Type: corev1.SecretTypeOpaque},
			want:   "not type",
		},
		{
			name:   "missing certificate",
			secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "rights", Name: "source-tls"}, Type: corev1.SecretTypeTLS},
			want:   "missing tls.crt",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := NewClientForClientset(fake.NewSimpleClientset(test.secret))
			_, err := client.GetTLSSecret(context.Background(), "rights", "source-tls")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("GetTLSSecret() error = %v, want %q", err, test.want)
			}
		})
	}
}

func testSecretTLSMaterial(t *testing.T, now time.Time) ([]byte, []byte) {
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
		Subject:      pkix.Name{CommonName: "*.example.com"},
		DNSNames:     []string{"*.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
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
