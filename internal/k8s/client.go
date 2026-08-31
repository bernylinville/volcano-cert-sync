// Package k8s reads a named TLS Secret from either in-cluster configuration or
// an explicitly configured local kubeconfig.
package k8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bernylinville/volcano-cert-sync/internal/cert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// TLSCert is kept as an alias for callers of the original package.
type TLSCert = cert.TLSCert

// Client wraps only the Kubernetes API surface this program needs.
type Client struct {
	clientset kubernetes.Interface
	now       func() time.Time
}

// NewClient prefers service-account based in-cluster configuration. Local
// callers may use KUBECONFIG; no insecure TLS fallback is ever used.
func NewClient() (*Client, error) {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		kubeconfigPath := os.Getenv("KUBECONFIG")
		if kubeconfigPath == "" {
			home, homeErr := os.UserHomeDir()
			if homeErr != nil {
				return nil, fmt.Errorf("cannot resolve home directory for kubeconfig: %w", homeErr)
			}
			kubeconfigPath = filepath.Join(home, ".kube", "config")
		}
		restConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, fmt.Errorf("build Kubernetes config: %w", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	return NewClientForClientset(clientset), nil
}

// NewClientForClientset is used by tests and local embedding without requiring
// a real kubeconfig.
func NewClientForClientset(clientset kubernetes.Interface) *Client {
	return &Client{clientset: clientset, now: time.Now}
}

// GetTLSSecret reads exactly one named TLS Secret and validates the key pair
// before returning it.
func (c *Client) GetTLSSecret(ctx context.Context, namespace, name string) (*TLSCert, error) {
	secret, err := c.clientset.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get secret %s/%s: %w", namespace, name, err)
	}
	if secret.Type != corev1.SecretTypeTLS {
		return nil, fmt.Errorf("secret %s/%s is not type kubernetes.io/tls", namespace, name)
	}
	certificate, exists := secret.Data[corev1.TLSCertKey]
	if !exists {
		return nil, fmt.Errorf("secret %s/%s is missing tls.crt", namespace, name)
	}
	privateKey, exists := secret.Data[corev1.TLSPrivateKeyKey]
	if !exists {
		return nil, fmt.Errorf("secret %s/%s is missing tls.key", namespace, name)
	}

	tlsCert, err := cert.Parse(certificate, privateKey, c.now())
	if err != nil {
		return nil, fmt.Errorf("validate secret %s/%s: %w", namespace, name, err)
	}
	return tlsCert, nil
}
