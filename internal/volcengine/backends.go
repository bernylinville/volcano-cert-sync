package volcengine

import (
	"fmt"

	"github.com/bernylinville/volcano-cert-sync/internal/syncer"
)

// NewBackends initializes all explicit product adapters once. Initialization
// is local-only: no cloud API call occurs until Sync starts inspecting state.
func NewBackends(accessKey, secretKey, mcdnRequestTemplate string) (map[string]syncer.Backend, error) {
	certificateCenter, err := NewCertCenterClient(accessKey, secretKey)
	if err != nil {
		return nil, fmt.Errorf("initialize Certificate Center client: %w", err)
	}
	dcdnBackend, err := NewDCDNBackend(accessKey, secretKey, certificateCenter)
	if err != nil {
		return nil, fmt.Errorf("initialize DCDN client: %w", err)
	}
	mcdnBackend, err := NewMCDNBackend(accessKey, secretKey, certificateCenter, mcdnRequestTemplate)
	if err != nil {
		return nil, fmt.Errorf("initialize MCDN client: %w", err)
	}
	cdnBackend, err := NewCDNBackend(accessKey, secretKey)
	if err != nil {
		return nil, fmt.Errorf("initialize CDN client: %w", err)
	}
	return map[string]syncer.Backend{
		"cdn":  cdnBackend,
		"dcdn": dcdnBackend,
		"mcdn": mcdnBackend,
	}, nil
}
