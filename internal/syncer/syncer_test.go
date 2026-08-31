package syncer

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bernylinville/volcano-cert-sync/internal/cert"
)

func TestSyncDryRunPerformsReadOnlyPlan(t *testing.T) {
	backend := newFakeBackend(map[string][]State{
		"one.example.com": {{CloudFingerprint: "old", PublicFingerprint: "old"}},
	})
	service := Service{
		Backends: map[string]Backend{"dcdn": backend},
		Options:  Options{DryRun: true},
	}

	result, err := service.Sync(context.Background(), testCertificate(), []Target{{Domain: "one.example.com", Type: "dcdn"}})
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if got := result.Targets["one.example.com"]; got != "would-deploy" {
		t.Fatalf("result = %q, want would-deploy", got)
	}
	if backend.preflightCalls != 0 || backend.deployCalls != 0 {
		t.Fatalf("dry run called preflight=%d deploy=%d, want 0/0", backend.preflightCalls, backend.deployCalls)
	}
}

func TestSyncDeploysEachProductGroupOnceAndVerifies(t *testing.T) {
	backend := newFakeBackend(map[string][]State{
		"one.example.com": {
			{CloudFingerprint: "old", PublicFingerprint: "old"},
			{CloudFingerprint: "source", PublicFingerprint: "source"},
		},
		"two.example.com": {
			{CloudFingerprint: "old", PublicFingerprint: "old"},
			{CloudFingerprint: "source", PublicFingerprint: "source"},
		},
	})
	service := Service{
		Backends: map[string]Backend{"dcdn": backend},
		Options: Options{
			PollTimeout: time.Second,
			Sleep: func(context.Context, time.Duration) error {
				return errors.New("unexpected polling sleep")
			},
		},
	}

	result, err := service.Sync(context.Background(), testCertificate(), []Target{
		{Domain: "one.example.com", Type: "dcdn"},
		{Domain: "two.example.com", Type: "dcdn"},
	})
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if backend.preflightCalls != 1 || backend.deployCalls != 1 {
		t.Fatalf("calls preflight=%d deploy=%d, want 1/1", backend.preflightCalls, backend.deployCalls)
	}
	if len(backend.lastDeploy) != 2 {
		t.Fatalf("Deploy() target count = %d, want 2", len(backend.lastDeploy))
	}
	for _, domain := range []string{"one.example.com", "two.example.com"} {
		if got := result.Targets[domain]; got != "synced" {
			t.Fatalf("result for %s = %q, want synced", domain, got)
		}
	}
}

func TestSyncDoesNotDeployWhenPreflightFails(t *testing.T) {
	backend := newFakeBackend(map[string][]State{
		"one.example.com": {{CloudFingerprint: "old", PublicFingerprint: "old"}},
	})
	backend.preflightErr = errors.New("domain is stopped")
	service := Service{Backends: map[string]Backend{"dcdn": backend}}

	result, err := service.Sync(context.Background(), testCertificate(), []Target{{Domain: "one.example.com", Type: "dcdn"}})
	if err == nil {
		t.Fatal("Sync() error = nil, want preflight error")
	}
	if backend.deployCalls != 0 {
		t.Fatalf("Deploy() calls = %d, want 0", backend.deployCalls)
	}
	if got := result.Targets["one.example.com"]; got != "failed" {
		t.Fatalf("result = %q, want failed", got)
	}
}

func TestSyncReportsMissingBackendWithoutBlockingOtherTargets(t *testing.T) {
	backend := newFakeBackend(map[string][]State{
		"one.example.com": {{CloudFingerprint: "source", PublicFingerprint: "source"}},
	})
	service := Service{Backends: map[string]Backend{"dcdn": backend}, Options: Options{DryRun: true}}

	result, err := service.Sync(context.Background(), testCertificate(), []Target{
		{Domain: "one.example.com", Type: "dcdn"},
		{Domain: "two.example.com", Type: "mcdn"},
	})
	if err == nil {
		t.Fatal("Sync() error = nil, want missing backend error")
	}
	if result.Targets["one.example.com"] != "unchanged" || result.Targets["two.example.com"] != "failed" {
		t.Fatalf("result = %#v, want independent target outcomes", result.Targets)
	}
}

func testCertificate() *cert.TLSCert {
	return &cert.TLSCert{
		Leaf:        &x509.Certificate{DNSNames: []string{"*.example.com"}},
		Fingerprint: "source",
	}
}

type fakeBackend struct {
	states         map[string][]State
	positions      map[string]int
	preflightCalls int
	deployCalls    int
	lastDeploy     []Target
	preflightErr   error
	deployErr      error
}

func newFakeBackend(states map[string][]State) *fakeBackend {
	return &fakeBackend{states: states, positions: make(map[string]int)}
}

func (b *fakeBackend) Preflight(_ context.Context, _ []Target) error {
	b.preflightCalls++
	return b.preflightErr
}

func (b *fakeBackend) Inspect(_ context.Context, target Target) (State, error) {
	states, found := b.states[target.Domain]
	if !found || len(states) == 0 {
		return State{}, fmt.Errorf("missing state for %s", target.Domain)
	}
	position := b.positions[target.Domain]
	if position >= len(states) {
		position = len(states) - 1
	}
	b.positions[target.Domain]++
	return states[position], nil
}

func (b *fakeBackend) Deploy(_ context.Context, _ *cert.TLSCert, targets []Target) error {
	b.deployCalls++
	b.lastDeploy = append([]Target(nil), targets...)
	return b.deployErr
}
