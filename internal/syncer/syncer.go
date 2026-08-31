// Package syncer contains cloud-provider-neutral reconciliation. All cloud
// adapters are deliberately behind this small interface so tests can prove
// dry-run and idempotency behavior without real credentials.
package syncer

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/bernylinville/volcano-cert-sync/internal/cert"
)

// Target is an explicit cloud certificate binding target.
type Target struct {
	Domain string
	Type   string
}

// State is the read-only reconciliation result for one target.
// CloudFingerprint is the product control-plane fingerprint and
// PublicFingerprint is the certificate presented to TLS clients.
type State struct {
	CloudFingerprint  string
	PublicFingerprint string
}

func (s State) cloudMatches(source string) bool {
	return cert.EqualFingerprint(s.CloudFingerprint, source)
}

func (s State) matches(source string) bool {
	return s.cloudMatches(source) && cert.EqualFingerprint(s.PublicFingerprint, source)
}

// Backend is a product-specific adapter. Deploy receives a validated
// certificate and may import/reuse it in the certificate center. It is called
// once per product group, allowing DCDN to bind all three domains atomically.
type Backend interface {
	Preflight(ctx context.Context, targets []Target) error
	Inspect(ctx context.Context, target Target) (State, error)
	Deploy(ctx context.Context, certificate *cert.TLSCert, targets []Target) error
}

// Event is safe to write to structured logs. It contains no PEM, key, access
// key, secret key, or full cloud request payload.
type Event struct {
	Stage       string
	Domain      string
	TargetType  string
	Action      string
	Fingerprint string
	Message     string
}

// Result records the action selected for each target.
type Result struct {
	Targets map[string]string
}

// Options controls a reconciliation run. The defaults are production-safe and
// can be replaced by deterministic clocks in tests.
type Options struct {
	DryRun       bool
	PollInterval time.Duration
	PollTimeout  time.Duration
	Now          func() time.Time
	Sleep        func(context.Context, time.Duration) error
	Report       func(Event)
}

// Service reconciles one source TLS Secret to an explicit set of targets.
type Service struct {
	Backends map[string]Backend
	Options  Options
}

// Sync reads all provider state before the first write. Dry-run executes every
// validation and inspection but never calls Preflight or Deploy, making it a
// real read-only reconciliation plan rather than a configuration preview.
func (s Service) Sync(ctx context.Context, certificate *cert.TLSCert, targets []Target) (Result, error) {
	result := Result{Targets: make(map[string]string, len(targets))}
	if certificate == nil {
		return result, fmt.Errorf("certificate is required")
	}
	if len(targets) == 0 {
		return result, fmt.Errorf("at least one target is required")
	}

	domains := make([]string, 0, len(targets))
	for _, target := range targets {
		domains = append(domains, target.Domain)
	}
	if err := certificate.ValidateDomains(domains); err != nil {
		return result, err
	}

	options := s.options()
	needsDeploy := make(map[string][]Target)
	needsVerify := make(map[string][]Target)
	var errs []error

	for _, target := range targets {
		backend, exists := s.Backends[target.Type]
		if !exists {
			err := fmt.Errorf("no backend is configured for %s target %s", target.Type, target.Domain)
			errs = append(errs, err)
			result.Targets[target.Domain] = "failed"
			s.report(options, target, "inspect", "failed", certificate, err.Error())
			continue
		}

		state, err := backend.Inspect(ctx, target)
		if err != nil {
			err = fmt.Errorf("inspect %s:%s: %w", target.Type, target.Domain, err)
			errs = append(errs, err)
			result.Targets[target.Domain] = "failed"
			s.report(options, target, "inspect", "failed", certificate, err.Error())
			continue
		}

		switch {
		case state.matches(certificate.Fingerprint):
			result.Targets[target.Domain] = "unchanged"
			s.report(options, target, "inspect", "unchanged", certificate, "cloud and public TLS fingerprints already match")
		case state.cloudMatches(certificate.Fingerprint):
			needsVerify[target.Type] = append(needsVerify[target.Type], target)
			if options.DryRun {
				result.Targets[target.Domain] = "would-wait"
				s.report(options, target, "plan", "would-wait", certificate, "cloud binding matches; public TLS propagation is pending")
			} else {
				result.Targets[target.Domain] = "waiting"
				s.report(options, target, "inspect", "waiting", certificate, "cloud binding matches; waiting for public TLS propagation")
			}
		default:
			needsDeploy[target.Type] = append(needsDeploy[target.Type], target)
			if options.DryRun {
				result.Targets[target.Domain] = "would-deploy"
				s.report(options, target, "plan", "would-deploy", certificate, "cloud binding differs from source certificate")
			} else {
				result.Targets[target.Domain] = "pending"
				s.report(options, target, "inspect", "pending", certificate, "cloud binding differs from source certificate")
			}
		}
	}

	if options.DryRun {
		return result, errors.Join(errs...)
	}

	productTypes := sortedKeys(needsDeploy)
	for _, productType := range productTypes {
		group := needsDeploy[productType]
		backend := s.Backends[productType]
		if err := backend.Preflight(ctx, group); err != nil {
			err = fmt.Errorf("preflight %s: %w", productType, err)
			errs = append(errs, err)
			for _, target := range group {
				result.Targets[target.Domain] = "failed"
				s.report(options, target, "preflight", "failed", certificate, err.Error())
			}
			continue
		}
		if err := backend.Deploy(ctx, certificate, group); err != nil {
			err = fmt.Errorf("deploy %s: %w", productType, err)
			errs = append(errs, err)
			for _, target := range group {
				result.Targets[target.Domain] = "failed"
				s.report(options, target, "deploy", "failed", certificate, err.Error())
			}
			continue
		}
		for _, target := range group {
			needsVerify[productType] = append(needsVerify[productType], target)
			result.Targets[target.Domain] = "verifying"
			s.report(options, target, "deploy", "submitted", certificate, "provider accepted certificate deployment")
		}
	}

	for _, productType := range sortedKeys(needsVerify) {
		backend := s.Backends[productType]
		for _, target := range needsVerify[productType] {
			if result.Targets[target.Domain] == "failed" {
				continue
			}
			if err := s.waitForMatch(ctx, options, backend, target, certificate.Fingerprint); err != nil {
				err = fmt.Errorf("verify %s:%s: %w", productType, target.Domain, err)
				errs = append(errs, err)
				result.Targets[target.Domain] = "failed"
				s.report(options, target, "verify", "failed", certificate, err.Error())
				continue
			}
			result.Targets[target.Domain] = "synced"
			s.report(options, target, "verify", "synced", certificate, "cloud and public TLS fingerprints match")
		}
	}

	return result, errors.Join(errs...)
}

func (s Service) waitForMatch(ctx context.Context, options Options, backend Backend, target Target, fingerprint string) error {
	deadline := options.Now().Add(options.PollTimeout)
	var lastErr error
	for {
		state, err := backend.Inspect(ctx, target)
		if err == nil && state.matches(fingerprint) {
			return nil
		}
		if err != nil {
			lastErr = err
		}
		if !options.Now().Before(deadline) {
			if lastErr != nil {
				return lastErr
			}
			return fmt.Errorf("fingerprints did not converge before %s (cloud=%s public=%s)", deadline.UTC().Format(time.RFC3339), cert.ShortFingerprint(state.CloudFingerprint), cert.ShortFingerprint(state.PublicFingerprint))
		}
		if err := options.Sleep(ctx, options.PollInterval); err != nil {
			return err
		}
	}
}

func (s Service) options() Options {
	options := s.Options
	if options.PollInterval <= 0 {
		options.PollInterval = 3 * time.Second
	}
	if options.PollTimeout <= 0 {
		options.PollTimeout = 10 * time.Minute
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Sleep == nil {
		options.Sleep = sleep
	}
	return options
}

func (s Service) report(options Options, target Target, stage, action string, certificate *cert.TLSCert, message string) {
	if options.Report == nil {
		return
	}
	options.Report(Event{
		Stage:       stage,
		Domain:      target.Domain,
		TargetType:  target.Type,
		Action:      action,
		Fingerprint: certificate.ShortFingerprint(),
		Message:     message,
	})
}

func sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func sortedKeys(values map[string][]Target) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
