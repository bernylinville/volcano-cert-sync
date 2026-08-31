// Package config loads the intentionally small configuration surface of the
// synchronizer. It validates every target before any Kubernetes or cloud API
// call is made so a typo can never silently route a certificate to another
// product.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// TargetType is the explicit acceleration product for a domain.
type TargetType string

const (
	TargetCDN  TargetType = "cdn"  // legacy, explicit standard CDN support
	TargetDCDN TargetType = "dcdn" // Dynamic CDN
	TargetMCDN TargetType = "mcdn" // Multi-cloud CDN; never falls back to CDN
)

// SyncTarget is a DNS name and the product that owns its certificate binding.
type SyncTarget struct {
	Domain string
	Type   TargetType
}

// Config contains one Kubernetes TLS Secret and its explicit downstream
// targets. Production uses one Config/CronJob per source Secret.
type Config struct {
	VolcAccessKey string
	VolcSecretKey string

	SecretName      string
	SecretNamespace string
	SyncTargets     []SyncTarget
	DryRun          bool

	// MCDNDeployRequestTemplate is a JSON payload template for the currently
	// undocumented MCDN submit action. It is optional for read-only dry-runs;
	// an actual MCDN update refuses to run without a validated template.
	MCDNDeployRequestTemplate string
}

// Load loads an optional local .env without overriding process environment.
func Load() (*Config, error) {
	_ = godotenv.Load()
	return LoadFrom(os.Getenv)
}

// LoadFrom exists to keep configuration tests free of process-global state.
func LoadFrom(getenv func(string) string) (*Config, error) {
	dryRun, err := parseBool(getenv("DRY_RUN"))
	if err != nil {
		return nil, err
	}

	targets, err := ParseTargets(getenv("SYNC_TARGETS"), getenv("CDN_DOMAINS"))
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		VolcAccessKey:             strings.TrimSpace(getenv("VOLCENGINE_ACCESS_KEY")),
		VolcSecretKey:             strings.TrimSpace(getenv("VOLCENGINE_SECRET_KEY")),
		SecretName:                strings.TrimSpace(getenv("K8S_SECRET_NAME")),
		SecretNamespace:           strings.TrimSpace(getenv("K8S_SECRET_NAMESPACE")),
		SyncTargets:               targets,
		DryRun:                    dryRun,
		MCDNDeployRequestTemplate: strings.TrimSpace(getenv("MCDN_DEPLOY_REQUEST_TEMPLATE")),
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func parseBool(value string) (bool, error) {
	if strings.TrimSpace(value) == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("DRY_RUN must be a boolean: %w", err)
	}
	return parsed, nil
}

// ParseTargets gives SYNC_TARGETS precedence over the legacy CDN_DOMAINS
// variable. Empty list entries, duplicate domains, and unknown types are
// errors instead of being ignored or silently routed to standard CDN.
func ParseTargets(syncTargets, legacyCDNDomains string) ([]SyncTarget, error) {
	if strings.TrimSpace(syncTargets) != "" {
		return parseExplicitTargets(syncTargets)
	}
	if strings.TrimSpace(legacyCDNDomains) == "" {
		return nil, nil
	}

	parts := strings.Split(legacyCDNDomains, ",")
	targets := make([]SyncTarget, 0, len(parts))
	for _, raw := range parts {
		domain, err := normalizeDomain(raw)
		if err != nil {
			return nil, fmt.Errorf("CDN_DOMAINS: %w", err)
		}
		targets = append(targets, SyncTarget{Domain: domain, Type: TargetCDN})
	}
	return validateTargets(targets)
}

func parseExplicitTargets(raw string) ([]SyncTarget, error) {
	parts := strings.Split(raw, ",")
	targets := make([]SyncTarget, 0, len(parts))
	for _, item := range parts {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, fmt.Errorf("SYNC_TARGETS contains an empty target")
		}
		fields := strings.Split(item, ":")
		if len(fields) > 2 {
			return nil, fmt.Errorf("SYNC_TARGETS target %q has too many ':' separators", item)
		}
		domain, err := normalizeDomain(fields[0])
		if err != nil {
			return nil, fmt.Errorf("SYNC_TARGETS: %w", err)
		}

		targetType := TargetCDN // compatibility for a bare legacy domain
		if len(fields) == 2 {
			targetType = TargetType(strings.ToLower(strings.TrimSpace(fields[1])))
			if targetType == "" {
				return nil, fmt.Errorf("SYNC_TARGETS target %q has an empty type", item)
			}
		}
		targets = append(targets, SyncTarget{Domain: domain, Type: targetType})
	}
	return validateTargets(targets)
}

func validateTargets(targets []SyncTarget) ([]SyncTarget, error) {
	seen := make(map[string]TargetType, len(targets))
	for _, target := range targets {
		switch target.Type {
		case TargetCDN, TargetDCDN, TargetMCDN:
		default:
			return nil, fmt.Errorf("unsupported target type %q for %s (allowed: cdn, dcdn, mcdn)", target.Type, target.Domain)
		}
		if previous, exists := seen[target.Domain]; exists {
			if previous == target.Type {
				return nil, fmt.Errorf("duplicate target %s:%s", target.Domain, target.Type)
			}
			return nil, fmt.Errorf("conflicting target types for %s: %s and %s", target.Domain, previous, target.Type)
		}
		seen[target.Domain] = target.Type
	}
	return targets, nil
}

func normalizeDomain(value string) (string, error) {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if domain == "" {
		return "", fmt.Errorf("domain is empty")
	}
	if len(domain) > 253 {
		return "", fmt.Errorf("domain %q exceeds 253 characters", domain)
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("domain %q must contain at least one dot", domain)
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("domain %q has an invalid label", domain)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("domain %q has a label beginning or ending with '-'", domain)
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return "", fmt.Errorf("domain %q contains an invalid character", domain)
			}
		}
	}
	return domain, nil
}

// Validate checks fields shared by both a mutating run and a real read-only
// reconciliation. Dry-run still needs cloud credentials to inspect bindings.
func (c *Config) Validate() error {
	if c.VolcAccessKey == "" {
		return fmt.Errorf("VOLCENGINE_ACCESS_KEY is required")
	}
	if c.VolcSecretKey == "" {
		return fmt.Errorf("VOLCENGINE_SECRET_KEY is required")
	}
	if c.SecretName == "" {
		return fmt.Errorf("K8S_SECRET_NAME is required")
	}
	if c.SecretNamespace == "" {
		return fmt.Errorf("K8S_SECRET_NAMESPACE is required")
	}
	if len(c.SyncTargets) == 0 {
		return fmt.Errorf("SYNC_TARGETS or CDN_DOMAINS is required")
	}
	return nil
}
