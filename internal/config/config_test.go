package config

import (
	"strings"
	"testing"
)

func TestParseTargetsExplicitNormalizesAndPreservesType(t *testing.T) {
	targets, err := ParseTargets(" DCDN.EXAMPLE.COM.:dcdn, mcdn.example.com:mcdn ", "")
	if err != nil {
		t.Fatalf("ParseTargets() error = %v", err)
	}
	want := []SyncTarget{
		{Domain: "dcdn.example.com", Type: TargetDCDN},
		{Domain: "mcdn.example.com", Type: TargetMCDN},
	}
	if len(targets) != len(want) {
		t.Fatalf("ParseTargets() returned %d targets, want %d", len(targets), len(want))
	}
	for index := range want {
		if targets[index] != want[index] {
			t.Fatalf("target %d = %#v, want %#v", index, targets[index], want[index])
		}
	}
}

func TestParseTargetsLegacyDefaultsToCDN(t *testing.T) {
	targets, err := ParseTargets("", "one.example.com,two.example.com")
	if err != nil {
		t.Fatalf("ParseTargets() error = %v", err)
	}
	if len(targets) != 2 || targets[0].Type != TargetCDN || targets[1].Type != TargetCDN {
		t.Fatalf("legacy targets = %#v, want two CDN targets", targets)
	}
}

func TestParseTargetsRejectsAmbiguousAndInvalidValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "unknown product", value: "one.example.com:not-a-product"},
		{name: "duplicate", value: "one.example.com:dcdn,one.example.com:dcdn"},
		{name: "conflicting types", value: "one.example.com:dcdn,one.example.com:mcdn"},
		{name: "empty element", value: "one.example.com:dcdn,"},
		{name: "invalid domain", value: "not_a_domain:dcdn"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseTargets(test.value, ""); err == nil {
				t.Fatalf("ParseTargets(%q) returned nil error", test.value)
			}
		})
	}
}

func TestLoadFromValidatesInputs(t *testing.T) {
	values := map[string]string{
		"VOLCENGINE_ACCESS_KEY":        "access",
		"VOLCENGINE_SECRET_KEY":        "secret",
		"K8S_SECRET_NAME":              "source-tls",
		"K8S_SECRET_NAMESPACE":         "rights",
		"SYNC_TARGETS":                 "one.example.com:dcdn",
		"DRY_RUN":                      "true",
		"MCDN_DEPLOY_REQUEST_TEMPLATE": `{"CertificateId":"{{CERTIFICATE_ID}}"}`,
	}
	getenv := func(key string) string { return values[key] }

	cfg, err := LoadFrom(getenv)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if !cfg.DryRun || len(cfg.SyncTargets) != 1 || cfg.SyncTargets[0].Type != TargetDCDN {
		t.Fatalf("LoadFrom() config = %#v, want parsed dry-run DCDN configuration", cfg)
	}

	delete(values, "VOLCENGINE_SECRET_KEY")
	_, err = LoadFrom(getenv)
	if err == nil || !strings.Contains(err.Error(), "VOLCENGINE_SECRET_KEY") {
		t.Fatalf("LoadFrom() error = %v, want missing SecretKey validation", err)
	}
}

func TestLoadFromRejectsInvalidBoolean(t *testing.T) {
	values := map[string]string{"DRY_RUN": "sometimes"}
	_, err := LoadFrom(func(key string) string { return values[key] })
	if err == nil || !strings.Contains(err.Error(), "DRY_RUN") {
		t.Fatalf("LoadFrom() error = %v, want DRY_RUN validation", err)
	}
}
