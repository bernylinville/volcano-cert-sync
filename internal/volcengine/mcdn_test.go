package volcengine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bernylinville/volcano-cert-sync/internal/syncer"
	"github.com/volcengine/volcengine-go-sdk/service/mcdn"
)

func TestRenderMCDNRequestSubstitutesOnlyApprovedValues(t *testing.T) {
	domain := &mcdn.DomainForListCdnDomainsOutput{}
	domain.SetId("resource-1")
	domain.SetCloudAccountId("account-1")
	domain.SetVendor("builtin")
	domain.SetSubProduct("cdn")
	template := `{
  "CertificateId": "{{CERTIFICATE_ID}}",
  "ResourceId": "{{RESOURCE_ID}}",
  "CloudAccountId": "{{CLOUD_ACCOUNT_ID}}",
  "Domain": "{{DOMAIN}}",
  "Vendor": "{{VENDOR}}",
  "SubProduct": "{{SUB_PRODUCT}}"
}`

	payload, err := renderMCDNRequest(template, mcdnTemplateValues{
		domain: domain,
		target: syncer.Target{Domain: "mcdn.example.com", Type: "mcdn"},
	})
	if err != nil {
		t.Fatalf("renderMCDNRequest() error = %v", err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	text := string(encoded)
	for _, want := range []string{"resource-1", "account-1", "mcdn.example.com", "builtin", "cdn", "__CERTIFICATE_ID__"} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered payload %s does not contain %q", text, want)
		}
	}
	if strings.Contains(text, "{{") {
		t.Fatalf("rendered payload retained a template marker: %s", text)
	}

	replaced := replaceMCDNCertificateID(payload, "certificate-1")
	replacedJSON, _ := json.Marshal(replaced)
	if strings.Contains(string(replacedJSON), "__CERTIFICATE_ID__") || !strings.Contains(string(replacedJSON), "certificate-1") {
		t.Fatalf("certificate replacement = %s", replacedJSON)
	}
}

func TestRenderMCDNRequestRejectsUnsafeTemplates(t *testing.T) {
	domain := &mcdn.DomainForListCdnDomainsOutput{}
	domain.SetId("resource-1")
	tests := []string{
		`{}`,
		`{"CertificateId":"not-a-template"}`,
		`{"CertificateId":"{{UNKNOWN}}"}`,
		`not-json`,
	}
	for _, template := range tests {
		t.Run(template, func(t *testing.T) {
			if _, err := renderMCDNRequest(template, mcdnTemplateValues{domain: domain, target: syncer.Target{Domain: "one.example.com"}}); err == nil {
				t.Fatalf("renderMCDNRequest(%q) returned nil error", template)
			}
		})
	}
}
