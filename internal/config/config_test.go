package config

import (
	"testing"
)

func TestIsAudienceAllowed(t *testing.T) {
	c := &Config{AllowedAudiences: []string{"sts.amazonaws.com", "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider"}}

	if !c.IsAudienceAllowed("sts.amazonaws.com") {
		t.Error("should allow sts.amazonaws.com")
	}
	if !c.IsAudienceAllowed("//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider") {
		t.Error("should allow GCP audience")
	}
	if c.IsAudienceAllowed("https://evil.example.com") {
		t.Error("should reject unknown audience")
	}
}

func FuzzIsAudienceAllowed(f *testing.F) {
	f.Add("sts.amazonaws.com")
	f.Add("https://evil.example.com")
	f.Add("")
	f.Add("//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider")

	c := &Config{AllowedAudiences: []string{"sts.amazonaws.com"}}
	f.Fuzz(func(t *testing.T, aud string) {
		result := c.IsAudienceAllowed(aud)
		if aud == "sts.amazonaws.com" && !result {
			t.Error("should allow exact match")
		}
		if aud != "sts.amazonaws.com" && result {
			t.Errorf("should reject %q", aud)
		}
	})
}

func TestIsNamespaceAllowed(t *testing.T) {
	tests := []struct {
		name       string
		namespaces []string
		ns         string
		allowed    bool
	}{
		{"wildcard", []string{"*"}, "anything", true},
		{"exact match", []string{"my-ns"}, "my-ns", true},
		{"no match", []string{"my-ns"}, "other-ns", false},
		{"prefix match", []string{"tenant-*"}, "tenant-foo", true},
		{"prefix no match", []string{"tenant-*"}, "other-foo", false},
		{"multiple patterns", []string{"ns-a", "ns-b"}, "ns-b", true},
		{"empty list", []string{}, "anything", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{AllowedNamespaces: tt.namespaces}
			got := c.IsNamespaceAllowed(tt.ns)
			if got != tt.allowed {
				t.Errorf("IsNamespaceAllowed(%q) = %v, want %v", tt.ns, got, tt.allowed)
			}
		})
	}
}
