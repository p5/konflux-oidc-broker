package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestParseSAToken(t *testing.T) {
	claims := map[string]any{
		"kubernetes.io": map[string]any{
			"namespace":      "my-ns",
			"pod":            map[string]any{"name": "my-pod", "uid": "abc-123"},
			"serviceaccount": map[string]any{"name": "my-sa"},
		},
		"sub": "system:serviceaccount:my-ns:my-sa",
	}
	payload, _ := json.Marshal(claims)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	token := "eyJhbGciOiJSUzI1NiJ9." + encoded + ".fake-sig"

	parsed, err := ParseSAToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Kubernetes.Namespace != "my-ns" {
		t.Errorf("namespace = %q, want my-ns", parsed.Kubernetes.Namespace)
	}
	if parsed.Kubernetes.Pod.Name != "my-pod" {
		t.Errorf("pod name = %q, want my-pod", parsed.Kubernetes.Pod.Name)
	}
	if parsed.Kubernetes.Pod.UID != "abc-123" {
		t.Errorf("pod uid = %q, want abc-123", parsed.Kubernetes.Pod.UID)
	}
}

func TestParseSATokenInvalidJWT(t *testing.T) {
	_, err := ParseSAToken("not-a-jwt")
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

func TestParseSATokenInvalidBase64(t *testing.T) {
	_, err := ParseSAToken("header.!!!invalid!!!.sig")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func FuzzParseSATokenClaims(f *testing.F) {
	f.Add("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.fake")
	f.Add("not-a-jwt")
	f.Add("")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, token string) {
		ParseSAToken(token)
	})
}
