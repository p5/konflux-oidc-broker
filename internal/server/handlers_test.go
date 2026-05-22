package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/p5/konflux-oidc-broker/internal/config"
	"github.com/p5/konflux-oidc-broker/internal/token"
)

func testServer(t *testing.T, namespaces []string) *Server {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := &token.Signer{Key: key, Kid: "test-kid", IssuerURL: "https://test", TTL: 5 * time.Minute}
	if namespaces == nil {
		namespaces = []string{"*"}
	}
	return &Server{
		Config: &config.Config{
			IssuerURL:         "https://test",
			BrokerAudience:    "konflux-oidc-broker",
			AllowedNamespaces: namespaces,
			DefaultAudience:   "sts.amazonaws.com",
			AllowedAudiences:  []string{"sts.amazonaws.com"},
		},
		Signer: signer,
	}
}

func fakeSAToken(ns, pod string) string {
	claims := map[string]any{
		"kubernetes.io": map[string]any{
			"namespace": ns,
			"pod":       map[string]any{"name": pod, "uid": "test-uid"},
		},
	}
	payload, _ := json.Marshal(claims)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return "eyJhbGciOiJSUzI1NiJ9." + encoded + ".fake"
}

func TestHandleDiscovery(t *testing.T) {
	srv := testServer(t, nil)
	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	srv.HandleDiscovery(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var disc map[string]any
	json.Unmarshal(w.Body.Bytes(), &disc)
	if disc["issuer"] != "https://test" {
		t.Errorf("issuer = %v", disc["issuer"])
	}
}

func TestHandleJWKS(t *testing.T) {
	srv := testServer(t, nil)
	req := httptest.NewRequest("GET", "/keys.json", nil)
	w := httptest.NewRecorder()
	srv.HandleJWKS(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	json.Unmarshal(w.Body.Bytes(), &jwks)
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0]["kid"] != "test-kid" {
		t.Errorf("kid = %s", jwks.Keys[0]["kid"])
	}
}

func TestHandleTokenRejectsGET(t *testing.T) {
	srv := testServer(t, nil)
	req := httptest.NewRequest("GET", "/token", nil)
	w := httptest.NewRecorder()
	srv.HandleToken(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandleTokenRejectsEmptyBody(t *testing.T) {
	srv := testServer(t, nil)
	req := httptest.NewRequest("POST", "/token", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	srv.HandleToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleTokenRejectsInvalidJSON(t *testing.T) {
	srv := testServer(t, nil)
	req := httptest.NewRequest("POST", "/token", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	srv.HandleToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleTokenRejectsMissingPodClaims(t *testing.T) {
	srv := testServer(t, nil)
	claims := map[string]any{"sub": "test"}
	payload, _ := json.Marshal(claims)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	token := "eyJhbGciOiJSUzI1NiJ9." + encoded + ".fake"

	body := fmt.Sprintf(`{"sa_token": %q}`, token)
	req := httptest.NewRequest("POST", "/token", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.HandleToken(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleTokenRejectsDisallowedNamespace(t *testing.T) {
	srv := testServer(t, []string{"allowed-ns"})
	token := fakeSAToken("forbidden-ns", "pod")
	body := fmt.Sprintf(`{"sa_token": %q}`, token)
	req := httptest.NewRequest("POST", "/token", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.HandleToken(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}
