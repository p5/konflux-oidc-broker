package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/quick"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func init() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	signingKey = key
	issuerURL = "https://test-issuer.example.com"
	brokerAudience = "konflux-oidc-broker"
	tokenTTL = 5 * time.Minute
	allowedNamespaces = []string{"*"}

	hash := sha256.Sum256(x509.MarshalPKCS1PublicKey(&key.PublicKey))
	kid = base64.RawURLEncoding.EncodeToString(hash[:8])
}

// --- Unit Tests: Sub Claim Construction ---

func TestBuildSubClaim(t *testing.T) {
	tests := []struct {
		name     string
		meta     PipelineRunMeta
		expected string
	}{
		{
			name: "all fields populated",
			meta: PipelineRunMeta{
				Namespace:    "my-ns",
				Application:  "my-app",
				Component:    "api",
				PipelineType: "build",
				PipelineName: "docker-build",
				TaskName:     "buildah",
				TargetBranch: "main",
			},
			expected: "v1:ns:my-ns:app:my-app:component:api:type:build:pipeline:docker-build:task:buildah:ref:main",
		},
		{
			name: "empty optional fields",
			meta: PipelineRunMeta{
				Namespace:    "ns",
				Application:  "app",
				Component:    "comp",
				PipelineType: "",
				PipelineName: "",
				TaskName:     "",
				TargetBranch: "",
			},
			expected: "v1:ns:ns:app:app:component:comp:type::pipeline::task::ref:",
		},
		{
			name: "ref with slash",
			meta: PipelineRunMeta{
				Namespace:    "ns",
				Application:  "app",
				Component:    "comp",
				PipelineType: "build",
				PipelineName: "build",
				TaskName:     "push",
				TargetBranch: "feature/login",
			},
			expected: "v1:ns:ns:app:app:component:comp:type:build:pipeline:build:task:push:ref:feature/login",
		},
		{
			name: "ref with multiple slashes",
			meta: PipelineRunMeta{
				Namespace:    "ns",
				Application:  "app",
				Component:    "comp",
				PipelineType: "build",
				PipelineName: "build",
				TaskName:     "push",
				TargetBranch: "refs/heads/release/1.0",
			},
			expected: "v1:ns:ns:app:app:component:comp:type:build:pipeline:build:task:push:ref:refs/heads/release/1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, err := buildSubClaim(&tt.meta)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if sub != tt.expected {
				t.Errorf("got %q, want %q", sub, tt.expected)
			}
		})
	}
}

func TestBuildSubClaimRejectsColonInValues(t *testing.T) {
	fields := []struct {
		name  string
		apply func(*PipelineRunMeta)
	}{
		{"application", func(m *PipelineRunMeta) { m.Application = "evil:app" }},
		{"component", func(m *PipelineRunMeta) { m.Component = "evil:comp" }},
		{"pipelineType", func(m *PipelineRunMeta) { m.PipelineType = "evil:type" }},
		{"pipelineName", func(m *PipelineRunMeta) { m.PipelineName = "evil:pipe" }},
		{"taskName", func(m *PipelineRunMeta) { m.TaskName = "evil:task" }},
		{"targetBranch", func(m *PipelineRunMeta) { m.TargetBranch = "evil:ref" }},
		{"commitSHA", func(m *PipelineRunMeta) { m.CommitSHA = "evil:sha" }},
	}

	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			meta := PipelineRunMeta{
				Namespace:   "ns",
				Application: "app",
				Component:   "comp",
			}
			f.apply(&meta)
			_, err := buildSubClaim(&meta)
			if err == nil {
				t.Error("expected error for colon in value, got nil")
			}
			if !strings.Contains(err.Error(), "delimiter") {
				t.Errorf("error should mention delimiter, got: %v", err)
			}
		})
	}
}

func TestBuildSubClaimVersionPrefix(t *testing.T) {
	meta := PipelineRunMeta{
		Namespace:   "ns",
		Application: "app",
		Component:   "comp",
	}
	sub, err := buildSubClaim(&meta)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sub, "v1:") {
		t.Errorf("sub should start with 'v1:', got %q", sub)
	}
}

func TestBuildSubClaimFieldOrder(t *testing.T) {
	meta := PipelineRunMeta{
		Namespace:    "ns",
		Application:  "app",
		Component:    "comp",
		PipelineType: "build",
		PipelineName: "pipe",
		TaskName:     "task",
		TargetBranch: "main",
	}
	sub, _ := buildSubClaim(&meta)

	fields := []string{"ns:", "app:", "component:", "type:", "pipeline:", "task:", "ref:"}
	lastIdx := -1
	for _, f := range fields {
		idx := strings.Index(sub, f)
		if idx == -1 {
			t.Errorf("field %q not found in sub %q", f, sub)
			continue
		}
		if idx <= lastIdx {
			t.Errorf("field %q at index %d is out of order (previous was at %d)", f, idx, lastIdx)
		}
		lastIdx = idx
	}
}

// --- Unit Tests: Namespace Allow-list ---

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
			origNS := allowedNamespaces
			allowedNamespaces = tt.namespaces
			defer func() { allowedNamespaces = origNS }()

			got := isNamespaceAllowed(tt.ns)
			if got != tt.allowed {
				t.Errorf("isNamespaceAllowed(%q) = %v, want %v", tt.ns, got, tt.allowed)
			}
		})
	}
}

// --- Unit Tests: SA Token Parsing ---

func TestParseSATokenClaims(t *testing.T) {
	claims := map[string]any{
		"kubernetes.io": map[string]any{
			"namespace": "my-ns",
			"pod": map[string]any{
				"name": "my-pod",
				"uid":  "abc-123",
			},
			"serviceaccount": map[string]any{
				"name": "my-sa",
			},
		},
		"sub": "system:serviceaccount:my-ns:my-sa",
	}
	payload, _ := json.Marshal(claims)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	token := "eyJhbGciOiJSUzI1NiJ9." + encoded + ".fake-sig"

	parsed, err := parseSATokenClaims(token)
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

func TestParseSATokenClaimsInvalidJWT(t *testing.T) {
	_, err := parseSATokenClaims("not-a-jwt")
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

func TestParseSATokenClaimsInvalidBase64(t *testing.T) {
	_, err := parseSATokenClaims("header.!!!invalid!!!.sig")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

// --- Unit Tests: HTTP Handlers ---

func TestHandleDiscovery(t *testing.T) {
	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	handleDiscovery(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var disc map[string]any
	json.Unmarshal(w.Body.Bytes(), &disc)

	if disc["issuer"] != issuerURL {
		t.Errorf("issuer = %v, want %s", disc["issuer"], issuerURL)
	}
	if disc["jwks_uri"] != issuerURL+"/keys.json" {
		t.Errorf("jwks_uri = %v", disc["jwks_uri"])
	}
}

func TestHandleJWKS(t *testing.T) {
	req := httptest.NewRequest("GET", "/keys.json", nil)
	w := httptest.NewRecorder()
	handleJWKS(w, req)

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
	if jwks.Keys[0]["kty"] != "RSA" {
		t.Errorf("kty = %s, want RSA", jwks.Keys[0]["kty"])
	}
	if jwks.Keys[0]["kid"] != kid {
		t.Errorf("kid = %s, want %s", jwks.Keys[0]["kid"], kid)
	}
	if jwks.Keys[0]["alg"] != "RS256" {
		t.Errorf("alg = %s, want RS256", jwks.Keys[0]["alg"])
	}
}

func TestHandleTokenRejectsGET(t *testing.T) {
	req := httptest.NewRequest("GET", "/token", nil)
	w := httptest.NewRecorder()
	handleToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandleTokenRejectsEmptyBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/token", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	handleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleTokenRejectsInvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/token", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleTokenRejectsMissingPodClaims(t *testing.T) {
	// SA token with no kubernetes.io claims
	claims := map[string]any{"sub": "test"}
	payload, _ := json.Marshal(claims)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	token := "eyJhbGciOiJSUzI1NiJ9." + encoded + ".fake"

	body := fmt.Sprintf(`{"sa_token": %q}`, token)
	req := httptest.NewRequest("POST", "/token", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "pod claims") {
		t.Errorf("response should mention pod claims: %s", w.Body.String())
	}
}

func TestHandleTokenRejectsDisallowedNamespace(t *testing.T) {
	origNS := allowedNamespaces
	allowedNamespaces = []string{"allowed-ns"}
	defer func() { allowedNamespaces = origNS }()

	claims := map[string]any{
		"kubernetes.io": map[string]any{
			"namespace": "forbidden-ns",
			"pod":       map[string]any{"name": "pod", "uid": "uid"},
		},
	}
	payload, _ := json.Marshal(claims)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	token := "eyJhbGciOiJSUzI1NiJ9." + encoded + ".fake"

	body := fmt.Sprintf(`{"sa_token": %q}`, token)
	req := httptest.NewRequest("POST", "/token", strings.NewReader(body))
	w := httptest.NewRecorder()
	handleToken(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// --- Unit Tests: JWKS Signature Verification ---

func TestJWKSCanVerifySignedToken(t *testing.T) {
	enrichedClaims := jwt.MapClaims{
		"iss": issuerURL,
		"sub": "v1:ns:test:app:app:component:comp:type:build:pipeline:p:task:t:ref:main",
		"aud": "sts.amazonaws.com",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, enrichedClaims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(signingKey)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with public key
	parsed, err := jwt.Parse(signed, func(t *jwt.Token) (any, error) {
		return &signingKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to verify token: %v", err)
	}
	if !parsed.Valid {
		t.Error("token should be valid")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("claims type assertion failed")
	}
	if claims["iss"] != issuerURL {
		t.Errorf("iss = %v, want %s", claims["iss"], issuerURL)
	}
}

// --- Fuzz Tests ---

func FuzzBuildSubClaimNoColonInjection(f *testing.F) {
	f.Add("app", "comp", "build", "pipe", "task", "main")
	f.Add("my-app", "my-comp", "test", "docker-build", "buildah", "feature/login")
	f.Add("", "", "", "", "", "")
	f.Add("a-b-c", "x-y-z", "release", "p", "t", "refs/heads/release/1.0")

	f.Fuzz(func(t *testing.T, app, comp, ptype, pipe, task, ref string) {
		meta := PipelineRunMeta{
			Namespace:    "ns",
			Application:  app,
			Component:    comp,
			PipelineType: ptype,
			PipelineName: pipe,
			TaskName:     task,
			TargetBranch: ref,
		}

		sub, err := buildSubClaim(&meta)
		if err != nil {
			// Expected for values containing ':'
			if !strings.Contains(err.Error(), "delimiter") {
				t.Errorf("unexpected error: %v", err)
			}
			return
		}

		// Verify version prefix
		if !strings.HasPrefix(sub, "v1:") {
			t.Errorf("missing version prefix: %q", sub)
		}

		// Verify field count — should always have exactly 8 coloned key-value pairs
		// v1:ns:NS:app:APP:component:COMP:type:TYPE:pipeline:PIPE:task:TASK:ref:REF
		if !strings.Contains(sub, ":ns:") {
			t.Errorf("missing ns field in %q", sub)
		}
		if !strings.Contains(sub, ":app:") {
			t.Errorf("missing app field in %q", sub)
		}
		if !strings.Contains(sub, ":component:") {
			t.Errorf("missing component field in %q", sub)
		}
		if !strings.Contains(sub, ":type:") {
			t.Errorf("missing type field in %q", sub)
		}
		if !strings.Contains(sub, ":pipeline:") {
			t.Errorf("missing pipeline field in %q", sub)
		}
		if !strings.Contains(sub, ":task:") {
			t.Errorf("missing task field in %q", sub)
		}
		if !strings.Contains(sub, ":ref:") {
			t.Errorf("missing ref field in %q", sub)
		}
	})
}

func FuzzParseSATokenClaims(f *testing.F) {
	f.Add("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.fake")
	f.Add("not-a-jwt")
	f.Add("")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, token string) {
		// Should never panic
		parseSATokenClaims(token)
	})
}

// --- Property Tests ---

func TestBuildSubClaimIsIdempotent(t *testing.T) {
	f := func(app, comp, ref string) bool {
		// Filter out values with colons (would be rejected)
		if strings.Contains(app, ":") || strings.Contains(comp, ":") || strings.Contains(ref, ":") {
			return true
		}
		meta := PipelineRunMeta{
			Namespace:    "ns",
			Application:  app,
			Component:    comp,
			TargetBranch: ref,
		}
		sub1, err1 := buildSubClaim(&meta)
		sub2, err2 := buildSubClaim(&meta)
		if err1 != nil || err2 != nil {
			return err1 != nil && err2 != nil
		}
		return sub1 == sub2
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
