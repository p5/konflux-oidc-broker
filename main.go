package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const subVersion = "v1"

var (
	signingKey        *rsa.PrivateKey
	issuerURL         string
	kid               string
	brokerAudience    string
	tokenTTL          time.Duration
	allowedNamespaces []string
	kubeClient        *http.Client
	kubeBase          string
)

// TokenRequest — client sends only the SA token projected for the broker audience.
type TokenRequest struct {
	SAToken string `json:"sa_token"`
}

type TokenResponse struct {
	Token  string            `json:"token"`
	Claims map[string]string `json:"claims"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type PipelineRunMeta struct {
	Namespace    string
	Application  string
	Component    string
	PipelineType string
	PipelineName string
	TaskName     string
	TargetBranch string
	CommitSHA    string
	PipelineRun  string
}

// --- SA Token Parsing ---

type saClaims struct {
	Kubernetes struct {
		Namespace string `json:"namespace"`
		Pod       struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"pod"`
		ServiceAccount struct {
			Name string `json:"name"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
	Sub string `json:"sub"`
}

func parseSATokenClaims(tokenStr string) (*saClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}
	var claims saClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}
	return &claims, nil
}

// --- K8s API Helpers ---

func kubeGet(path, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", kubeBase+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := kubeClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	return body, nil
}

func tokenReview(saToken, brokerToken string) (bool, string, error) {
	reviewBody := fmt.Sprintf(`{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenReview",
		"spec": {"token": %q, "audiences": [%q]}
	}`, saToken, brokerAudience)

	req, err := http.NewRequest("POST",
		kubeBase+"/apis/authentication.k8s.io/v1/tokenreviews",
		strings.NewReader(reviewBody))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+brokerToken)

	resp, err := kubeClient.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var review struct {
		Status struct {
			Authenticated bool           `json:"authenticated"`
			User          map[string]any `json:"user"`
			Error         string         `json:"error"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &review); err != nil {
		return false, "", fmt.Errorf("parsing review: %w", err)
	}

	username, _ := review.Status.User["username"].(string)
	return review.Status.Authenticated, username, nil
}

// --- Metadata Resolution ---

func resolveMetadata(namespace, podName, brokerToken string) (*PipelineRunMeta, error) {
	meta := &PipelineRunMeta{Namespace: namespace}

	// Get pod
	podData, err := kubeGet(
		fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", namespace, podName),
		brokerToken)
	if err != nil {
		return nil, fmt.Errorf("getting pod: %w", err)
	}

	var pod struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	}
	if err := json.Unmarshal(podData, &pod); err != nil {
		return nil, fmt.Errorf("parsing pod: %w", err)
	}

	if pod.Status.Phase != "Running" {
		return nil, fmt.Errorf("pod %s is not running (phase: %s)", podName, pod.Status.Phase)
	}

	// Pod must be owned by Tekton
	taskRunName := pod.Metadata.Labels["tekton.dev/taskRun"]
	if taskRunName == "" {
		return nil, fmt.Errorf("pod %s is not a Tekton task pod (missing tekton.dev/taskRun label)", podName)
	}

	// Get TaskRun
	trData, err := kubeGet(
		fmt.Sprintf("/apis/tekton.dev/v1/namespaces/%s/taskruns/%s", namespace, taskRunName),
		brokerToken)
	if err != nil {
		return nil, fmt.Errorf("getting taskrun: %w", err)
	}

	var taskRun struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(trData, &taskRun); err != nil {
		return nil, fmt.Errorf("parsing taskrun: %w", err)
	}

	meta.TaskName = taskRun.Metadata.Labels["tekton.dev/pipelineTask"]
	pipelineRunName := taskRun.Metadata.Labels["tekton.dev/pipelineRun"]
	if pipelineRunName == "" {
		return nil, fmt.Errorf("taskrun %s is not part of a PipelineRun", taskRunName)
	}

	// Get PipelineRun
	prData, err := kubeGet(
		fmt.Sprintf("/apis/tekton.dev/v1/namespaces/%s/pipelineruns/%s", namespace, pipelineRunName),
		brokerToken)
	if err != nil {
		return nil, fmt.Errorf("getting pipelinerun: %w", err)
	}

	var pipelineRun struct {
		Metadata struct {
			Name        string            `json:"name"`
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(prData, &pipelineRun); err != nil {
		return nil, fmt.Errorf("parsing pipelinerun: %w", err)
	}

	meta.PipelineRun = pipelineRun.Metadata.Name
	meta.PipelineName = pipelineRun.Metadata.Labels["tekton.dev/pipeline"]
	meta.Application = pipelineRun.Metadata.Labels["appstudio.openshift.io/application"]
	meta.Component = pipelineRun.Metadata.Labels["appstudio.openshift.io/component"]
	meta.PipelineType = pipelineRun.Metadata.Labels["pipelines.appstudio.openshift.io/type"]
	meta.CommitSHA = pipelineRun.Metadata.Annotations["build.appstudio.redhat.com/commit_sha"]
	meta.TargetBranch = pipelineRun.Metadata.Annotations["build.appstudio.redhat.com/target_branch"]

	if meta.Application == "" || meta.Component == "" {
		return nil, fmt.Errorf("pipelinerun %s missing required Konflux labels (application, component)", pipelineRunName)
	}

	return meta, nil
}

// --- Namespace Allow-list ---

func isNamespaceAllowed(ns string) bool {
	if len(allowedNamespaces) == 0 {
		return true
	}
	for _, pattern := range allowedNamespaces {
		if pattern == "*" {
			return true
		}
		if pattern == ns {
			return true
		}
		if strings.HasSuffix(pattern, "*") && strings.HasPrefix(ns, pattern[:len(pattern)-1]) {
			return true
		}
	}
	return false
}

// --- Sub Claim Construction ---

func buildSubClaim(meta *PipelineRunMeta) (string, error) {
	for field, value := range map[string]string{
		"application":  meta.Application,
		"component":    meta.Component,
		"pipelineType": meta.PipelineType,
		"pipelineName": meta.PipelineName,
		"taskName":     meta.TaskName,
		"targetBranch": meta.TargetBranch,
		"commitSHA":    meta.CommitSHA,
	} {
		if strings.Contains(value, ":") {
			return "", fmt.Errorf("invalid %s value %q: contains delimiter ':'", field, value)
		}
	}

	return fmt.Sprintf("%s:ns:%s:app:%s:component:%s:type:%s:pipeline:%s:task:%s:ref:%s",
		subVersion,
		meta.Namespace,
		meta.Application,
		meta.Component,
		meta.PipelineType,
		meta.PipelineName,
		meta.TaskName,
		meta.TargetBranch,
	), nil
}

// --- Handlers ---

func handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "reading body: "+err.Error())
		return
	}

	var req TokenRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "parsing JSON: "+err.Error())
		return
	}

	if req.SAToken == "" {
		writeError(w, http.StatusBadRequest, "sa_token is required")
		return
	}

	// Parse SA token to extract pod identity (unforgeable, bound to token)
	saClaims, err := parseSATokenClaims(req.SAToken)
	if err != nil {
		auditLog("token_failure", "", "", err.Error())
		writeError(w, http.StatusBadRequest, "parsing SA token: "+err.Error())
		return
	}

	namespace := saClaims.Kubernetes.Namespace
	podName := saClaims.Kubernetes.Pod.Name

	if namespace == "" || podName == "" {
		auditLog("token_failure", namespace, podName, "missing pod identity in SA token")
		writeError(w, http.StatusBadRequest, "SA token missing kubernetes.io pod claims")
		return
	}

	// Check namespace allow-list
	if !isNamespaceAllowed(namespace) {
		auditLog("token_failure", namespace, podName, "namespace not allowed")
		writeError(w, http.StatusForbidden, fmt.Sprintf("namespace %q is not allowed", namespace))
		return
	}

	// Validate SA token via TokenReview with broker-specific audience
	brokerSAToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reading broker SA token")
		return
	}

	authenticated, username, err := tokenReview(req.SAToken, string(brokerSAToken))
	if err != nil {
		auditLog("token_failure", namespace, podName, "TokenReview error: "+err.Error())
		writeError(w, http.StatusInternalServerError, "token review: "+err.Error())
		return
	}
	if !authenticated {
		auditLog("token_failure", namespace, podName, "token not authenticated")
		writeError(w, http.StatusUnauthorized, "token not authenticated")
		return
	}

	// Resolve PipelineRun metadata from K8s (authoritative, not client-supplied)
	meta, err := resolveMetadata(namespace, podName, string(brokerSAToken))
	if err != nil {
		auditLog("token_failure", namespace, podName, "metadata resolution: "+err.Error())
		writeError(w, http.StatusForbidden, "metadata resolution failed: "+err.Error())
		return
	}

	// Build sub claim
	sub, err := buildSubClaim(meta)
	if err != nil {
		auditLog("token_failure", namespace, podName, "sub construction: "+err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Build enriched JWT
	now := time.Now()
	jti := uuid.New().String()

	enrichedClaims := jwt.MapClaims{
		"iss": issuerURL,
		"sub": sub,
		"aud": "sts.amazonaws.com",
		"exp": now.Add(tokenTTL).Unix(),
		"iat": now.Unix(),
		"jti": jti,
		// Individual claims for GCP/Azure compatibility
		"konflux.dev/namespace":     meta.Namespace,
		"konflux.dev/application":   meta.Application,
		"konflux.dev/component":     meta.Component,
		"konflux.dev/pipeline-type": meta.PipelineType,
		"konflux.dev/pipeline":      meta.PipelineName,
		"konflux.dev/task":          meta.TaskName,
		"konflux.dev/git-ref":       meta.TargetBranch,
		"konflux.dev/git-sha":       meta.CommitSHA,
		"konflux.dev/pipelinerun":   meta.PipelineRun,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, enrichedClaims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(signingKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing token")
		return
	}

	claimsMap := map[string]string{
		"sa":            username,
		"namespace":     meta.Namespace,
		"application":   meta.Application,
		"component":     meta.Component,
		"pipeline_type": meta.PipelineType,
		"pipeline":      meta.PipelineName,
		"task":          meta.TaskName,
		"ref":           meta.TargetBranch,
		"sha":           meta.CommitSHA,
		"pipelinerun":   meta.PipelineRun,
		"sub":           sub,
	}

	auditLog("token_issued", namespace, podName,
		fmt.Sprintf("app=%s component=%s type=%s pipeline=%s task=%s ref=%s sha=%s pipelinerun=%s jti=%s",
			meta.Application, meta.Component, meta.PipelineType,
			meta.PipelineName, meta.TaskName, meta.TargetBranch,
			meta.CommitSHA, meta.PipelineRun, jti))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenResponse{Token: signed, Claims: claimsMap})
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := signingKey.PublicKey
	type jwk struct {
		Kty string `json:"kty"`
		Use string `json:"use"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	resp := struct {
		Keys []jwk `json:"keys"`
	}{
		Keys: []jwk{{
			Kty: "RSA",
			Use: "sig",
			Kid: kid,
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleDiscovery(w http.ResponseWriter, r *http.Request) {
	disc := map[string]any{
		"issuer":                                issuerURL,
		"jwks_uri":                              issuerURL + "/keys.json",
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"claims_supported": []string{
			"iss", "sub", "aud", "exp", "iat", "jti",
			"konflux.dev/namespace", "konflux.dev/application",
			"konflux.dev/component", "konflux.dev/pipeline-type",
			"konflux.dev/task", "konflux.dev/git-ref",
			"konflux.dev/git-sha", "konflux.dev/pipelinerun",
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(disc)
}

// --- Utilities ---

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{Error: msg})
}

func auditLog(event, namespace, pod, detail string) {
	log.Printf(`{"event":%q,"namespace":%q,"pod":%q,"detail":%q,"time":%q}`,
		event, namespace, pod, detail, time.Now().UTC().Format(time.RFC3339))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func buildKubeClient() *http.Client {
	caCert, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		log.Printf("WARNING: cannot read CA cert, using insecure TLS: %v", err)
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caCertPool},
		},
	}
}

func main() {
	keyPath := envOr("SIGNING_KEY_PATH", "/etc/oidc-broker/signing-key.pem")
	issuerURL = os.Getenv("ISSUER_URL")
	if issuerURL == "" {
		log.Fatal("ISSUER_URL is required")
	}

	brokerAudience = envOr("BROKER_AUDIENCE", "konflux-oidc-broker")

	ttlStr := envOr("TOKEN_TTL", "5m")
	var err error
	tokenTTL, err = time.ParseDuration(ttlStr)
	if err != nil {
		log.Fatalf("invalid TOKEN_TTL %q: %v", ttlStr, err)
	}

	nsStr := envOr("ALLOWED_NAMESPACES", "*")
	allowedNamespaces = strings.Split(nsStr, ",")
	for i := range allowedNamespaces {
		allowedNamespaces[i] = strings.TrimSpace(allowedNamespaces[i])
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		log.Fatalf("reading signing key: %v", err)
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		log.Fatal("failed to decode PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsed, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			log.Fatalf("parsing key: %v / %v", err, err2)
		}
		key = parsed.(*rsa.PrivateKey)
	}
	signingKey = key

	hash := sha256.Sum256(x509.MarshalPKCS1PublicKey(&key.PublicKey))
	kid = base64.RawURLEncoding.EncodeToString(hash[:8])

	kubeClient = buildKubeClient()
	kubeBase = fmt.Sprintf("https://%s:%s",
		envOr("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc"),
		envOr("KUBERNETES_SERVICE_PORT", "443"))

	http.HandleFunc("/.well-known/openid-configuration", handleDiscovery)
	http.HandleFunc("/keys.json", handleJWKS)
	http.HandleFunc("/token", handleToken)

	port := envOr("PORT", "8080")
	log.Printf("OIDC Broker starting on :%s (issuer: %s, audience: %s, ttl: %s, namespaces: %v)",
		port, issuerURL, brokerAudience, tokenTTL, allowedNamespaces)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
