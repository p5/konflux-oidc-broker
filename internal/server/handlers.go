package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/p5/konflux-oidc-broker/internal/auth"
	"github.com/p5/konflux-oidc-broker/internal/config"
	"github.com/p5/konflux-oidc-broker/internal/metadata"
	"github.com/p5/konflux-oidc-broker/internal/token"
)

type Server struct {
	Config   *config.Config
	Reviewer *auth.TokenReviewer
	Resolver *metadata.Resolver
	Signer   *token.Signer
}

type tokenRequest struct {
	SAToken  string `json:"sa_token"`
	Audience string `json:"audience"`
}

type tokenResponse struct {
	Token  string            `json:"token"`
	Claims map[string]string `json:"claims"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "reading body: "+err.Error())
		return
	}

	var req tokenRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "parsing JSON: "+err.Error())
		return
	}
	if req.SAToken == "" {
		writeError(w, http.StatusBadRequest, "sa_token is required")
		return
	}

	saClaims, err := auth.ParseSAToken(req.SAToken)
	if err != nil {
		auditLog("token_failure", "", "", "parsing SA token: "+err.Error())
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

	if !s.Config.IsNamespaceAllowed(namespace) {
		auditLog("token_failure", namespace, podName, "namespace not allowed")
		writeError(w, http.StatusForbidden, fmt.Sprintf("namespace %q is not allowed", namespace))
		return
	}

	username, err := s.Reviewer.Validate(req.SAToken)
	if err != nil {
		auditLog("token_failure", namespace, podName, "TokenReview error: "+err.Error())
		writeError(w, http.StatusUnauthorized, "token validation failed: "+err.Error())
		return
	}

	meta, err := s.Resolver.Resolve(namespace, podName)
	if err != nil {
		auditLog("token_failure", namespace, podName, "metadata resolution: "+err.Error())
		writeError(w, http.StatusForbidden, "metadata resolution failed: "+err.Error())
		return
	}

	sub, err := token.BuildSubClaim(meta)
	if err != nil {
		auditLog("token_failure", namespace, podName, "sub construction: "+err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	audience := req.Audience
	if audience == "" {
		audience = s.Config.DefaultAudience
	}
	if !s.Config.IsAudienceAllowed(audience) {
		auditLog("token_failure", namespace, podName, "audience not allowed: "+audience)
		writeError(w, http.StatusBadRequest, fmt.Sprintf("audience %q is not allowed", audience))
		return
	}

	signed, err := s.Signer.Sign(sub, audience, meta)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing token")
		return
	}

	auditLog("token_issued", namespace, podName,
		fmt.Sprintf("sa=%s app=%s component=%s type=%s pipeline=%s task=%s ref=%s",
			username, meta.Application, meta.Component, meta.PipelineType,
			meta.PipelineName, meta.TaskName, meta.TargetBranch))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResponse{
		Token: signed,
		Claims: map[string]string{
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
		},
	})
}

func (s *Server) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.Signer.JWKS())
}

func (s *Server) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	disc := map[string]any{
		"issuer":                                s.Config.IssuerURL,
		"jwks_uri":                              s.Config.IssuerURL + "/keys.json",
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"claims_supported": []string{
			"iss", "sub", "aud", "exp", "iat", "jti",
			"konflux.dev/namespace", "konflux.dev/application",
			"konflux.dev/component", "konflux.dev/pipeline-type",
			"konflux.dev/pipeline", "konflux.dev/task",
			"konflux.dev/git-ref", "konflux.dev/git-sha",
			"konflux.dev/pipelinerun",
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(disc)
}

func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/openid-configuration", s.HandleDiscovery)
	mux.HandleFunc("/keys.json", s.HandleJWKS)
	mux.HandleFunc("/v1/token", s.HandleToken)
	mux.HandleFunc("/token", s.HandleToken)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(errorResponse{Error: msg})
}

func auditLog(event, namespace, pod, detail string) {
	log.Printf(`{"event":%q,"namespace":%q,"pod":%q,"detail":%q,"time":%q}`,
		event, namespace, pod, detail, time.Now().UTC().Format(time.RFC3339))
}
