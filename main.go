package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/p5/konflux-oidc-broker/internal/auth"
	"github.com/p5/konflux-oidc-broker/internal/config"
	"github.com/p5/konflux-oidc-broker/internal/metadata"
	"github.com/p5/konflux-oidc-broker/internal/server"
	"github.com/p5/konflux-oidc-broker/internal/token"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}
	if cfg.IssuerURL == "" {
		log.Fatal("ISSUER_URL is required")
	}

	signer, err := token.NewSigner(cfg.SigningKeyPath, cfg.IssuerURL, cfg.TokenTTL)
	if err != nil {
		log.Fatalf("initializing signer: %v", err)
	}

	kubeClient := buildKubeClient()
	kubeBase := fmt.Sprintf("https://%s:%s",
		envOr("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc"),
		envOr("KUBERNETES_SERVICE_PORT", "443"))

	srv := &server.Server{
		Config:   cfg,
		Reviewer: &auth.TokenReviewer{Client: kubeClient, KubeBase: kubeBase, Audience: cfg.BrokerAudience},
		Resolver: &metadata.Resolver{Client: kubeClient, KubeBase: kubeBase},
		Signer:   signer,
	}

	mux := http.NewServeMux()
	srv.Register(mux)

	log.Printf("OIDC Broker starting on :%s (issuer: %s, audience: %s, ttl: %s, namespaces: %v)",
		cfg.Port, cfg.IssuerURL, cfg.BrokerAudience, cfg.TokenTTL, cfg.AllowedNamespaces)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, mux))
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
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
