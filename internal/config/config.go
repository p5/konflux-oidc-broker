package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	SigningKeyPath    string
	IssuerURL         string
	BrokerAudience    string
	TokenTTL          time.Duration
	AllowedNamespaces []string
	DefaultAudience   string
	AllowedAudiences  []string
	Port              string
}

func Load() (*Config, error) {
	ttlStr := envOr("TOKEN_TTL", "5m")
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return nil, err
	}

	nsStr := envOr("ALLOWED_NAMESPACES", "*")
	namespaces := strings.Split(nsStr, ",")
	for i := range namespaces {
		namespaces[i] = strings.TrimSpace(namespaces[i])
	}

	audStr := os.Getenv("ALLOWED_AUDIENCES")
	if audStr == "" {
		return nil, fmt.Errorf("ALLOWED_AUDIENCES is required")
	}
	audiences := strings.Split(audStr, ",")
	for i := range audiences {
		audiences[i] = strings.TrimSpace(audiences[i])
	}

	return &Config{
		SigningKeyPath:    envOr("SIGNING_KEY_PATH", "/etc/oidc-broker/signing-key.pem"),
		IssuerURL:         os.Getenv("ISSUER_URL"),
		BrokerAudience:    envOr("BROKER_AUDIENCE", "konflux-oidc-broker"),
		TokenTTL:          ttl,
		AllowedNamespaces: namespaces,
		DefaultAudience:   audiences[0],
		AllowedAudiences:  audiences,
		Port:              envOr("PORT", "8080"),
	}, nil
}

func (c *Config) IsNamespaceAllowed(ns string) bool {
	if len(c.AllowedNamespaces) == 0 {
		return true
	}
	for _, pattern := range c.AllowedNamespaces {
		if pattern == "*" || pattern == ns {
			return true
		}
		if strings.HasSuffix(pattern, "*") && strings.HasPrefix(ns, pattern[:len(pattern)-1]) {
			return true
		}
	}
	return false
}

func (c *Config) IsAudienceAllowed(aud string) bool {
	for _, a := range c.AllowedAudiences {
		if a == aud {
			return true
		}
	}
	return false
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
