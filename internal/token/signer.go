package token

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/p5/konflux-oidc-broker/internal/metadata"
)

type Signer struct {
	Key       *rsa.PrivateKey
	Kid       string
	IssuerURL string
	TTL       time.Duration
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func NewSigner(keyPath, issuerURL string, ttl time.Duration) (*Signer, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading signing key: %w", err)
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsed, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parsing key: %v / %v", err, err2)
		}
		key = parsed.(*rsa.PrivateKey)
	}

	hash := sha256.Sum256(x509.MarshalPKCS1PublicKey(&key.PublicKey))
	kid := base64.RawURLEncoding.EncodeToString(hash[:8])

	return &Signer{Key: key, Kid: kid, IssuerURL: issuerURL, TTL: ttl}, nil
}

func (s *Signer) Sign(sub, audience string, meta *metadata.PipelineRunMeta) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":                       s.IssuerURL,
		"sub":                       sub,
		"aud":                       audience,
		"exp":                       now.Add(s.TTL).Unix(),
		"iat":                       now.Unix(),
		"jti":                       uuid.New().String(),
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

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.Kid
	return token.SignedString(s.Key)
}

func (s *Signer) JWKS() map[string]any {
	pub := s.Key.PublicKey
	return map[string]any{
		"keys": []JWK{{
			Kty: "RSA",
			Use: "sig",
			Kid: s.Kid,
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	}
}
