package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type TokenReviewer struct {
	Client   *http.Client
	KubeBase string
	Audience string
}

func (r *TokenReviewer) Validate(saToken string) (string, error) {
	reviewBody := fmt.Sprintf(`{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenReview",
		"spec": {"token": %q, "audiences": [%q]}
	}`, saToken, r.Audience)

	brokerToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return "", fmt.Errorf("reading broker SA token: %w", err)
	}

	req, err := http.NewRequest("POST",
		r.KubeBase+"/apis/authentication.k8s.io/v1/tokenreviews",
		strings.NewReader(reviewBody))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(brokerToken))

	resp, err := r.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token review request: %w", err)
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
		return "", fmt.Errorf("parsing review: %w", err)
	}
	if !review.Status.Authenticated {
		return "", fmt.Errorf("token not authenticated: %s", review.Status.Error)
	}

	username, _ := review.Status.User["username"].(string)
	return username, nil
}
