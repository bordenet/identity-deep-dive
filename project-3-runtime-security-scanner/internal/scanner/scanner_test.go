package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScanner_Run(t *testing.T) {
	// Create a mock OIDC server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{
				"issuer": "http://%s",
				"authorization_endpoint": "http://%s/authorize",
				"token_endpoint": "http://%s/token",
				"jwks_uri": "http://%s/jwks"
			}`,
				r.Host, r.Host, r.Host, r.Host)
		case "/authorize":
			// For the CSRF check, we expect a redirect if the state is missing.
			if r.URL.Query().Get("state") == "" {
				w.Header().Set("Location", "http://localhost:8080/callback?code=1234")
				w.WriteHeader(http.StatusFound)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	doc, err := DiscoverOIDCConfig(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Failed to discover OIDC config: %v", err)
	}

	scanner := NewScanner(server.URL, doc)
	results := scanner.Run(context.Background())

	if len(results) != 3 {
		t.Fatalf("Expected 3 results, got %d", len(results))
	}

	expected := "CSRF check: VULNERABLE. Server redirected to http://localhost:8080/callback?code=1234 without state parameter."
	if results[0] != expected {
		t.Errorf("Expected result '%s', got '%s'", expected, results[0])
	}
}
