package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/rs/zerolog/log"
)

func (s *Scanner) checkCSRF(ctx context.Context) string {
	// 1. Build authorization URL without state parameter
	authURL, err := url.Parse(s.doc.AuthorizationEndpoint)
	if err != nil {
		return fmt.Sprintf("CSRF check failed: could not parse authorization endpoint URL: %v", err)
	}

	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", "some-client-id") // This should be a configurable value
	q.Set("redirect_uri", "http://localhost:8080/callback") // This should be a configurable value
	authURL.RawQuery = q.Encode()

	// 2. Make request to authorization endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL.String(), nil)
	if err != nil {
		return fmt.Sprintf("CSRF check failed: could not create request: %v", err)
	}

	// We use a client that doesn't follow redirects, so we can inspect the redirect response.
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf("CSRF check failed: could not make request to authorization endpoint: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close response body")
		}
	}()

	// 3. Analyze response
	// A secure server should reject the request because the state parameter is missing.
	// If the server redirects, it might be vulnerable.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		return fmt.Sprintf("CSRF check: VULNERABLE. Server redirected to %s without state parameter.", location)
	}

	if resp.StatusCode >= 400 {
		return fmt.Sprintf("CSRF check: OK. Server rejected request with status code %d.", resp.StatusCode)
	}

	return fmt.Sprintf("CSRF check: UNKNOWN. Server responded with status code %d.", resp.StatusCode)
}
