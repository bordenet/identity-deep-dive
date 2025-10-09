package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bordenet/identity-deep-dive/project-3-runtime-security-scanner/pkg/models"
	"github.com/rs/zerolog/log"
)

// DiscoverOIDCConfig fetches and parses the OIDC discovery document.
func DiscoverOIDCConfig(ctx context.Context, issuer string) (*models.OIDCDiscoveryDocument, error) {
	discoveryURL := fmt.Sprintf("%s/.well-known/openid-configuration", issuer)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch discovery document: status code %d", resp.StatusCode)
	}

	var doc models.OIDCDiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to parse discovery document: %w", err)
	}

	return &doc, nil
}
