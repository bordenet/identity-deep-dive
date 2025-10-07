package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/pkg/models"
	"github.com/redis/go-redis/v9"
)

// RedisStore implements session storage using Redis
type RedisStore struct {
	client    *redis.Client
	keyPrefix string
}

// NewRedisStore creates a new Redis-backed session store
func NewRedisStore(client *redis.Client, keyPrefix string) *RedisStore {
	return &RedisStore{
		client:    client,
		keyPrefix: keyPrefix,
	}
}

// StoreAuthorizationCode stores an authorization code in Redis
func (rs *RedisStore) StoreAuthorizationCode(ctx context.Context, code *models.AuthorizationCode) error {
	key := rs.authCodeKey(code.Code)

	data, err := json.Marshal(code)
	if err != nil {
		return fmt.Errorf("failed to marshal authorization code: %w", err)
	}

	ttl := time.Until(code.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("authorization code already expired")
	}

	err = rs.client.Set(ctx, key, data, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to store authorization code: %w", err)
	}

	return nil
}

// GetAuthorizationCode retrieves an authorization code from Redis
func (rs *RedisStore) GetAuthorizationCode(ctx context.Context, code string) (*models.AuthorizationCode, error) {
	key := rs.authCodeKey(code)

	data, err := rs.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, fmt.Errorf("authorization code not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get authorization code: %w", err)
	}

	var authCode models.AuthorizationCode
	err = json.Unmarshal(data, &authCode)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal authorization code: %w", err)
	}

	return &authCode, nil
}

// InvalidateAuthorizationCode marks an authorization code as used
func (rs *RedisStore) InvalidateAuthorizationCode(ctx context.Context, code string) error {
	key := rs.authCodeKey(code)

	// Delete the authorization code from Redis
	err := rs.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to invalidate authorization code: %w", err)
	}

	return nil
}

// StoreRefreshToken stores a refresh token in Redis
func (rs *RedisStore) StoreRefreshToken(ctx context.Context, refreshToken *models.RefreshToken) error {
	key := rs.refreshTokenKey(refreshToken.Token)

	data, err := json.Marshal(refreshToken)
	if err != nil {
		return fmt.Errorf("failed to marshal refresh token: %w", err)
	}

	ttl := time.Until(refreshToken.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("refresh token already expired")
	}

	err = rs.client.Set(ctx, key, data, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	return nil
}

// GetRefreshToken retrieves a refresh token from Redis
func (rs *RedisStore) GetRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	key := rs.refreshTokenKey(token)

	data, err := rs.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, fmt.Errorf("refresh token not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	var refreshToken models.RefreshToken
	err = json.Unmarshal(data, &refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal refresh token: %w", err)
	}

	return &refreshToken, nil
}

// RevokeRefreshToken deletes a refresh token from Redis
func (rs *RedisStore) RevokeRefreshToken(ctx context.Context, token string) error {
	key := rs.refreshTokenKey(token)

	err := rs.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	return nil
}

// RevokeToken adds a token to the revocation blocklist
// Used for access token revocation
func (rs *RedisStore) RevokeToken(ctx context.Context, token string, ttl time.Duration) error {
	key := rs.revokedTokenKey(token)

	// Store "1" with TTL matching token expiration
	err := rs.client.Set(ctx, key, "1", ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to add token to revocation list: %w", err)
	}

	return nil
}

// IsTokenRevoked checks if a token is in the revocation blocklist
func (rs *RedisStore) IsTokenRevoked(ctx context.Context, token string) (bool, error) {
	key := rs.revokedTokenKey(token)

	exists, err := rs.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check revocation list: %w", err)
	}

	return exists > 0, nil
}

// StoreClient stores a client in Redis (for demo purposes)
func (rs *RedisStore) StoreClient(ctx context.Context, client *models.Client) error {
	key := rs.clientKey(client.ID)

	data, err := json.Marshal(client)
	if err != nil {
		return fmt.Errorf("failed to marshal client: %w", err)
	}

	// No TTL for clients
	err = rs.client.Set(ctx, key, data, 0).Err()
	if err != nil {
		return fmt.Errorf("failed to store client: %w", err)
	}

	return nil
}

// GetClient retrieves a client from Redis
func (rs *RedisStore) GetClient(ctx context.Context, clientID string) (*models.Client, error) {
	key := rs.clientKey(clientID)

	data, err := rs.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, fmt.Errorf("client not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	var client models.Client
	err = json.Unmarshal(data, &client)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal client: %w", err)
	}

	return &client, nil
}

// Ping checks Redis connectivity
func (rs *RedisStore) Ping(ctx context.Context) error {
	return rs.client.Ping(ctx).Err()
}

// Helper functions for key generation
func (rs *RedisStore) authCodeKey(code string) string {
	return fmt.Sprintf("%sauth:code:%s", rs.keyPrefix, code)
}

func (rs *RedisStore) refreshTokenKey(token string) string {
	return fmt.Sprintf("%srefresh:token:%s", rs.keyPrefix, token)
}

func (rs *RedisStore) revokedTokenKey(token string) string {
	return fmt.Sprintf("%srevoked:%s", rs.keyPrefix, token)
}

func (rs *RedisStore) clientKey(clientID string) string {
	return fmt.Sprintf("%sclient:%s", rs.keyPrefix, clientID)
}
