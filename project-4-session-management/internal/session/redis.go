package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bordenet/identity-deep-dive/project-4-session-management/pkg/models"
	"github.com/redis/go-redis/v9"
)

// RedisStore implements session storage using Redis
type RedisStore struct {
	client    *redis.Client
	keyPrefix string
}

// NewRedisStore creates a new Redis session store
func NewRedisStore(client *redis.Client, keyPrefix string) *RedisStore {
	return &RedisStore{
		client:    client,
		keyPrefix: keyPrefix,
	}
}

// StoreRefreshToken stores a refresh token in Redis
func (rs *RedisStore) StoreRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	key := rs.refreshTokenKey(token.TenantID, token.ID)

	// Serialize token to JSON
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal refresh token: %w", err)
	}

	// Calculate TTL
	ttl := time.Until(token.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("refresh token already expired")
	}

	// Store in Redis with TTL
	err = rs.client.Set(ctx, key, data, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	return nil
}

// GetRefreshToken retrieves a refresh token from Redis
func (rs *RedisStore) GetRefreshToken(ctx context.Context, tenantID, tokenID string) (*models.RefreshToken, error) {
	key := rs.refreshTokenKey(tenantID, tokenID)

	data, err := rs.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, models.ErrRefreshTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	var token models.RefreshToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("failed to unmarshal refresh token: %w", err)
	}

	return &token, nil
}

// UpdateRefreshTokenLastUsed updates the last used timestamp of a refresh token
func (rs *RedisStore) UpdateRefreshTokenLastUsed(ctx context.Context, tenantID, tokenID string) error {
	key := rs.refreshTokenKey(tenantID, tokenID)

	// Get current token
	data, err := rs.client.Get(ctx, key).Bytes()
	if err != nil {
		return fmt.Errorf("failed to get refresh token: %w", err)
	}

	var token models.RefreshToken
	if err := json.Unmarshal(data, &token); err != nil {
		return fmt.Errorf("failed to unmarshal refresh token: %w", err)
	}

	// Update last used timestamp
	token.LastUsed = time.Now()

	// Re-serialize
	updatedData, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal refresh token: %w", err)
	}

	// Update in Redis (keep existing TTL)
	ttl := time.Until(token.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("refresh token expired")
	}

	err = rs.client.Set(ctx, key, updatedData, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to update refresh token: %w", err)
	}

	return nil
}

// DeleteRefreshToken deletes a refresh token from Redis
func (rs *RedisStore) DeleteRefreshToken(ctx context.Context, tenantID, tokenID string) error {
	key := rs.refreshTokenKey(tenantID, tokenID)

	err := rs.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return nil
}

// RevokeToken adds a token to the revocation blocklist
func (rs *RedisStore) RevokeToken(ctx context.Context, tenantID, tokenID string, ttl time.Duration) error {
	key := rs.revokedTokenKey(tenantID, tokenID)

	// Store with TTL matching token expiration (auto-cleanup)
	err := rs.client.Set(ctx, key, "1", ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	return nil
}

// IsTokenRevoked checks if a token is in the revocation blocklist
func (rs *RedisStore) IsTokenRevoked(ctx context.Context, tenantID, tokenID string) (bool, error) {
	key := rs.revokedTokenKey(tenantID, tokenID)

	exists, err := rs.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check revocation: %w", err)
	}

	return exists > 0, nil
}

// RevokeAllUserTokens revokes all tokens for a user
func (rs *RedisStore) RevokeAllUserTokens(ctx context.Context, tenantID, userID string) (int, error) {
	// Get all refresh tokens for this user
	pattern := rs.refreshTokenKey(tenantID, "*")

	var cursor uint64
	var count int

	for {
		keys, nextCursor, err := rs.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return count, fmt.Errorf("failed to scan refresh tokens: %w", err)
		}

		for _, key := range keys {
			// Get token to check if it belongs to this user
			data, err := rs.client.Get(ctx, key).Bytes()
			if err != nil {
				continue // Skip if error (might be deleted)
			}

			var token models.RefreshToken
			if err := json.Unmarshal(data, &token); err != nil {
				continue // Skip if can't parse
			}

			if token.UserID == userID {
				// Delete refresh token
				if err := rs.client.Del(ctx, key).Err(); err != nil {
					continue // Skip if error
				}

				// Add to revocation blocklist
				ttl := time.Until(token.ExpiresAt)
				if ttl > 0 {
					revokedKey := rs.revokedTokenKey(tenantID, token.ID)
					rs.client.Set(ctx, revokedKey, "1", ttl)
				}

				count++
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return count, nil
}

// StoreKeyPair stores a tenant's RSA key pair (implements KeyStore interface)
func (rs *RedisStore) StoreKeyPair(tenantID string, privateKeyPEM, publicKeyPEM []byte) error {
	ctx := context.Background()

	privateKey := rs.privateKeyKey(tenantID)
	publicKey := rs.publicKeyKey(tenantID)

	// Store private key (no expiration - permanent until rotation)
	if err := rs.client.Set(ctx, privateKey, privateKeyPEM, 0).Err(); err != nil {
		return fmt.Errorf("failed to store private key: %w", err)
	}

	// Store public key (no expiration)
	if err := rs.client.Set(ctx, publicKey, publicKeyPEM, 0).Err(); err != nil {
		return fmt.Errorf("failed to store public key: %w", err)
	}

	return nil
}

// GetKeyPair retrieves a tenant's RSA key pair (implements KeyStore interface)
func (rs *RedisStore) GetKeyPair(tenantID string) (privateKeyPEM, publicKeyPEM []byte, err error) {
	ctx := context.Background()

	privateKey := rs.privateKeyKey(tenantID)
	publicKey := rs.publicKeyKey(tenantID)

	// Get private key
	privateKeyPEM, err = rs.client.Get(ctx, privateKey).Bytes()
	if err == redis.Nil {
		return nil, nil, models.ErrTenantNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get private key: %w", err)
	}

	// Get public key
	publicKeyPEM, err = rs.client.Get(ctx, publicKey).Bytes()
	if err == redis.Nil {
		return nil, nil, models.ErrTenantNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get public key: %w", err)
	}

	return privateKeyPEM, publicKeyPEM, nil
}

// DeleteKeyPair deletes a tenant's RSA key pair (implements KeyStore interface)
func (rs *RedisStore) DeleteKeyPair(tenantID string) error {
	ctx := context.Background()

	privateKey := rs.privateKeyKey(tenantID)
	publicKey := rs.publicKeyKey(tenantID)

	// Delete both keys
	if err := rs.client.Del(ctx, privateKey, publicKey).Err(); err != nil {
		return fmt.Errorf("failed to delete key pair: %w", err)
	}

	return nil
}

// Ping checks Redis connectivity
func (rs *RedisStore) Ping(ctx context.Context) error {
	return rs.client.Ping(ctx).Err()
}

// Key generation helpers (namespaced per tenant)
func (rs *RedisStore) refreshTokenKey(tenantID, tokenID string) string {
	return fmt.Sprintf("%stenant:%s:refresh:%s", rs.keyPrefix, tenantID, tokenID)
}

func (rs *RedisStore) revokedTokenKey(tenantID, tokenID string) string {
	return fmt.Sprintf("%stenant:%s:revoked:%s", rs.keyPrefix, tenantID, tokenID)
}

func (rs *RedisStore) privateKeyKey(tenantID string) string {
	return fmt.Sprintf("%stenant:%s:keys:private", rs.keyPrefix, tenantID)
}

func (rs *RedisStore) publicKeyKey(tenantID string) string {
	return fmt.Sprintf("%stenant:%s:keys:public", rs.keyPrefix, tenantID)
}
