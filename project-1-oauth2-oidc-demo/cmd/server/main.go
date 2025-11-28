// Package main provides the OAuth2/OIDC authorization server.
package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bordenet/identity-deep-dive/pkg/logger"
	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/internal/handlers"
	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/internal/session"
	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/internal/store"
	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/internal/tokens"
	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/pkg/models"
	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

//nolint:funlen // Main function with server initialization
func main() {
	// Initialize structured logging.
	logger.InitLogger("oauth2-oidc-server")

	log.Info().Msg("Starting OAuth2/OIDC Authorization Server")

	// Load configuration from environment.
	config := loadConfig()

	// Initialize Redis.
	redisClient, err := initRedis(config)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize Redis")
	}

	// Initialize session store.
	sessionStore := session.NewRedisStore(redisClient, "identity:")

	// Initialize user store (in-memory for demo)
	userStore := store.NewInMemoryUserStore()

	// Load RSA keys.
	privateKey, publicKey := loadRSAKeys(config)

	// Initialize JWT manager.
	jwtManager := tokens.NewJWTManager(
		privateKey,
		publicKey,
		config.Issuer,
		15*time.Minute,  // Access token TTL
		30*24*time.Hour, // Refresh token TTL (30 days)
		15*time.Minute,  // ID token TTL
	)

	// Initialize handlers.
	authorizeHandler := handlers.NewAuthorizeHandler(sessionStore)
	tokenHandler := handlers.NewTokenHandler(sessionStore, jwtManager, userStore)
	userInfoHandler := handlers.NewUserInfoHandler(jwtManager, userStore)
	discoveryHandler := handlers.NewDiscoveryHandler(config.Issuer, publicKey)
	jwksHandler := handlers.NewJWKSHandler(publicKey)

	// Setup router.
	router := mux.NewRouter()

	// OAuth2/OIDC endpoints.
	router.Handle("/authorize", authorizeHandler).Methods("GET")
	router.Handle("/oauth2/token", tokenHandler).Methods("POST")
	router.Handle("/userinfo", userInfoHandler).Methods("GET")
	router.Handle("/.well-known/openid-configuration", discoveryHandler).Methods("GET")
	router.Handle("/.well-known/jwks.json", jwksHandler).Methods("GET")

	// Health check endpoint.
	router.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := fmt.Fprint(w, "OK"); err != nil {
			log.Error().Err(err).Msg("Failed to write health check response")
		}
	}).Methods("GET")

	// Seed demo clients.
	seedDemoClients(context.Background(), sessionStore)

	// Create HTTP server.
	srv := &http.Server{
		Addr:         config.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine.
	go func() {
		log.Info().
			Str("addr", config.Port).
			Str("issuer", config.Issuer).
			Str("discovery", config.Issuer+"/.well-known/openid-configuration").
			Msg("Server starting")

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("Server failed to start")
		}
	}()

	// Wait for interrupt signal to gracefully shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("Shutting down server")

	// Graceful shutdown with timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Server forced to shutdown")
		cancel()
		// Explicitly close Redis before exiting.
		if closeErr := redisClient.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Failed to close Redis client")
		}
		log.Error().Msg("Exiting due to shutdown error")
		os.Exit(1)
	}
	cancel()

	// Close Redis connection.
	if err := redisClient.Close(); err != nil {
		log.Warn().Err(err).Msg("Failed to close Redis client")
	}

	log.Info().Msg("Server stopped")
}

// Config holds server configuration.
type Config struct {
	Port           string
	Issuer         string
	RedisAddr      string
	RedisPassword  string
	RedisDB        int
	PrivateKeyPath string
	PublicKeyPath  string
}

// loadConfig loads configuration from environment variables.
func loadConfig() *Config {
	return &Config{
		Port:           getEnv("PORT", ":8080"),
		Issuer:         getEnv("ISSUER", "http://localhost:8080"),
		RedisAddr:      getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:  getEnv("REDIS_PASSWORD", ""),
		RedisDB:        0,
		PrivateKeyPath: getEnv("PRIVATE_KEY_PATH", "../.secrets/jwt-private.pem"),
		PublicKeyPath:  getEnv("PUBLIC_KEY_PATH", "../.secrets/jwt-public.pem"),
	}
}

// getEnv gets an environment variable with a default value.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// initRedis initializes Redis connection.
func initRedis(config *Config) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})

	// Test connection.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis at %s: %w", config.RedisAddr, err)
	}

	log.Info().Str("addr", config.RedisAddr).Msg("Connected to Redis")
	return client, nil
}

// loadRSAKeys loads RSA private and public keys from files.
func loadRSAKeys(config *Config) (*rsa.PrivateKey, *rsa.PublicKey) {
	// Load private key.
	privateKeyData, err := os.ReadFile(config.PrivateKeyPath)
	if err != nil {
		log.Fatal().Err(err).Str("path", config.PrivateKeyPath).Msg("Failed to read private key")
	}

	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		log.Fatal().Str("path", config.PrivateKeyPath).Msg("Failed to parse PEM block containing private key")
		return nil, nil // Unreachable but satisfies staticcheck
	}

	// Try PKCS#8 format first (modern format), fallback to PKCS#1 (legacy RSA format)
	var privateKey *rsa.PrivateKey
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fallback to PKCS#1 format.
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to parse private key (tried PKCS#8 and PKCS#1)")
		}
	} else {
		// PKCS#8 parsed successfully, assert to RSA key.
		var ok bool
		privateKey, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			log.Fatal().Msg("Private key is not an RSA key")
		}
	}

	// Load public key.
	publicKeyData, err := os.ReadFile(config.PublicKeyPath)
	if err != nil {
		log.Fatal().Err(err).Str("path", config.PublicKeyPath).Msg("Failed to read public key")
	}

	block, _ = pem.Decode(publicKeyData)
	if block == nil {
		log.Fatal().Str("path", config.PublicKeyPath).Msg("Failed to parse PEM block containing public key")
		return nil, nil // Unreachable but satisfies staticcheck
	}

	// Try PKIX (X.509) format first (standard), fallback to PKCS#1 (legacy RSA format)
	var publicKey *rsa.PublicKey
	parsedPubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Fallback to PKCS#1 format.
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to parse public key (tried PKIX and PKCS#1)")
		}
	} else {
		// PKIX parsed successfully, assert to RSA key.
		var ok bool
		publicKey, ok = parsedPubKey.(*rsa.PublicKey)
		if !ok {
			log.Fatal().Msg("Public key is not an RSA key")
		}
	}

	log.Info().
		Str("private_key_path", config.PrivateKeyPath).
		Str("public_key_path", config.PublicKeyPath).
		Msg("Loaded RSA keys")
	return privateKey, publicKey
}

// seedDemoClients adds demo OAuth2 clients to Redis.
func seedDemoClients(ctx context.Context, sessionStore *session.RedisStore) {
	demoClients := []*models.Client{
		{
			ID:     "web-app",
			Secret: "web-app-secret-change-in-production",
			RedirectURIs: []string{
				"http://localhost:3000/callback",
				"http://localhost:3000/auth/callback",
			},
			Name: "Demo Web Application",
			Type: "confidential",
			Scopes: []string{
				"openid",
				"profile",
				"email",
				"offline_access",
			},
			CreatedAt: time.Now(),
		},
		{
			ID:     "mobile-app",
			Secret: "", // Public client - no secret
			RedirectURIs: []string{
				"myapp://callback",
				"http://localhost:3000/mobile/callback",
			},
			Name: "Demo Mobile App",
			Type: "public",
			Scopes: []string{
				"openid",
				"profile",
				"email",
			},
			CreatedAt: time.Now(),
		},
		{
			ID:     "service-app",
			Secret: "service-app-secret-change-in-production",
			RedirectURIs: []string{
				"http://localhost:4000/callback",
			},
			Name: "Demo Service (Client Credentials)",
			Type: "confidential",
			Scopes: []string{
				"api.read",
				"api.write",
			},
			CreatedAt: time.Now(),
		},
	}

	for _, client := range demoClients {
		if err := sessionStore.StoreClient(ctx, client); err != nil {
			log.Warn().Err(err).Str("client_id", client.ID).Msg("Failed to seed client")
		} else {
			log.Info().
				Str("client_id", client.ID).
				Str("client_name", client.Name).
				Str("client_type", client.Type).
				Msg("Seeded demo client")
		}
	}
}
