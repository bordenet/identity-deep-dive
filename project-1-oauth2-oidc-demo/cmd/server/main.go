package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/internal/handlers"
	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/internal/session"
	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/internal/store"
	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/internal/tokens"
	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/pkg/models"
	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
)

func main() {
	log.Println("Starting OAuth2/OIDC Authorization Server...")

	// Load configuration from environment
	config := loadConfig()

	// Initialize Redis
	redisClient := initRedis(config)
	defer redisClient.Close()

	// Initialize session store
	sessionStore := session.NewRedisStore(redisClient, "identity:")

	// Initialize user store (in-memory for demo)
	userStore := store.NewInMemoryUserStore()

	// Load RSA keys
	privateKey, publicKey := loadRSAKeys(config)

	// Initialize JWT manager
	jwtManager := tokens.NewJWTManager(
		privateKey,
		publicKey,
		config.Issuer,
		15*time.Minute,  // Access token TTL
		30*24*time.Hour, // Refresh token TTL (30 days)
		15*time.Minute,  // ID token TTL
	)

	// Initialize handlers
	authorizeHandler := handlers.NewAuthorizeHandler(sessionStore)
	tokenHandler := handlers.NewTokenHandler(sessionStore, jwtManager, userStore)
	userInfoHandler := handlers.NewUserInfoHandler(jwtManager, userStore)
	discoveryHandler := handlers.NewDiscoveryHandler(config.Issuer, publicKey)
	jwksHandler := handlers.NewJWKSHandler(publicKey)

	// Setup router
	router := mux.NewRouter()

	// OAuth2/OIDC endpoints
	router.Handle("/authorize", authorizeHandler).Methods("GET")
	router.Handle("/oauth2/token", tokenHandler).Methods("POST")
	router.Handle("/userinfo", userInfoHandler).Methods("GET")
	router.Handle("/.well-known/openid-configuration", discoveryHandler).Methods("GET")
	router.Handle("/.well-known/jwks.json", jwksHandler).Methods("GET")

	// Health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}).Methods("GET")

	// Seed demo clients
	seedDemoClients(context.Background(), sessionStore)

	// Create HTTP server
	srv := &http.Server{
		Addr:         config.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Server listening on %s", config.Port)
		log.Printf("Issuer: %s", config.Issuer)
		log.Printf("Discovery endpoint: %s/.well-known/openid-configuration", config.Issuer)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped")
}

// Config holds server configuration
type Config struct {
	Port           string
	Issuer         string
	RedisAddr      string
	RedisPassword  string
	RedisDB        int
	PrivateKeyPath string
	PublicKeyPath  string
}

// loadConfig loads configuration from environment variables
func loadConfig() *Config {
	return &Config{
		Port:           getEnv("PORT", ":8080"),
		Issuer:         getEnv("ISSUER", "http://localhost:8080"),
		RedisAddr:      getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:  getEnv("REDIS_PASSWORD", ""),
		RedisDB:        0,
		PrivateKeyPath: getEnv("PRIVATE_KEY_PATH", "./keys/jwt-private.key"),
		PublicKeyPath:  getEnv("PUBLIC_KEY_PATH", "./keys/jwt-public.key"),
	}
}

// getEnv gets an environment variable with a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// initRedis initializes Redis connection
func initRedis(config *Config) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	log.Println("Connected to Redis")
	return client
}

// loadRSAKeys loads RSA private and public keys from files
func loadRSAKeys(config *Config) (*rsa.PrivateKey, *rsa.PublicKey) {
	// Load private key
	privateKeyData, err := os.ReadFile(config.PrivateKeyPath)
	if err != nil {
		log.Fatalf("Failed to read private key: %v", err)
	}

	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		log.Fatal("Failed to parse PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	// Load public key
	publicKeyData, err := os.ReadFile(config.PublicKeyPath)
	if err != nil {
		log.Fatalf("Failed to read public key: %v", err)
	}

	block, _ = pem.Decode(publicKeyData)
	if block == nil {
		log.Fatal("Failed to parse PEM block containing public key")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse public key: %v", err)
	}

	log.Println("Loaded RSA keys")
	return privateKey, publicKey
}

// seedDemoClients adds demo OAuth2 clients to Redis
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
			Name:   "Demo Mobile App",
			Type:   "public",
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
			log.Printf("Warning: Failed to seed client %s: %v", client.ID, err)
		} else {
			log.Printf("Seeded demo client: %s (%s)", client.Name, client.ID)
		}
	}
}
