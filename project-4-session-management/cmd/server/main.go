package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bordenet/identity-deep-dive/project-4-session-management/internal/handlers"
	"github.com/bordenet/identity-deep-dive/project-4-session-management/internal/logger"
	"github.com/bordenet/identity-deep-dive/project-4-session-management/internal/session"
	"github.com/bordenet/identity-deep-dive/project-4-session-management/internal/tokens"
	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

func main() {
	// Initialize structured logging
	logger.InitLogger("session-management-server")

	log.Info().Msg("Starting Session Management Server")

	// Load configuration from environment
	config := loadConfig()

	// Initialize Redis
	redisClient := initRedis(config)
	defer func() {
		if err := redisClient.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close Redis client")
		}
	}()

	// Initialize session store
	sessionStore := session.NewRedisStore(redisClient, "identity:")

	// Initialize key manager
	keyManager := tokens.NewTenantKeyManager(sessionStore)

	// Initialize JWT manager
	jwtManager := tokens.NewJWTManager(
		config.Issuer,
		15*time.Minute,  // Access token TTL
		30*24*time.Hour, // Refresh token TTL (30 days)
		keyManager,
	)

	// Initialize handlers
	sessionHandler := handlers.NewSessionHandler(jwtManager, sessionStore)
	jwksHandler := handlers.NewJWKSHandler(keyManager)

	// Setup router
	router := mux.NewRouter()

	// Session endpoints
	router.HandleFunc("/sessions", sessionHandler.CreateSession).Methods("POST")
	router.HandleFunc("/sessions/validate", sessionHandler.ValidateSession).Methods("POST")
	router.HandleFunc("/sessions/refresh", sessionHandler.RefreshSession).Methods("POST")
	router.HandleFunc("/sessions/revoke", sessionHandler.RevokeSession).Methods("POST")
	router.HandleFunc("/sessions/revoke-all", sessionHandler.RevokeAllSessions).Methods("POST")

	// JWKS endpoint
	router.HandleFunc("/tenants/{tenant_id}/jwks", jwksHandler.GetJWKS).Methods("GET")

	// Health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "OK")
	}).Methods("GET")

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
		log.Info().
			Str("addr", config.Port).
			Str("issuer", config.Issuer).
			Msg("Server starting")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Server failed to start")
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("Shutting down server")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	log.Info().Msg("Server stopped")
}

// Config holds server configuration
type Config struct {
	Port          string
	Issuer        string
	RedisAddr     string
	RedisPassword string
	RedisDB       int
}

// loadConfig loads configuration from environment variables
func loadConfig() *Config {
	return &Config{
		Port:          getEnv("PORT", ":8081"),
		Issuer:        getEnv("ISSUER", "http://localhost:8081"),
		RedisAddr:     getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       0,
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
		log.Fatal().Err(err).Str("addr", config.RedisAddr).Msg("Failed to connect to Redis")
	}

	log.Info().Str("addr", config.RedisAddr).Msg("Connected to Redis")
	return client
}
