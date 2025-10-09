// Package logger provides centralized structured logging for all identity-deep-dive projects.
//
// This package uses zerolog for high-performance JSON logging with:
// - Nanosecond timestamp precision
// - Structured fields for observability
// - Configurable log levels via LOG_LEVEL environment variable
// - Service name context for multi-service deployments
//
// Usage:
//
//	logger.InitLogger("my-service")
//	log.Info().Str("key", "value").Msg("Application started")
package logger

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// InitLogger initializes the global logger with service context.
//
// The log level is determined by the LOG_LEVEL environment variable:
//   - "debug" - Most verbose, includes all log levels
//   - "info"  - Default, includes info, warn, error, fatal, panic
//   - "warn"  - Includes warn, error, fatal, panic
//   - "error" - Includes error, fatal, panic
//   - "fatal" - Includes fatal, panic (exits on fatal)
//   - "panic" - Only panic (panics and exits)
//
// The service parameter is added as a "service" field to all log entries,
// enabling filtering and routing in log aggregation systems (Loki, Elastic, etc.).
//
// Example:
//
//	logger.InitLogger("oauth2-server")
//	log.Info().Str("addr", ":8080").Msg("Server starting")
//	// Output: {"level":"info","service":"oauth2-server","time":"2025-10-09T10:30:45.123456789Z","addr":":8080","message":"Server starting"}
func InitLogger(service string) {
	// Use RFC3339Nano for nanosecond precision timestamps
	zerolog.TimeFieldFormat = time.RFC3339Nano

	// Set log level from environment variable (default: info)
	logLevel := getLogLevel()
	zerolog.SetGlobalLevel(logLevel)

	// Create logger with timestamp and service context
	log.Logger = zerolog.New(os.Stdout).With().
		Timestamp().
		Str("service", service).
		Logger()

	log.Debug().
		Str("log_level", logLevel.String()).
		Msg("Logger initialized")
}

// getLogLevel parses the LOG_LEVEL environment variable.
// Returns zerolog.InfoLevel if not set or invalid.
func getLogLevel() zerolog.Level {
	levelStr := strings.ToLower(os.Getenv("LOG_LEVEL"))
	if levelStr == "" {
		return zerolog.InfoLevel // Default to info
	}

	switch levelStr {
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn", "warning":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	case "fatal":
		return zerolog.FatalLevel
	case "panic":
		return zerolog.PanicLevel
	default:
		// Invalid level, default to info
		log.Warn().
			Str("invalid_level", levelStr).
			Msg("Invalid LOG_LEVEL, defaulting to info")
		return zerolog.InfoLevel
	}
}
