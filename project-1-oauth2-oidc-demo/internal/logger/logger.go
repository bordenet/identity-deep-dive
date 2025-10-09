package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// InitLogger initializes the global logger with structured JSON logging
func InitLogger(service string) {
	// Configure zerolog for structured JSON output
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.TimestampFieldName = "timestamp"
	zerolog.LevelFieldName = "level"
	zerolog.MessageFieldName = "message"

	// Set log level from environment (defaults to Info)
	logLevel := os.Getenv("LOG_LEVEL")
	switch logLevel {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Create logger with service context
	log.Logger = zerolog.New(os.Stdout).With().
		Timestamp().
		Str("service", service).
		Logger()
}

// NewRequestLogger creates a logger with request context
func NewRequestLogger(requestID, method, path string) zerolog.Logger {
	return log.With().
		Str("request_id", requestID).
		Str("http_method", method).
		Str("http_path", path).
		Logger()
}
