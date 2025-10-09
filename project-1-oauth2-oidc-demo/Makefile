# OAuth2/OIDC Authorization Server - Makefile

.PHONY: help build redis-start redis-stop run-server run-client clean test

help:
	@echo "OAuth2/OIDC Authorization Server - Available Commands:"
	@echo ""
	@echo "  make build            Build server and client binaries"
	@echo "  make redis-start      Start Redis server (Podman)"
	@echo "  make redis-stop       Stop Redis server"
	@echo "  make run-server       Run authorization server (uses root .env)"
	@echo "  make run-client       Run demo client (port 3000)"
	@echo "  make clean            Remove build artifacts"
	@echo "  make test             Run all tests"
	@echo ""
	@echo "NOTE: JWT keys are managed in root .secrets/ directory (see ../.env)"
	@echo "      Run '../setup-macos.sh' if keys are missing"
	@echo ""

# Build server and client binaries
build:
	@echo "Building OAuth2/OIDC server and client..."
	@mkdir -p bin
	@go build -o bin/server cmd/server/main.go
	@go build -o bin/client cmd/client/main.go
	@echo "✓ Built bin/server and bin/client"

# Start Redis server using Podman
redis-start:
	@echo "Starting Redis server..."
	@podman run -d --name oauth2-redis -p 6379:6379 redis:7-alpine
	@echo "✓ Redis running on localhost:6379"

# Stop Redis server
redis-stop:
	@echo "Stopping Redis server..."
	@podman stop oauth2-redis || true
	@podman rm oauth2-redis || true
	@echo "✓ Redis stopped"

# Run authorization server (uses environment variables from root .env)
run-server:
	@echo "Starting OAuth2/OIDC Authorization Server..."
	@if [ ! -f "../.env" ]; then \
		echo "ERROR: ../.env file not found"; \
		echo "Run '../setup-macos.sh' to create it"; \
		exit 1; \
	fi
	@echo "Loading environment from ../.env"
	@set -a && . ../.env && set +a && \
		echo "Server will listen on http://$$SERVER_HOST:$$SERVER_PORT" && \
		echo "Using JWT keys from: $$JWT_PRIVATE_KEY_PATH" && \
		if [ ! -f "../$$JWT_PRIVATE_KEY_PATH" ]; then \
			echo "ERROR: JWT keys not found at ../$$JWT_PRIVATE_KEY_PATH"; \
			echo "Run '../setup-macos.sh' to generate keys"; \
			exit 1; \
		fi && \
		cd .. && go run project-1-oauth2-oidc-demo/cmd/server/main.go

# Run demo client
run-client:
	@echo "Starting Demo Client..."
	@echo "Client will listen on http://localhost:3000"
	@echo "Visit http://localhost:3000 to start OAuth2/OIDC flow"
	@echo ""
	@go run cmd/client/main.go

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@echo "✓ Cleaned (bin/ removed)"
	@echo "NOTE: JWT keys in ../.secrets/ are preserved"

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...
