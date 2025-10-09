# OAuth2/OIDC Authorization Server - Makefile

.PHONY: help generate-keys redis-start redis-stop run-server run-client clean test

help:
	@echo "OAuth2/OIDC Authorization Server - Available Commands:"
	@echo ""
	@echo "  make generate-keys    Generate RSA key pair for JWT signing"
	@echo "  make redis-start      Start Redis server (Podman)"
	@echo "  make redis-stop       Stop Redis server"
	@echo "  make run-server       Run authorization server (port 8080)"
	@echo "  make run-client       Run demo client (port 3000)"
	@echo "  make clean            Remove generated keys and temporary files"
	@echo "  make test             Run all tests"
	@echo ""

# Generate RSA keys for JWT signing (2048-bit)
generate-keys:
	@echo "Generating RSA key pair..."
	@mkdir -p keys
	@openssl genrsa -out keys/private.pem 2048
	@openssl rsa -in keys/private.pem -pubout -out keys/public.pem
	@echo "✓ Keys generated in keys/ directory"

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

# Run authorization server
run-server:
	@echo "Starting OAuth2/OIDC Authorization Server..."
	@echo "Server will listen on http://localhost:8080"
	@echo ""
	@REDIS_URL=localhost:6379 \
	 ISSUER=http://localhost:8080 \
	 PORT=:8080 \
	 PRIVATE_KEY_PATH=keys/private.pem \
	 PUBLIC_KEY_PATH=keys/public.pem \
	 go run cmd/server/main.go

# Run demo client
run-client:
	@echo "Starting Demo Client..."
	@echo "Client will listen on http://localhost:3000"
	@echo "Visit http://localhost:3000 to start OAuth2/OIDC flow"
	@echo ""
	@go run cmd/client/main.go

# Clean generated files
clean:
	@echo "Cleaning generated files..."
	@rm -rf keys/
	@echo "✓ Cleaned"

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...
