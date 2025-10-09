.PHONY: build test lint clean run podman-up podman-down

# Binary output directory
BIN_DIR := bin
BINARY_NAME := session-server

# Build the server binary
build:
	@echo "Building session management server..."
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(BINARY_NAME) cmd/server/main.go
	@echo "✓ Built $(BIN_DIR)/$(BINARY_NAME)"

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...
	@echo "✓ Tests passed"

# Run linter
lint:
	@echo "Running golangci-lint..."
	golangci-lint run
	@echo "✓ Linting passed"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BIN_DIR)
	@echo "✓ Cleaned"

# Run the server (requires Redis)
run: build
	@echo "Starting session management server..."
	@echo "Prerequisites: Redis must be running (podman-compose up redis or make podman-up)"
	$(BIN_DIR)/$(BINARY_NAME)

# Start Redis with Podman
podman-up:
	@echo "Starting Redis with Podman..."
	podman-compose up -d redis
	@echo "✓ Redis started"

# Stop Podman services
podman-down:
	@echo "Stopping Podman services..."
	podman-compose down
	@echo "✓ Services stopped"

# Install dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy
	@echo "✓ Dependencies installed"
