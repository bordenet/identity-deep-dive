.PHONY: build run test clean install scan-vulnerable scan-secure

# Build the scanner
build:
	@echo "Building identity-scanner..."
	@go build -o bin/identity-scanner ./cmd/scanner

# Install dependencies
install:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@go clean

# Scan vulnerable example config
scan-vulnerable: build
	@echo "Scanning vulnerable configuration..."
	@./bin/identity-scanner scan examples/vulnerable/

# Scan secure example config
scan-secure: build
	@echo "Scanning secure configuration..."
	@./bin/identity-scanner scan examples/secure/

# Scan with JSON output
scan-json: build
	@echo "Scanning with JSON output..."
	@./bin/identity-scanner scan examples/vulnerable/ --format json

# Install scanner globally
install-global: build
	@echo "Installing identity-scanner to /usr/local/bin..."
	@sudo cp bin/identity-scanner /usr/local/bin/
	@echo "Done! Run 'identity-scanner --help' to get started"

# Development: watch and rebuild
dev:
	@echo "Starting development mode..."
	@which air > /dev/null || go install github.com/cosmtrek/air@latest
	@air

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Lint code
lint:
	@echo "Linting code..."
	@which golangci-lint > /dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@golangci-lint run

# Run all checks
check: fmt lint test
	@echo "All checks passed!"

# Show help
help:
	@echo "Identity Security Scanner - Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build              Build the scanner binary"
	@echo "  make install            Install Go dependencies"
	@echo "  make test               Run tests"
	@echo "  make scan-vulnerable    Scan example vulnerable config"
	@echo "  make scan-secure        Scan example secure config"
	@echo "  make scan-json          Scan with JSON output"
	@echo "  make install-global     Install scanner system-wide"
	@echo "  make clean              Clean build artifacts"
	@echo "  make fmt                Format code"
	@echo "  make lint               Lint code"
	@echo "  make check              Run all checks (fmt, lint, test)"
	@echo "  make help               Show this help message"
