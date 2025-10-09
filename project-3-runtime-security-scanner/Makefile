.PHONY: build test lint clean run

# Binary output directory
BIN_DIR := bin
BINARY_NAME := scanner

# Build the scanner binary
build:
	@echo "Building scanner..."
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(BINARY_NAME) cmd/scanner/main.go
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

# Run the scanner (requires target issuer URL as argument)
run: build
	@echo "Usage: make run TARGET=http://localhost:8080"
	@if [ -z "$(TARGET)" ]; then \
		echo "Error: TARGET not set. Example: make run TARGET=http://localhost:8080"; \
		exit 1; \
	fi
	$(BIN_DIR)/$(BINARY_NAME) run $(TARGET)

# Install dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy
	@echo "✓ Dependencies installed"
