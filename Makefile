.PHONY: build-all test-all lint-all clean-all cleanup help install-hooks

# Root Makefile for identity-deep-dive monorepo
# Runs commands across all projects

PROJECTS := project-1-oauth2-oidc-demo \
            project-2-identity-security-scanner \
            project-3-runtime-security-scanner \
            project-4-session-management

# Build all projects
build-all:
	@echo "========================================="
	@echo "Building all projects..."
	@echo "========================================="
	@for project in $(PROJECTS); do \
		echo ""; \
		echo "Building $$project..."; \
		(cd $$project && make build) || exit 1; \
	done
	@echo ""
	@echo "========================================="
	@echo "✓ All projects built successfully"
	@echo "========================================="

# Run tests for all projects
test-all:
	@echo "========================================="
	@echo "Running tests for all projects..."
	@echo "========================================="
	@for project in $(PROJECTS); do \
		echo ""; \
		echo "Testing $$project..."; \
		(cd $$project && go test ./...) || exit 1; \
	done
	@echo ""
	@echo "========================================="
	@echo "✓ All tests passed"
	@echo "========================================="

# Lint all projects
lint-all:
	@echo "========================================="
	@echo "Linting all projects..."
	@echo "========================================="
	@for project in $(PROJECTS); do \
		echo ""; \
		echo "Linting $$project..."; \
		(cd $$project && golangci-lint run) || exit 1; \
	done
	@echo ""
	@echo "========================================="
	@echo "✓ All projects passed linting"
	@echo "========================================="

# Clean all projects
clean-all:
	@echo "========================================="
	@echo "Cleaning all projects..."
	@echo "========================================="
	@for project in $(PROJECTS); do \
		echo "Cleaning $$project..."; \
		(cd $$project && make clean 2>/dev/null || rm -rf bin) || true; \
	done
	@echo "✓ All projects cleaned"

# Install dependencies for all projects
deps-all:
	@echo "========================================="
	@echo "Installing dependencies for all projects..."
	@echo "========================================="
	@for project in $(PROJECTS); do \
		echo ""; \
		echo "Installing dependencies for $$project..."; \
		(cd $$project && go mod download && go mod tidy) || exit 1; \
	done
	@echo ""
	@echo "========================================="
	@echo "✓ All dependencies installed"
	@echo "========================================="

# Clean up containers, images, and volumes
cleanup:
	@echo "========================================="
	@echo "Running cleanup script..."
	@echo "========================================="
	@./scripts/cleanup.sh

# Install git hooks for quality checks
install-hooks:
	@echo "========================================="
	@echo "Installing git hooks..."
	@echo "========================================="
	@./scripts/install-hooks.sh

# Show help
help:
	@echo "Identity Deep Dive - Monorepo Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  build-all      - Build all projects"
	@echo "  test-all       - Run tests for all projects"
	@echo "  lint-all       - Run linting for all projects"
	@echo "  clean-all      - Clean all projects (build artifacts)"
	@echo "  cleanup        - Clean up containers, images, volumes"
	@echo "  deps-all       - Install dependencies for all projects"
	@echo "  install-hooks  - Install git hooks for quality checks"
	@echo "  help           - Show this help message"
	@echo ""
	@echo "Projects:"
	@for project in $(PROJECTS); do \
		echo "  - $$project"; \
	done
