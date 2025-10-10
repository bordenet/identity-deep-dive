#!/bin/bash

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo_error "This script is designed for macOS/Darwin environments only"
    exit 1
fi

echo_info "Identity Deep Dive - macOS Setup Script"
echo_info "========================================"
echo ""

# Check for Homebrew
echo_info "Checking for Homebrew..."
if ! command -v brew &> /dev/null; then
    echo_warn "Homebrew not found. Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
else
    echo_info "✓ Homebrew already installed"
fi

# Update Homebrew
echo_info "Updating Homebrew..."
brew update

# Install ggshield FIRST for secret scanning (critical security tool)
echo_info "Checking for ggshield..."
if ! command -v ggshield &> /dev/null; then
    echo_warn "ggshield not found. Installing ggshield..."
    brew install gitguardian/tap/ggshield
else
    echo_info "✓ ggshield already installed ($(ggshield --version))"
fi

# Install Go
echo_info "Checking for Go..."
if ! command -v go &> /dev/null; then
    echo_warn "Go not found. Installing Go..."
    brew install go
else
    echo_info "✓ Go already installed ($(go version))"
fi

# Install Podman (Docker alternative, no VM required)
echo_info "Checking for Podman..."
if ! command -v podman &> /dev/null; then
    echo_warn "Podman not found. Installing Podman..."
    brew install podman

    # Initialize Podman machine
    echo_info "Initializing Podman machine..."
    podman machine init
    echo_info "Starting Podman machine..."
    podman machine start

    echo_info "✓ Podman installed and machine started"
else
    echo_info "✓ Podman already installed ($(podman --version))"

    # Check if Podman machine is running
    if ! podman machine list | grep -q "Currently running"; then
        echo_warn "Podman machine not running. Starting..."
        podman machine start || echo_warn "Podman machine may already be starting"
    fi
fi

# Podman is used directly, no docker alias needed.

# Install podman-compose (native podman compose tool)
echo_info "Checking for podman-compose..."
if ! command -v podman-compose &> /dev/null; then
    echo_warn "podman-compose not found. Installing podman-compose..."
    brew install podman-compose
    echo_info "✓ podman-compose installed"
else
    echo_info "✓ podman-compose already installed ($(podman-compose --version))"
fi

# Ensure Podman socket is enabled for podman-compose
echo_info "Ensuring Podman socket is enabled for podman-compose..."
podman machine ssh sudo systemctl enable --now podman.socket 2>/dev/null || true

# Install Redis
echo_info "Checking for Redis..."
if ! command -v redis-server &> /dev/null; then
    echo_warn "Redis not found. Installing Redis..."
    brew install redis
else
    echo_info "✓ Redis already installed ($(redis-server --version))"
fi

# Install k6 for load testing
echo_info "Checking for k6..."
if ! command -v k6 &> /dev/null; then
    echo_warn "k6 not found. Installing k6..."
    brew install k6
else
    echo_info "✓ k6 already installed ($(k6 version))"
fi

# Install jq for JSON processing
echo_info "Checking for jq..."
if ! command -v jq &> /dev/null; then
    echo_warn "jq not found. Installing jq..."
    brew install jq
else
    echo_info "✓ jq already installed ($(jq --version))"
fi

# Install yq for YAML processing
echo_info "Checking for yq..."
if ! command -v yq &> /dev/null; then
    echo_warn "yq not found. Installing yq..."
    brew install yq
else
    echo_info "✓ yq already installed ($(yq --version))"
fi

# Install OpenSSL (for generating keys/certificates)
echo_info "Checking for OpenSSL..."
if ! command -v openssl &> /dev/null; then
    echo_warn "OpenSSL not found. Installing OpenSSL..."
    brew install openssl
else
    echo_info "✓ OpenSSL already installed ($(openssl version))"
fi

# Install golangci-lint for Go linting
echo_info "Checking for golangci-lint..."
if ! command -v golangci-lint &> /dev/null; then
    echo_warn "golangci-lint not found. Installing golangci-lint..."
    brew install golangci-lint
else
    echo_info "✓ golangci-lint already installed ($(golangci-lint --version))"
fi

# Install pre-commit framework (optional but recommended)
echo_info "Checking for pre-commit..."
if ! command -v pre-commit &> /dev/null; then
    echo_warn "pre-commit not found. Installing pre-commit..."
    brew install pre-commit
else
    echo_info "✓ pre-commit already installed ($(pre-commit --version))"
fi

# Install Make (should be present, but check)
echo_info "Checking for Make..."
if ! command -v make &> /dev/null; then
    echo_error "Make not found. Please install Xcode Command Line Tools: xcode-select --install"
    exit 1
else
    echo_info "✓ Make already installed ($(make --version | head -n 1))"
fi

echo ""
echo_info "========================================"
echo_info "Dependency Installation Complete!"
echo_info "========================================"
echo ""

# Check for .env file
if [ ! -f .env ]; then
    echo_warn ".env file not found"
    echo_info "Creating .env from .env.example..."
    if [ -f .env.example ]; then
        cp .env.example .env
        echo_info "✓ Created .env file"
        echo_warn "Please edit .env and set your secret values"
    else
        echo_error ".env.example not found. Cannot create .env file"
    fi
else
    echo_info "✓ .env file already exists"
fi

# Generate JWT keys if they don't exist
echo_info "Checking for JWT signing keys..."
if [ ! -f .env ]; then
    echo_error ".env file not found. Cannot check for JWT keys"
else
    source .env

    if [ -z "$JWT_PRIVATE_KEY_PATH" ] || [ ! -f "$JWT_PRIVATE_KEY_PATH" ]; then
        echo_warn "JWT keys not found. Generating RSA keypair..."
        mkdir -p .secrets
        openssl genrsa -out .secrets/jwt-private.pem 2048
        openssl rsa -in .secrets/jwt-private.pem -pubout -out .secrets/jwt-public.pem
        echo_info "✓ Generated JWT RSA keypair"
        echo_info "  Private key: .secrets/jwt-private.pem"
        echo_info "  Public key:  .secrets/jwt-public.pem"
        echo_warn "Please update .env with the correct paths if needed"
    else
        echo_info "✓ JWT keys already exist"
    fi
fi

# Install comprehensive git hooks (secrets, formatting, build validation)
echo_info "Installing comprehensive git hooks..."
if [ -d .git ]; then
    ./scripts/install-hooks.sh
    echo_info "✓ Comprehensive git hooks installed (secrets, formatting, build validation)"
    echo_warn "Pre-commit checks will validate code quality before each commit"
else
    echo_warn "Not a git repository. Skipping git hooks installation"
fi

echo_info "Ensuring the build is healthy..."
make build-all

echo_info "Running all tests..."
make test-all

echo_info "Linting project code..."
make lint-all

echo ""
echo_info "========================================"
echo_info "Next Steps:"
echo_info "========================================"
echo_info "1. Review and edit .env file (if needed)"
echo_info ""
echo_info "2. Build all projects:"
echo_info "   make build-all"
echo_info ""
echo_info "3. Run individual projects:"
echo_info ""
echo_info "   Project 1 - OAuth2/OIDC Server:"
echo_info "     cd project-1-oauth2-oidc-demo"
echo_info "     podman-compose up     # Start Redis + server"
echo_info "     # Note: JWT keys are in root .secrets/ (auto-generated by setup)"
echo_info ""
echo_info "   Project 2 - Security Scanner:"
echo_info "     cd project-2-identity-security-scanner"
echo_info "     make scan-vulnerable  # Scan example vulnerable config"
echo_info "     make scan-secure      # Scan example secure config"
echo_info ""
echo_info "   Project 3 - Runtime Scanner:"
echo_info "     # IMPORTANT: This scanner tests LIVE OAuth2/OIDC servers"
echo_info "     # You MUST start Project 1 server first, or it will fail with 'connection refused'"
echo_info "     # Step 1: Start Project 1 server (see above)"
echo_info "     # Step 2: Then run the scanner:"
echo_info "     cd project-3-runtime-security-scanner"
echo_info "     make run TARGET=http://localhost:8080"
echo_info ""
echo_info "   Project 4 - Session Management:"
echo_info "     cd project-4-session-management"
echo_info "     make podman-up        # Start Redis"
echo_info "     make run              # Run server"
echo_info ""
echo_info "For detailed documentation, see README.md or individual project READMEs"
echo ""
