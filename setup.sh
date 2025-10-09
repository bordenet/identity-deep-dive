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

# Create docker alias for podman (for compatibility)
if ! grep -q "alias docker='podman'" ~/.zshrc 2>/dev/null && ! grep -q "alias docker='podman'" ~/.bashrc 2>/dev/null; then
    echo_info "Creating 'docker' alias for podman..."
    if [ -f ~/.zshrc ]; then
        echo "alias docker='podman'" >> ~/.zshrc
        echo_info "Added docker alias to ~/.zshrc"
    fi
    if [ -f ~/.bashrc ]; then
        echo "alias docker='podman'" >> ~/.bashrc
        echo_info "Added docker alias to ~/.bashrc"
    fi
    echo_warn "Please restart your terminal or run: source ~/.zshrc (or ~/.bashrc)"
fi

# Install docker-compose (works with podman via docker socket)
echo_info "Checking for docker-compose..."
if ! command -v docker-compose &> /dev/null; then
    echo_warn "docker-compose not found. Installing docker-compose..."
    brew install docker-compose
    echo_info "✓ docker-compose installed"
else
    echo_info "✓ docker-compose already installed ($(docker-compose --version))"
fi

# Enable Podman socket for docker-compose compatibility
echo_info "Enabling Podman socket for docker-compose compatibility..."
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

# Install ggshield pre-commit and pre-push hooks
echo_info "Installing ggshield git hooks (pre-commit and pre-push)..."
if [ -d .git ]; then
    # Install pre-commit hook
    ggshield install --mode local
    echo_info "✓ ggshield pre-commit hook installed"

    # Install pre-push hook manually (ggshield doesn't have native pre-push support)
    cat > .git/hooks/pre-push <<'EOF'
#!/bin/sh
# ggshield pre-push hook to prevent pushing secrets
echo "Running ggshield secret scan before push..."
ggshield secret scan pre-push "$@"
EOF
    chmod +x .git/hooks/pre-push
    echo_info "✓ ggshield pre-push hook installed"

    echo_warn "ggshield will now block commits AND pushes if secrets are detected"
else
    echo_warn "Not a git repository. Skipping ggshield git hooks installation"
fi

echo ""
echo_info "========================================"
echo_info "Next Steps:"
echo_info "========================================"
echo_info "1. Restart your terminal (or run: source ~/.zshrc) to enable docker alias"
echo_info "2. Review and edit .env file with your secret values"
echo_info "3. Source the .env file: source .env"
echo_info "4. Run individual project setup:"
echo_info "   cd project-1-oauth2-oidc-demo && make setup"
echo_info "   cd project-2-session-management && make setup"
echo_info "   cd project-3-identity-security-scanner && make setup"
echo_info "   cd project-3b-runtime-identity-scanner && make setup"
echo_info "5. Or run all projects with Podman Compose:"
echo_info "   docker-compose up  # (uses podman via alias)"
echo_info "   # OR directly: podman-compose up"
echo ""
echo_info "Note: Using Podman instead of Docker Desktop (lighter, no VM overhead)"
echo_info "For more information, see README.md"
echo ""
