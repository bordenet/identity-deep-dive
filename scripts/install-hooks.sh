#!/bin/bash
# install-hooks.sh - Install git hooks for quality checks

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

echo ""
echo_info "Installing git hooks for quality checks..."
echo ""

# Check if in git repository
if [ ! -d ".git" ]; then
    echo_warn "Not in a git repository!"
    exit 1
fi

# Install pre-commit hook
echo_info "Installing pre-commit hook..."
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/sh
# Pre-commit hook - runs comprehensive validation including:
# - Secret scanning (ggshield)
# - Go formatting (gofmt)
# - Static analysis (go vet)
# - Build validation (go build)
# - Module consistency (go mod tidy)

exec scripts/pre-commit.sh
EOF
chmod +x .git/hooks/pre-commit

# Install pre-push hook
echo_info "Installing pre-push hook..."
cat > .git/hooks/pre-push << 'EOF'
#!/bin/sh
# Pre-push hook - additional checks before pushing

echo "Running ggshield pre-push scan..."
ggshield secret scan pre-push "$@"
EOF
chmod +x .git/hooks/pre-push

echo ""
echo_info "✓ Git hooks installed successfully!"
echo ""
echo_info "Pre-commit hook will run:"
echo "  • Secret scanning (ggshield)"
echo "  • Go formatting checks"
echo "  • Static analysis (go vet)"
echo "  • Build validation"
echo "  • Module consistency checks"
echo ""
echo_info "Pre-push hook will run:"
echo "  • Secret scanning on commits being pushed"
echo ""
echo_warn "To bypass hooks (NOT RECOMMENDED):"
echo "  git commit --no-verify"
echo "  git push --no-verify"
echo ""
