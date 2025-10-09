#!/bin/bash
# cleanup.sh - Clean up all containers, images, and build artifacts

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

echo_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

echo ""
echo_info "========================================"
echo_info "Identity Deep Dive - Cleanup Script"
echo_info "========================================"
echo ""

# Check if running from correct directory
if [ ! -f "CLAUDE.md" ]; then
    echo_error "Must run from repository root directory"
    exit 1
fi

# Stop and remove all compose stacks
echo_step "Stopping and removing compose stacks..."
for project in project-1-oauth2-oidc-demo project-4-session-management; do
    if [ -f "$project/compose.yaml" ]; then
        echo_info "Stopping $project..."
        (cd "$project" && podman-compose down 2>/dev/null) || true
    fi
done

# Stop all running containers with our project names
echo_step "Stopping all identity-deep-dive containers..."
podman ps -a --format "{{.Names}}" | grep -E "(oauth2|session|identity|scanner)" | while read container; do
    echo_info "Stopping and removing container: $container"
    podman stop "$container" 2>/dev/null || true
    podman rm "$container" 2>/dev/null || true
done

# Remove all project images
echo_step "Removing all identity-deep-dive images..."
podman images --format "{{.Repository}}:{{.Tag}}" | grep -E "(oauth2|session|identity|scanner|project-)" | while read image; do
    echo_info "Removing image: $image"
    podman rmi "$image" 2>/dev/null || true
done

# Remove dangling images
echo_step "Removing dangling images..."
podman image prune -f 2>/dev/null || true

# Remove volumes
echo_step "Removing volumes..."
podman volume ls --format "{{.Name}}" | grep -E "(oauth2|session|identity|project-)" | while read volume; do
    echo_info "Removing volume: $volume"
    podman volume rm "$volume" 2>/dev/null || true
done

# Remove networks
echo_step "Removing custom networks..."
podman network ls --format "{{.Name}}" | grep -E "(oauth2|session|identity|project-)" | while read network; do
    echo_info "Removing network: $network"
    podman network rm "$network" 2>/dev/null || true
done

# Clean build artifacts
echo_step "Cleaning build artifacts..."
make clean-all 2>/dev/null || true

# Clean Go cache (optional - ask user)
echo ""
read -p "Clean Go build cache? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo_info "Cleaning Go build cache..."
    go clean -cache -modcache -testcache 2>/dev/null || true
fi

echo ""
echo_info "========================================"
echo_info "Cleanup Summary"
echo_info "========================================"
echo ""

# Show what's left
echo_info "Remaining containers:"
podman ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" | head -10

echo ""
echo_info "Remaining images (project-related):"
podman images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" | grep -E "(oauth2|session|identity|scanner|project-|golang|redis|alpine)" | head -10 || echo "None"

echo ""
echo_info "Remaining volumes:"
podman volume ls --format "table {{.Name}}\t{{.Driver}}" | head -10

echo ""
echo_info "Disk usage:"
podman system df

echo ""
echo_info "✓ Cleanup complete!"
echo ""
echo_warn "Note: Base images (golang, redis, alpine) are kept for faster rebuilds"
echo_warn "Run 'podman system prune -a --volumes' to remove ALL images and volumes"
echo ""
