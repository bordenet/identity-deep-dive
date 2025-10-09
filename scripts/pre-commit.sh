#!/bin/bash
# pre-commit.sh - Comprehensive pre-commit validation
# This script runs before each commit to ensure code quality

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo_info() { echo -e "${GREEN}✓${NC} $1"; }
echo_error() { echo -e "${RED}✗${NC} $1"; }
echo_warn() { echo -e "${YELLOW}⚠${NC} $1"; }

echo ""
echo "Running pre-commit checks..."
echo ""

# Track if any check failed
FAILED=0

# 1. Secret scanning with ggshield (critical security check)
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. Scanning for secrets (ggshield)..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if ! ggshield secret scan pre-commit; then
    echo_error "Secret scan failed - commit blocked!"
    FAILED=1
fi
echo ""

# 2. Check staged files for common issues
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. Validating staged files..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Get list of staged Go files
STAGED_GO_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.go$' || true)

if [ -z "$STAGED_GO_FILES" ]; then
    echo_info "No Go files staged, skipping Go checks"
else
    # 3. Go formatting check
    echo ""
    echo "3. Checking Go formatting (gofmt)..."
    UNFORMATTED=$(echo "$STAGED_GO_FILES" | xargs gofmt -l 2>/dev/null || true)
    if [ -n "$UNFORMATTED" ]; then
        echo_error "The following files need formatting:"
        echo "$UNFORMATTED"
        echo ""
        echo "Run: make fmt  (or 'gofmt -w' on the files above)"
        FAILED=1
    else
        echo_info "All Go files properly formatted"
    fi

    # 4. Go vet check
    echo ""
    echo "4. Running go vet..."
    for project in project-1-oauth2-oidc-demo project-2-identity-security-scanner \
                   project-3-runtime-security-scanner project-4-session-management; do
        if echo "$STAGED_GO_FILES" | grep -q "^$project/"; then
            echo "  Checking $project..."
            if ! (cd "$project" && go vet ./... 2>&1); then
                echo_error "go vet failed in $project"
                FAILED=1
            fi
        fi
    done
    echo_info "go vet checks passed"

    # 5. Build check for modified projects
    echo ""
    echo "5. Building modified projects..."
    PROJECTS_TO_BUILD=""
    for project in project-1-oauth2-oidc-demo project-2-identity-security-scanner \
                   project-3-runtime-security-scanner project-4-session-management; do
        if echo "$STAGED_GO_FILES" | grep -q "^$project/"; then
            PROJECTS_TO_BUILD="$PROJECTS_TO_BUILD $project"
        fi
    done

    if [ -n "$PROJECTS_TO_BUILD" ]; then
        for project in $PROJECTS_TO_BUILD; do
            echo "  Building $project..."
            if ! (cd "$project" && go build ./... 2>&1); then
                echo_error "Build failed in $project"
                FAILED=1
            else
                echo_info "$project builds successfully"
            fi
        done
    else
        echo_info "No projects need building"
    fi

    # 6. Go mod tidy check
    echo ""
    echo "6. Checking go.mod consistency..."
    for project in project-1-oauth2-oidc-demo project-2-identity-security-scanner \
                   project-3-runtime-security-scanner project-4-session-management; do
        if echo "$STAGED_GO_FILES" | grep -q "^$project/" || \
           git diff --cached --name-only --diff-filter=ACM | grep -q "^$project/go.mod"; then
            echo "  Checking $project/go.mod..."
            (cd "$project" && cp go.mod go.mod.backup && cp go.sum go.sum.backup 2>/dev/null || true)
            (cd "$project" && go mod tidy 2>/dev/null)
            if ! (cd "$project" && diff go.mod go.mod.backup >/dev/null 2>&1); then
                echo_error "$project/go.mod is not tidy"
                echo "Run: cd $project && go mod tidy"
                (cd "$project" && mv go.mod.backup go.mod && mv go.sum.backup go.sum 2>/dev/null || true)
                FAILED=1
            else
                echo_info "$project/go.mod is tidy"
                (cd "$project" && rm -f go.mod.backup go.sum.backup)
            fi
        fi
    done
fi

# 7. Check for debugging/TODO markers in staged code
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "7. Checking for debugging code..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM || true)
DEBUG_MARKERS=$(echo "$STAGED_FILES" | xargs grep -n -E "(fmt\.Println|console\.log|debugger|FIXME|XXX)" 2>/dev/null || true)
if [ -n "$DEBUG_MARKERS" ]; then
    echo_warn "Found potential debugging code:"
    echo "$DEBUG_MARKERS"
    echo ""
    echo "These may be intentional. Review before committing."
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ $FAILED -eq 0 ]; then
    echo_info "All pre-commit checks passed!"
    echo ""
    exit 0
else
    echo ""
    echo_error "Pre-commit checks failed!"
    echo ""
    echo "Fix the issues above and try again."
    echo "To bypass these checks (NOT RECOMMENDED):"
    echo "  git commit --no-verify"
    echo ""
    exit 1
fi
