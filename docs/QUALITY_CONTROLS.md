# Quality Controls & Pre-Commit Validation

## Overview

This repository now has comprehensive quality controls to catch build errors, formatting issues, and security problems **before** code is committed.

## Problem Solved

**Issue**: Pre-commit hooks only ran `ggshield` (secret scanning), missing:
- Build failures
- Go formatting issues
- Static analysis warnings
- Module consistency problems

**Result**: Broken code was being committed, causing build failures for other developers.

## Solution: Multi-Layer Validation

### 1. Pre-Commit Hook

Location: [`.git/hooks/pre-commit`](.git/hooks/pre-commit) → executes [`scripts/pre-commit.sh`](../scripts/pre-commit.sh)

**Checks performed:**

1. **Secret Scanning** (ggshield)
   - Scans staged files for hardcoded secrets
   - Blocks commit if secrets detected
   - Zero false negatives

2. **Go Formatting** (gofmt)
   - Validates all staged `.go` files are formatted
   - Shows which files need formatting
   - Suggests fix: `make fmt`

3. **Static Analysis** (go vet)
   - Runs `go vet` on modified projects
   - Catches common Go mistakes
   - Runs per-project for speed

4. **Build Validation** (go build)
   - Compiles all modified projects
   - Ensures code actually builds
   - **Critical**: Catches syntax errors, missing imports, type mismatches

5. **Module Consistency** (go mod tidy)
   - Validates `go.mod` and `go.sum` are up-to-date
   - Ensures dependencies are correctly declared
   - Prevents "module not found" errors

6. **Debug Code Detection**
   - Warns about `fmt.Println`, `console.log`, `debugger`, `FIXME`, `XXX`
   - Non-blocking (warnings only)
   - Helps catch accidental debug code

### 2. Pre-Push Hook

Location: [`.git/hooks/pre-push`](.git/hooks/pre-push)

**Checks performed:**
- Additional ggshield secret scan on commits being pushed
- Last line of defense before code reaches GitHub

## Usage

### Install Hooks

```bash
# Option 1: Run setup script (recommended for new setup)
./setup-macos.sh

# Option 2: Install hooks only
make install-hooks
# or
./scripts/install-hooks.sh
```

### Commit Workflow

```bash
# 1. Make changes
vim project-1-oauth2-oidc-demo/cmd/server/main.go

# 2. Stage changes
git add project-1-oauth2-oidc-demo/cmd/server/main.go

# 3. Commit (hooks run automatically)
git commit -m "fix: Update JWT key parsing"

# Pre-commit checks run:
# ✓ Secret scanning
# ✓ Go formatting
# ✓ Static analysis
# ✓ Build validation
# ✓ Module consistency

# 4. If checks fail, fix issues and retry
make fmt  # Fix formatting
go mod tidy  # Fix modules
git add .
git commit -m "fix: Update JWT key parsing"
```

### Bypass Hooks (NOT RECOMMENDED)

```bash
# Only use in emergencies (hotfixes, etc.)
git commit --no-verify -m "emergency hotfix"
git push --no-verify
```

## Container Cleanup

### Problem Solved

**Issue**: Podman containers, images, and volumes accumulate, consuming disk space and slowing down the machine.

**Solution**: Comprehensive cleanup script

### Cleanup Script

Location: [`scripts/cleanup.sh`](../scripts/cleanup.sh)

**What it cleans:**
- All project containers (stopped and removed)
- All project images (oauth2, session, identity, scanner)
- All project volumes (data persistence)
- All project networks (custom networks)
- Build artifacts (`bin/` directories)
- Optionally: Go build cache

### Usage

```bash
# Option 1: Via Makefile (recommended)
make cleanup

# Option 2: Direct execution
./scripts/cleanup.sh

# Interactive prompt asks:
# - Clean Go build cache? (y/N)
```

### What Gets Kept

The cleanup script preserves:
- **Base images** (golang, redis, alpine) - for faster rebuilds
- **System containers** - unrelated to this project
- **Source code** - only build artifacts removed

To remove **everything** (including base images):
```bash
podman system prune -a --volumes
```

## Makefile Targets

Updated root [Makefile](../Makefile) with new targets:

```bash
make build-all      # Build all 4 projects
make test-all       # Run all tests
make lint-all       # Run golangci-lint on all projects
make clean-all      # Remove build artifacts (bin/ directories)
make cleanup        # Remove containers, images, volumes
make deps-all       # Install/update Go dependencies
make install-hooks  # Install git hooks
make help           # Show available targets
```

## Best Practices

### Before Committing

1. **Run tests locally**
   ```bash
   make test-all
   ```

2. **Check formatting**
   ```bash
   make fmt  # or go fmt ./...
   ```

3. **Run linter**
   ```bash
   make lint-all
   ```

4. **Build all projects**
   ```bash
   make build-all
   ```

5. **Commit** (hooks will validate again)
   ```bash
   git commit -m "feat: Add new feature"
   ```

### After Development Session

1. **Clean up containers**
   ```bash
   make cleanup
   ```

2. **Check disk usage**
   ```bash
   podman system df
   ```

## Troubleshooting

### Pre-Commit Hook Fails

```bash
# Error: "go vet failed"
cd project-X && go vet ./...
# Fix reported issues, then retry commit

# Error: "Build failed in project-X"
cd project-X && go build ./...
# Fix compilation errors, then retry commit

# Error: "go.mod is not tidy"
cd project-X && go mod tidy
git add project-X/go.mod project-X/go.sum
git commit --amend
```

### Cleanup Script Issues

```bash
# Error: "podman-compose not found"
brew install podman-compose

# Containers won't stop
podman ps -a  # List all containers
podman stop <container_id>  # Stop manually
podman rm <container_id>    # Remove manually
```

## Quality Metrics

With these controls in place:

- **Zero secrets committed** (ggshield blocking)
- **Zero build failures pushed** (pre-commit validation)
- **Consistent code formatting** (gofmt enforcement)
- **Clean module dependencies** (go mod tidy validation)
- **No resource leaks** (cleanup script automation)

## Configuration Files

- [`scripts/pre-commit.sh`](../scripts/pre-commit.sh) - Main validation script
- [`scripts/pre-push.sh`](../.git/hooks/pre-push) - Push-time validation
- [`scripts/cleanup.sh`](../scripts/cleanup.sh) - Container cleanup
- [`scripts/install-hooks.sh`](../scripts/install-hooks.sh) - Hook installer
- [`.golangci.yml`](../.golangci.yml) - Linter configuration

## Future Enhancements

Potential additions:
- [ ] Test coverage thresholds (fail if coverage < 80%)
- [ ] Dependency vulnerability scanning (govulncheck)
- [ ] License compliance checks
- [ ] Commit message format validation
- [ ] Automated changelog generation
- [ ] CI/CD integration (GitHub Actions)

## See Also

- [CLAUDE.md](../CLAUDE.md) - Project overview and principles
- [README.md](../README.md) - Getting started guide
- [setup-macos.sh](../setup-macos.sh) - Initial setup script
