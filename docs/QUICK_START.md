# Quick Start Guide

[← Back to README](../README.md)

## 📑 Documentation

- [README](../README.md) - Project overview and introduction
- **Quick Start** (this document) - Setup and running instructions
- [Architecture](./ARCHITECTURE.md) - System design and technology choices
- [Learning Journey](./LEARNING_JOURNEY.md) - Three-day learning chronicle
- [Resources](./RESOURCES.md) - External learning materials and references

---

This guide will help you get up and running with all four identity projects in this repository.

## Prerequisites

- [Go](https://go.dev) 1.21+
- [Podman](https://podman.io/) & [Podman Compose](https://github.com/containers/podman-compose)
- [Redis](https://redis.io) (via Podman)
- [golangci-lint](https://golangci-lint.run) (for linting)

## One-Time Setup (macOS)

```bash
# Run automated setup script (installs all dependencies)
./setup-macos.sh

# Or install manually:
brew install go redis podman podman-compose golangci-lint ggshield
```

## Building & Testing

### Build All Projects

```bash
# Build all projects in monorepo
make build-all

# Or build individual projects
cd project-1-oauth2-oidc-demo && make build
cd project-2-identity-security-scanner && make build
cd project-3-runtime-security-scanner && make build
cd project-4-session-management && make build
```

### Run Tests

```bash
# Run all tests across projects
make test-all

# Or test individual projects
cd project-1-oauth2-oidc-demo && go test ./...
cd project-2-identity-security-scanner && go test ./...
cd project-3-runtime-security-scanner && go test ./...
cd project-4-session-management && go test ./...
```

### Lint Code

```bash
# Lint all projects
make lint-all

# Or lint individual projects
cd project-1-oauth2-oidc-demo && golangci-lint run
cd project-2-identity-security-scanner && golangci-lint run
cd project-3-runtime-security-scanner && golangci-lint run
cd project-4-session-management && golangci-lint run
```

## Running Projects

### Project 1: OAuth2/OIDC Server

```bash
cd project-1-oauth2-oidc-demo

# Start Redis and server with Podman Compose
podman-compose up

# Or run locally (requires Redis running)
make run

# Server will be available at:
# - Authorization: http://localhost:8080/authorize
# - Token: http://localhost:8080/token
# - UserInfo: http://localhost:8080/userinfo
# - Discovery: http://localhost:8080/.well-known/openid-configuration
```

### Project 2: Identity Security Scanner (Static)

```bash
cd project-2-identity-security-scanner

# Scan example vulnerable config
make scan-vulnerable

# Scan example secure config
make scan-secure

# Scan custom config
./bin/scanner scan --config path/to/config.yaml

# Output in JSON format
./bin/scanner scan --config config.yaml --format json
```

### Project 3: Runtime Security Scanner

```bash
cd project-3-runtime-security-scanner

# Build the scanner
make build

# Run against a live OAuth2/OIDC server
./bin/scanner run http://localhost:8080

# Run specific test
./bin/scanner test csrf http://localhost:8080

# View all available tests
./bin/scanner list
```

### Project 4: Multi-Tenant Session Management

```bash
cd project-4-session-management

# Start Redis cluster with Podman Compose
podman-compose up -d redis

# Run session service
make run

# Run load tests (requires k6)
make load-test
```

## Development Workflow

### Pre-commit Hooks

All commits are automatically checked for:
- **Secrets scanning** (ggshield) - blocks commits with hardcoded secrets
- **Go linting** (golangci-lint) - enforces code quality standards
- **Unit tests** (go test) - ensures tests pass before commit

```bash
# Hooks are installed automatically by setup.sh
# To manually trigger checks:
git commit -m "your message"  # Runs all checks automatically
```

### Pre-push Hooks

All pushes are automatically checked for:
- **Secrets scanning** (ggshield) - prevents pushing secrets to remote

```bash
git push origin main  # Runs secret scan automatically
```

## Logging and Debugging

All projects use structured logging with [zerolog](https://github.com/rs/zerolog) for JSON-formatted logs with timestamps.

**📖 Full Documentation**: See [LOGGING.md](../LOGGING.md) for:
- Log format and configuration
- Free tier log storage options (Grafana Loki, Elastic, Better Stack, Datadog)
- Query examples (LogQL, SQL)
- Best practices for structured logging

### Quick Logging Setup

```bash
# Set log level (debug, info, warn, error)
export LOG_LEVEL=debug

# Run with logging
cd project-1-oauth2-oidc-demo
LOG_LEVEL=debug go run cmd/server/main.go

# View logs with lnav (local)
brew install lnav
go run cmd/server/main.go 2>&1 | lnav
```

### Debug Breakpoints

The code includes special log statements prefixed with `MERMAID:` that correspond to the steps in the [mermaid sequence diagrams](../project-1-oauth2-oidc-demo/docs/OIDC_Walk_Thru.md).

**Setting Breakpoints**:
1. Open the file in your IDE/debugger (e.g., VS Code, GoLand)
2. Search for `MERMAID:` in the code
3. Set a breakpoint on that line
4. Start debugging (`dlv debug` or IDE debugger)
5. Make a request to trigger the flow

**Example** (Project 1 - OAuth2 Server):
```go
// In internal/handlers/authorize.go
log.Debug().
    Str("flow_step", "MERMAID: Step 2 - GET /authorize").
    Str("client_id", authReq.ClientID).
    Str("response_type", authReq.ResponseType).
    Msg("Authorization request received")
// ☝️ Set breakpoint here to inspect authorization request
```

Each log statement includes structured fields for inspection:
- `flow_step`: Which step in the OIDC flow
- Request parameters (client_id, scope, etc.)
- User context
- Error details (if any)

---

[← Back to README](../README.md)
