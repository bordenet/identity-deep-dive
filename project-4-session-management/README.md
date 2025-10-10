# Multi-Tenant Session Management Service

> **A distributed, horizontally-scalable session management service for multi-tenant identity platforms.**

This project demonstrates how to build a session management service that can handle millions of users across multiple brands, with a focus on performance, security, and scalability.

## Features

- **Multi-Tenant Session Isolation**: Cryptographically isolated sessions per tenant.
- **Stateless JWT Validation**: Fast-path validation for high performance.
- **Redis-Backed Revocation**: Slow-path validation for immediate session revocation.
- **Token Refresh**: Long-lived sessions with refresh tokens.
- **Horizontal Scalability**: Stateless service that can be scaled horizontally.

## Quick Start

### Prerequisites
- [Go](https://go.dev) 1.21+
- [Podman](https://podman.io/) & [Podman Compose](https://github.com/containers/podman-compose)
- [Redis](https://redis.io) (via Podman)

### Build and Run

```bash
# Build the service
make build

# Run the service
make run
```

## API

### Create Session

`POST /sessions`

Creates a new session and returns a token pair.

### Validate Session

`POST /sessions/validate`

Validates an access token.

### Refresh Session

`POST /sessions/refresh`

Refreshes an access token using a refresh token.

### Revoke Session

`POST /sessions/revoke`

Revokes a session.

## Project Structure

```
project-4-session-management/
├── cmd/
│   └── server/
│       └── main.go              # Main application
├── internal/
│   ├── handlers/
│   │   ├── jwks.go              # JWKS endpoint handler
│   │   └── session.go           # Session management handlers
│   ├── session/
│   │   └── redis.go             # Redis session store
│   └── tokens/
│       ├── jwt.go               # JWT management
│       └── keymanager.go        # Multi-tenant key manager
├── pkg/
│   └── models/
│       ├── session.go           # Session and token models
│       └── tenant.go            # Multi-tenant models
├── docs/
│   └── PRD.md                   # Product Requirements Document
├── Makefile
├── README.md
├── CHANGELOG.md
└── go.mod
```

## Architecture

### Component Design

```
┌─────────────────────────────────────────────────────────────┐
│                      Application Layer                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Web App 1   │  │  Web App 2   │  │  API Service │     │
│  │  (brand-a)   │  │  (brand-b)   │  │              │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
└─────────┼──────────────────┼──────────────────┼────────────┘
          │                  │                  │
          │ POST /sessions/validate (access_token)
          │                  │                  │
          ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│              Session Management Service (Go)                │
│                                                             │
│  ┌────────────────────────────────────────────────────────┐│
│  │  HTTP Handlers                                         ││
│  │  - POST /sessions (create)                            ││
│  │  - POST /sessions/validate (validate)                 ││
│  │  - POST /sessions/refresh (refresh)                   ││
│  │  - POST /sessions/revoke (revoke)                     ││
│  │  - GET /tenants/{id}/jwks (public keys)              ││
│  │  - GET /health, /metrics                              ││
│  └────────────────────────────────────────────────────────┘│
│                           │                                 │
│  ┌────────────────────────┼────────────────────────────┐   │
│  │  Core Services         │                            │   │
│  │  ┌──────────────┐ ┌────▼──────────┐ ┌────────────┐ │   │
│  │  │ JWT Manager  │ │ Session Store │ │ Key Manager│ │   │
│  │  │ (RS256)      │ │ (Redis ops)   │ │ (per-tenant│ │   │
│  │  └──────────────┘ └───────────────┘ └────────────┘ │   │
│  └────────────────────────────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
                 ┌───────────────────┐
                 │  Redis Cluster    │
                 │  ┌─────────────┐  │
                 │  │  Sessions   │  │  Namespaced keys:
                 │  │  Refresh    │  │  - tenant:brand-a:refresh:token:{id}
                 │  │  Revoked    │  │  - tenant:brand-a:revoked:{token}
                 │  │  Keys       │  │  - tenant:brand-a:keys:private
                 │  └─────────────┘  │
                 └───────────────────┘
```

## Testing

### Run Tests

```bash
make test
```

### Debugging Session Management Flows

Use [Delve](https://github.com/go-delve/delve) or your IDE debugger to step through the session lifecycle shown in the architecture diagram.

#### Install Delve

```bash
go install github.com/go-delve/delve/cmd/dlv@latest
```

#### Critical Breakpoint Locations

Based on the multi-tenant session management architecture, set breakpoints at these key functions:

**1. Session Creation** (`POST /sessions`):
- File: `internal/handlers/session.go`
- Function: `CreateSession`
- Line: First line (request validation)
- **What to inspect**: `tenant_id`, `user_id`, session creation parameters

**2. JWT Token Generation**:
- File: `internal/tokens/jwt.go`
- Function: `GenerateToken`
- Line: Claims creation and signing
- **What to inspect**: JWT claims, tenant-specific signing key, token expiration

**3. Session Validation** (`POST /sessions/validate`):
- File: `internal/handlers/session.go`
- Function: `ValidateSession`
- Line: Token parsing and validation
- **What to inspect**: Incoming token, validation result, revocation check

**4. Revocation Check**:
- File: `internal/session/redis.go`
- Function: `IsRevoked`
- Line: Redis blocklist lookup
- **What to inspect**: Token ID, blocklist key, TTL

**5. Token Refresh** (`POST /sessions/refresh`):
- File: `internal/handlers/session.go`
- Function: `RefreshSession`
- Line: Refresh token validation
- **What to inspect**: Refresh token, new access token generation, rotation

**6. Multi-Tenant Key Resolution**:
- File: `internal/tokens/keymanager.go`
- Function: `GetPrivateKey` or `GetPublicKey`
- Line: Tenant key lookup
- **What to inspect**: `tenant_id`, cached vs. fresh key fetch

#### Example: Debug with Delve

```bash
# Start server with debugger
cd project-4-session-management
dlv debug cmd/server/main.go

# In dlv console:
(dlv) break internal/handlers/session.go:CreateSession
(dlv) break internal/handlers/session.go:ValidateSession
(dlv) break internal/tokens/jwt.go:GenerateToken
(dlv) continue

# Then send API requests with curl
```

#### Example: Debug with VS Code

Add to `.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug Session Server",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}/project-4-session-management/cmd/server",
      "env": {
        "REDIS_ADDR": "localhost:6379",
        "SERVER_PORT": "8081"
      }
    }
  ]
}
```

Set breakpoints in VS Code at the locations listed above.

## Documentation & References

### Project-Specific Documentation
- **[Product Requirements Document (PRD)](docs/PRD.md)** - Design and requirements
- **[CHANGELOG](CHANGELOG.md)** - Version history and changes

### Specifications
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)

### Best Practices
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

## Learning Outcomes

### Security Patterns Applied

1.  **Multi-Tenant Security**: Cryptographic isolation of tenants.
2.  **Defense in Depth**: Combining stateless and stateful validation.

### Technical Skills Practiced

- **Protocol Knowledge**: JWT specifications.
- **Distributed Systems**: Designing for scalability and high availability.
- **[API](https://en.wikipedia.org/wiki/API) Design**: Building a RESTful API for session management.

## Future Enhancements

- **Load Testing**: Add load tests with `k6` to validate performance at scale.
- **Observability**: Add [Prometheus](https://prometheus.io/) metrics and a [Grafana](https://grafana.com/) dashboard.

## Contributing

This is a learning/demonstration project, but feedback is welcome!

## License

MIT License - see [LICENSE](../LICENSE) for details.
