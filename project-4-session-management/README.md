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
