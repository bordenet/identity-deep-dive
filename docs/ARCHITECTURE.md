# Architecture & Design

[← Back to README](../README.md)

## Documentation

- [README](../README.md) - Project overview and introduction
- [Quick Start](./QUICK_START.md) - Setup and running instructions
- **Architecture** (this document) - System design and technology choices
- [Learning Journey](./LEARNING_JOURNEY.md) - Three-day learning chronicle
- [Resources](./RESOURCES.md) - External learning materials and references

---

This document covers the architecture, technology choices, and design patterns used across all four identity projects.

## Architecture Highlights

### OAuth2/OIDC Server

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────┐
│   Client    │─────▶│  Authorization   │─────▶│    Redis    │
│             │      │     Server       │      │   (tokens)  │
│             │◀─────│  (Go + JWT)      │◀─────│             │
└─────────────┘      └──────────────────┘      └─────────────┘
   OAuth2 flows           Token mgmt          Distributed store
```

**Design Principles**:
- Stateless token validation with [JWT](https://datatracker.ietf.org/doc/html/rfc7519)
- [Redis](https://redis.io)-backed session storage for authorization codes and refresh tokens
- Horizontal scalability through shared Redis cluster
- [PKCE](https://datatracker.ietf.org/doc/html/rfc7636) enforcement for public clients

### Session Management

```
┌──────────────┐      ┌──────────────────┐      ┌──────────────┐
│  API Request │─────▶│  Session Service │─────▶│ Redis Cluster│
│  (JWT token) │      │  (Go stateless)  │      │ (revocation) │
│              │◀─────│  Fast validation │◀─────│              │
└──────────────┘      └──────────────────┘      └──────────────┘
   Multi-tenant          Horizontal scale      Global consistency
```

**Design Principles**:
- Hybrid validation: Fast path ([JWT](https://datatracker.ietf.org/doc/html/rfc7519)) + Slow path ([Redis](https://redis.io) blocklist)
- Multi-tenant isolation through separate signing keys
- Stateless validation enables horizontal scaling
- Revocation support through distributed blocklist

## Technology Choices

### Core Technologies

- **[Go](https://go.dev)**: Fast, concurrent, single-binary deployment
  - Standard library for cryptography and HTTP
  - Good performance for I/O-bound workloads
  - Simple deployment model (single binary)
  - Built-in concurrency primitives

- **[Redis](https://redis.io)**: Distributed cache for tokens/sessions - [HA](https://en.wikipedia.org/wiki/High_availability), global replication
  - Sub-millisecond latency for session lookups
  - Built-in TTL support for token expiration
  - Cluster mode for horizontal scaling
  - Persistence options for durability

- **[JWT](https://datatracker.ietf.org/doc/html/rfc7519)**: Industry standard, stateless validation, flexible claims
  - Stateless validation reduces database load
  - Standard claims for interoperability
  - Cryptographic signatures prevent tampering
  - Supports both symmetric (HS256) and asymmetric (RS256) algorithms

- **[Podman](https://podman.io/)**: Reproducible environments, easy deployment
  - Consistent development and production environments
  - Easy dependency management (Redis, etc.)
  - Container orchestration ready (Kubernetes, ECS)

- **[k6](https://k6.io)**: Modern load testing, [API](https://en.wikipedia.org/wiki/API)-focused, cloud-native
  - JavaScript-based test scripting
  - Real-time metrics and thresholds
  - Cloud integration for distributed load testing

### Key Libraries

| Library | Purpose | Why This Choice |
|---------|---------|-----------------|
| [golang-jwt/jwt](https://github.com/golang-jwt/jwt) | JWT token generation and validation | Most popular Go JWT library, actively maintained |
| [go-redis/redis](https://github.com/redis/go-redis) | Redis client | Official Redis client for Go, cluster support |
| [gorilla/mux](https://github.com/gorilla/mux) | HTTP routing | Flexible routing with path variables and middleware |
| [spf13/cobra](https://github.com/spf13/cobra) | CLI framework | Industry standard for Go CLI applications |
| [spf13/viper](https://github.com/spf13/viper) | Configuration management | Environment variables, config files, defaults |
| [rs/zerolog](https://github.com/rs/zerolog) | Structured logging | Zero-allocation JSON logger, high performance |

## Real-World Applications

### Multi-Brand Identity Platforms

**Challenge**: Unified identity across multiple brands in a portfolio

**Solution**: Multi-tenant session management with brand-specific signing keys

**Pattern**: [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749)/[OIDC](https://openid.net/specs/openid-connect-core-1_0.html) for consumer apps, [SAML](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html) for [B2B](https://en.wikipedia.org/wiki/Business-to-business) partners

**Implementation Details**:
- Separate RSA key pairs per tenant for cryptographic isolation
- Shared infrastructure with tenant-scoped session storage
- JWKS endpoint exposes public keys per tenant
- Tenant context propagated through all layers

### Enterprise Security

**Challenge**: Audit identity configurations across 100+ microservices

**Solution**: Automated security scanning in [CI/CD](https://en.wikipedia.org/wiki/CI/CD) pipelines

**Pattern**: [Shift-left security](https://www.devsecops.org/blog/2016/5/20/-security), fail builds on critical findings

**Implementation Details**:
- Static analysis scanner parses YAML/JSON configs
- 12 vulnerability detectors with OWASP/RFC references
- Severity-based thresholds (block on critical, warn on medium)
- JSON output for integration with security dashboards

### Global Scale

**Challenge**: Identity for hundreds of millions of users across regions

**Solution**: Stateless [JWT](https://datatracker.ietf.org/doc/html/rfc7519) validation, [Redis](https://redis.io) for global revocation

**Pattern**: Fast path ([JWT](https://datatracker.ietf.org/doc/html/rfc7519)), slow path ([Redis](https://redis.io)), observable metrics

**Implementation Details**:
- JWT validation happens locally (no network call)
- Redis blocklist checked only on revocation scenarios
- Multi-region Redis replication for global consistency
- Observability hooks for latency monitoring

## Metrics & Results

### Project Metrics

| Project | Key Features |
|---------|--------------|
| **OAuth2/OIDC Server** | 4 flows implemented, OIDC layer |
| **Security Scanner (Static)** | 12 detectors, <5ms scan time |
| **Security Scanner (Runtime)** | CSRF testing, OIDC discovery |
| **Session Management** | Multi-tenant isolation, hybrid validation |

### Technical Characteristics

- **Language**: Go
- **Security**: Zero hardcoded secrets, pre-commit scanning
- **Performance**:
  - OAuth2 Server: All flows functional
  - Security Scanner: <5ms scan time
- **Documentation**:
  - 4 READMEs
  - 3 PRDs (800+ lines each)
  - 3 CHANGELOGs with version history
  - 2 deep-dives (OIDC, PKCE)
- **Security Features**: Zero hardcoded secrets, secret redaction, remediation guidance

## Design Trade-offs

### Stateless vs Stateful Token Validation

**Stateless (JWT)**:
- ✅ Fast validation (no database lookup)
- ✅ Horizontal scalability
- ✅ Reduced database load
- ❌ Cannot revoke tokens before expiration
- ❌ Larger token size (includes claims)

**Stateful (Redis/Database)**:
- ✅ Can revoke tokens immediately
- ✅ Smaller token size (just session ID)
- ✅ Can update session data without reissue
- ❌ Database lookup on every request
- ❌ Database becomes scaling bottleneck

**Hybrid Approach (Used in Project 4)**:
- JWT for validation (fast path)
- Redis blocklist for revocation (slow path)
- Best of both worlds: fast + revocable

### Multi-Tenant Isolation Strategies

**1. Separate Databases per Tenant**:
- ✅ Complete data isolation
- ✅ Per-tenant backups and scaling
- ❌ Complex to manage at scale
- ❌ Resource inefficient

**2. Shared Database with Tenant Column**:
- ✅ Resource efficient
- ✅ Easy to manage
- ❌ Potential for data leakage bugs
- ❌ Performance impact from WHERE clauses

**3. Cryptographic Isolation (Used in Project 4)**:
- ✅ Separate signing keys per tenant
- ✅ Shared infrastructure
- ✅ Impossible to forge cross-tenant tokens
- ❌ Key management complexity

---

[← Back to README](../README.md)
