# CLAUDE.md - Identity Learning Projects

## Goal
Build 4 identity projects in 3 days to demonstrate rapid domain mastery for senior leadership role interview (Friday).

## Core Principles
1. **Production-quality patterns**: Error handling, observability, security, testing
2. **Document learning**: Capture "aha!" moments, explain trade-offs
3. **Multi-tenant thinking**: Design for global scale, HA requirements
4. **Security first**: Follow OWASP identity best practices

## Project Execution Order

### Priority 1: OAuth2/OIDC Server (6-8 hours)
**Stack**: Go, Redis, JWT, Docker
**Core Features**: Authorization Code Flow, PKCE, Client Credentials, Token Refresh, OIDC ID Tokens
**Security**: State parameter (CSRF), short token lifetimes (15m access, 30d refresh), scope validation

---

### Priority 2: Static Security Scanner (6-8 hours)
**Stack**: Go, Cobra CLI, YAML rules
**Scans**: Weak secrets, insecure redirect URIs, JWT issues, SAML misconfigs
**Output**: JSON/Markdown/SARIF, CI/CD integration

---

### Priority 3: Runtime Security Scanner (6-8 hours)
**Stack**: Go, HTTP client, attack simulation
**Tests**: CSRF, token replay, authorization code interception, algorithm confusion
**Output**: Attack simulation reports

---

### Priority 4: Multi-Tenant Session Management (8-10 hours)
**Stack**: Go, Redis Cluster, JWT, k6 load testing, Prometheus
**Features**: Multi-tenant isolation, stateless validation, token refresh, session revocation
**Scale**: 10K+ concurrent sessions, <10ms p99 latency

## Tech Stack
- **Go**: Fast, concurrent, single binary, strong stdlib
- **Redis**: Distributed cache, HA, TTL support
- **JWT**: Stateless validation, standard claims
- **k6**: Load testing
- **Prometheus + Grafana**: Observability

## Key Libraries
- `golang-jwt/jwt`, `go-redis/redis`, `gorilla/mux`, `spf13/cobra`, `spf13/viper`

## Resources
- RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), RFC 7519 (JWT)
- OIDC Core spec, OWASP ASVS, NIST SP 800-63B
