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

ALWAYS link critical acroyms and industry standars within markdown files to authoritative references.

- [RFC 6749 - OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636 - Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OWASP ASVS - Identity and Authentication](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SP 800-63B - Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

## Secrets Management Framework

### Setup Process
1. **Initial Setup**: Run `./setup.sh` to install all dependencies and generate keys
2. **Environment Variables**: All secrets stored in `.env` (gitignored)
3. **Secret Scanning**: ggshield blocks commits AND pushes if secrets detected

### File Structure
- **`.env.example`**: Documents all required environment variables (checked into git)
- **`.env`**: Contains actual secret values (NEVER committed, gitignored)
- **`.secrets/`**: Directory for generated keys/certificates (gitignored)

### Generated Secrets
- **JWT Keys**: RSA 2048-bit keypair for token signing
  - Private: `.secrets/jwt-private.pem`
  - Public: `.secrets/jwt-public.pem`
- **Session Secrets**: HMAC keys for session signing
- **Tenant Keys**: Per-tenant signing keys for multi-tenant isolation

### Using Secrets in Code
```bash
# Source environment variables
source .env

# Access in code via environment variables
echo $JWT_PRIVATE_KEY_PATH
```

### Security Guardrails
- **ggshield pre-commit hook**: Scans staged changes for secrets before commit
- **ggshield pre-push hook**: Scans commits before push to remote
- **`.gitignore`**: Comprehensive ignore patterns for secrets, keys, certificates
- **No hardcoded secrets**: All secrets injected via environment variables

### Adding New Secrets
1. Document in `.env.example` with placeholder value
2. Add actual value to `.env`
3. Update code to read from environment variable
4. Test with `git commit` to ensure ggshield doesn't flag it
