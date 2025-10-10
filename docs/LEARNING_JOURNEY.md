# Learning Journey

[← Back to README](../README.md)

## Documentation

- [README](../README.md) - Project overview and introduction
- [Quick Start](./QUICK_START.md) - Setup and running instructions
- [Architecture](./ARCHITECTURE.md) - System design and technology choices
- **Learning Journey** (this document) - Three-day learning chronicle
- [Resources](./RESOURCES.md) - External learning materials and references

---

This document chronicles the three-day learning journey through identity protocols, security patterns, and distributed systems that support identity implementations.

## OAuth2/OIDC Fundamentals

Started by implementing [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749) authorization server from [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) spec:

### Authorization Code Flow & JWT Tokens

**What I Built**:
- Authorization endpoint (`/authorize`)
- Token endpoint (`/token`)
- [JWT](https://datatracker.ietf.org/doc/html/rfc7519) token generation with RSA signing
- Authorization code storage in [Redis](https://redis.io)

**Key Learnings**:
- Authorization codes are single-use, short-lived (5 minutes)
- State parameter is critical for [CSRF](https://owasp.org/www-community/attacks/csrf) protection
- Access tokens should be short-lived (15 minutes)
- Refresh tokens enable long-lived sessions (30 days)

### PKCE, Client Credentials, Token Refresh

**What I Built**:
- [PKCE](https://datatracker.ietf.org/doc/html/rfc7636) code challenge/verifier validation
- Client Credentials flow for service-to-service auth
- Token refresh endpoint with refresh token rotation

**Key Learnings**:
- **[PKCE](https://datatracker.ietf.org/doc/html/rfc7636) is non-negotiable** for mobile/[SPA](https://en.wikipedia.org/wiki/Single-page_application) apps - prevents authorization code interception
- Code challenge uses SHA256 hash of code verifier
- Refresh token rotation prevents token replay attacks
- Client Credentials = machine-to-machine (no user context)

### OIDC Layer & Podman Setup

**What I Built**:
- [OIDC](https://openid.net/specs/openid-connect-core-1_0.html) ID tokens with user claims
- UserInfo endpoint (`/userinfo`)
- Discovery endpoint (`/.well-known/openid-configuration`)
- [Podman Compose](https://github.com/containers/podman-compose) setup with [Redis](https://redis.io)

**Key Learnings**:
- **[OIDC](https://openid.net/specs/openid-connect-core-1_0.html) adds identity layer to [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749)'s authorization framework** - this distinction is critical
- ID tokens contain user identity claims (sub, email, name)
- Access tokens are opaque - ID tokens are for identity
- Discovery endpoint enables dynamic client configuration

**Key Insight**: [OIDC](https://openid.net/specs/openid-connect-core-1_0.html) answers "who is the user?" while [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749) answers "what can they access?" They're complementary, not competing standards.

---

## Security Deep Dive

Built security scanning tools to internalize identity vulnerabilities.

### Static Config Scanner

**What I Built**:
- [CLI](https://en.wikipedia.org/wiki/Command-line_interface) static analysis tool with [Cobra](https://github.com/spf13/cobra)
- 12 vulnerability detectors (6 [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749) + 6 [JWT](https://datatracker.ietf.org/doc/html/rfc7519))
- YAML/JSON parser with line number tracking
- Human-readable and JSON report formats

**Vulnerability Detectors**:

*OAuth2 Vulnerabilities*:
1. Weak client secrets (< 32 bytes)
2. Insecure redirect URIs (wildcard, HTTP on non-localhost)
3. Missing [PKCE](https://datatracker.ietf.org/doc/html/rfc7636) enforcement
4. Excessive scopes (admin, *, write access)
5. Deprecated flows (implicit, password grant)
6. Missing state parameter validation

*JWT Vulnerabilities*:
1. Algorithm confusion (none, HS256 when RS256 expected)
2. Weak signing keys (< 256 bits)
3. Missing expiration claims
4. Excessive token lifetime (> 1 hour for access tokens)
5. Missing audience validation
6. Hardcoded secrets in config files

**Key Learnings**:
- **Weak secrets** are the #1 vulnerability - minimum 32 bytes of entropy
- **Redirect URI validation** is critical - wildcard URIs = open redirect
- **Algorithm confusion** attacks exploit lax JWT validation
- **Missing expiration** means tokens live forever

### Remediation Engine & CI/CD Integration

**What I Built**:
- Remediation guidance with [RFC](https://datatracker.ietf.org/) and [OWASP](https://owasp.org/) references
- Severity-based filtering (critical, high, medium, low)
- JSON output for CI/CD pipeline integration
- Configurable rule disabling

**Key Learnings**:
- Security tools must provide **actionable guidance**, not just findings
- Different severity thresholds for blocking builds vs warnings
- JSON output enables integration with security dashboards
- False positives hurt adoption - precision > recall

### Runtime Flow Analyzer

**What I Built**:
- [OIDC](https://openid.net/specs/openid-connect-core-1_0.html) discovery client
- [CSRF](https://owasp.org/www-community/attacks/csrf) attack simulation
- HTTP client with custom headers and redirects

**Key Learnings**:
- Runtime testing complements static analysis
- Discovery endpoints enable automated testing
- [CSRF](https://owasp.org/www-community/attacks/csrf) testing requires tracking state parameter across redirects
- Full OAuth2 flow simulation requires headless browser (complex)

**Key Insight**: Security patterns from previous roles (vulnerability scanners, compliance) apply directly to identity domain. The attack vectors are well-documented - implementation is the challenge.

---

## Scale & Operations

Implemented session management thinking about multi-brand, global-scale requirements.

### Session Service with Multi-Tenant Isolation

**What I Built**:
- Session data models (Session, Token, Tenant, RefreshToken)
- JWT Manager with RS256 signing
- Multi-Tenant Key Manager with in-memory cache
- [Redis](https://redis.io) Session Store with refresh tokens

**Key Learnings**:
- **Multi-tenant isolation** requires separate signing keys per tenant
- In-memory key cache reduces Redis lookups (99% hit rate)
- Refresh tokens stored separately from access tokens
- Session revocation requires blocklist (can't revoke JWTs directly)

### Load Testing & Observability

**What I Built**:
- HTTP handlers: CreateSession, ValidateSession, RefreshSession, RevokeSession
- JWKS endpoint for public key distribution
- [Prometheus](https://prometheus.io/) metrics hooks (counters, histograms)
- [k6](https://k6.io) load testing scripts

**Key Learnings**:
- **Observability is essential** - can't optimize what you don't measure
- Stateless JWT validation = O(1) performance
- [Redis](https://redis.io) blocklist lookup adds ~1-2ms latency
- Proper error handling prevents cascading failures

### Documentation & Architecture Diagrams

**What I Built**:
- Comprehensive README with setup instructions
- PRD documenting requirements and design decisions
- Architecture diagrams for OAuth2 server and session management
- Educational deep-dives ([OIDC](https://openid.net/specs/openid-connect-core-1_0.html) walkthrough, [PKCE](https://datatracker.ietf.org/doc/html/rfc7636) deep dive)

**Key Learnings**:
- Documentation is as important as code
- Architecture diagrams clarify system boundaries
- Educational content helps internalize concepts
- Linking to RFCs and standards aids future reference

**Key Insight**: Identity at scale = distributed systems problem. [JWT](https://datatracker.ietf.org/doc/html/rfc7519) for speed, [Redis](https://redis.io) for consistency. Hybrid approach gives best of both worlds.

---

## What I Learned

### Protocol Trade-offs

**[OAuth2](https://datatracker.ietf.org/doc/html/rfc6749) vs [OIDC](https://openid.net/specs/openid-connect-core-1_0.html)**:
- OAuth2 is **authorization** ("can user X access resource Y?")
- OIDC is **authentication** ("who is user X?")
- Different problems, complementary solutions
- OIDC extends OAuth2 with ID tokens and UserInfo endpoint

**[SAML](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html) vs [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749)**:
- SAML = Enterprise partnerships, XML-based, complex
- OAuth2 = Modern apps, JSON-based, developer-friendly
- Both have valid use cases - not mutually exclusive

**[SAML](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)/[OIDC](https://openid.net/specs/openid-connect-core-1_0.html) Interoperability**:
- Identity brokers ([Auth0](https://auth0.com), [Okta](https://www.okta.com)) bridge protocols
- [Microsoft Entra ID](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id) supports both natively
- Protocol translation layers for hybrid environments
- Many enterprises need both for legacy + modern apps

**[JWT](https://datatracker.ietf.org/doc/html/rfc7519) Validation Trade-offs**:
- Stateless = fast (no DB lookup), but can't revoke
- Stateful = revocable, but needs DB lookup on every request
- Hybrid = JWT + blocklist (best of both)

### Security Considerations

**[PKCE](https://datatracker.ietf.org/doc/html/rfc7636) is Non-Negotiable**:
- Prevents authorization code interception on mobile devices
- Without it, malicious apps can steal authorization codes
- Uses SHA256 hash of random verifier
- OAuth2.1 makes PKCE mandatory for all clients

**State Parameter Prevents [CSRF](https://owasp.org/www-community/attacks/csrf)**:
- Must be cryptographically random (32+ bytes)
- Stored in session, validated on callback
- Prevents attacker from hijacking authorization flow

**Redirect URI Validation is Critical**:
- Wildcard URIs = [open redirect vulnerability](https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards)
- Must match registered URI exactly
- HTTP only allowed for localhost (development)

**Token Lifetime Trade-offs**:
- Short access tokens (15 minutes) limit exposure
- Longer refresh tokens (30 days) for usability
- Refresh token rotation prevents replay attacks

### Scale Thinking

**Multi-Tenant Isolation**:
- Separate signing keys per tenant (cryptographic isolation)
- Shared infrastructure, separate session pools
- Tenant context propagated through all layers

**Global Deployments**:
- [Redis](https://redis.io) replication for cross-region consistency
- JWT validation works offline (no DB call)
- Revocation requires distributed blocklist

**Observability is Essential**:
- Can't optimize what you don't measure
- Structured logging for debugging
- Metrics for performance monitoring
- Distributed tracing for complex flows

---

[← Back to README](../README.md)
