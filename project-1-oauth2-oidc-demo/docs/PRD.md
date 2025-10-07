# Product Requirements Document (PRD)
# OAuth2/OIDC Authorization Server

**Version**: 1.0
**Date**: October 2025
**Status**: In Development
**Author**: Matt Bordenet

---

## 1. Executive Summary

### 1.1 Purpose
Build a standards-compliant [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749) and [OpenID Connect (OIDC)](https://openid.net/specs/openid-connect-core-1_0.html) authorization server from scratch to demonstrate deep understanding of identity protocols. This is a learning project to show rapid domain mastery in identity/access management for senior leadership roles.

### 1.2 Goals
- **Primary**: Implement [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749) authorization flows per [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- **Secondary**: Add [OIDC](https://openid.net/specs/openid-connect-core-1_0.html) identity layer per [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) spec
- **Tertiary**: Demonstrate production-quality patterns (error handling, security, observability)

### 1.3 Non-Goals
- Full production deployment (this is a learning/demonstration project)
- User management system (simple in-memory users for demo)
- Multi-tenancy (covered in Project 2)
- Advanced features like [OAuth2 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662), [Device Flow](https://datatracker.ietf.org/doc/html/rfc8628), etc.

---

## 2. Background & Context

### 2.1 Problem Statement
Modern applications require secure, delegated authorization. Users need to grant third-party apps limited access to their resources without sharing passwords. Identity providers need to authenticate users and provide identity information to apps.

### 2.2 Why OAuth2 + OIDC?
- **[OAuth2](https://datatracker.ietf.org/doc/html/rfc6749)**: Industry standard for authorization ([RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749))
- **[OIDC](https://openid.net/specs/openid-connect-core-1_0.html)**: Identity layer on top of OAuth2 (authentication + user info)
- **Ubiquity**: Used by Google, Facebook, Microsoft, GitHub, etc.
- **Security**: Proven patterns for web, mobile, [SPA](https://en.wikipedia.org/wiki/Single-page_application), and service-to-service auth

### 2.3 Learning Objectives
1. Understand [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749) vs [OIDC](https://openid.net/specs/openid-connect-core-1_0.html) differences (authorization vs authentication)
2. Implement security best practices ([PKCE](https://datatracker.ietf.org/doc/html/rfc7636), state parameter, short-lived tokens)
3. Build stateless [JWT](https://datatracker.ietf.org/doc/html/rfc7519) validation with distributed [Redis](https://redis.io) storage
4. Design for horizontal scalability (stateless server, external session store)

---

## 3. User Personas

### 3.1 Application Developer
**Needs**: Easy integration with [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749)/[OIDC](https://openid.net/specs/openid-connect-core-1_0.html) flows for their app
**Pain Points**: Complex OAuth2 setup, unclear error messages, missing documentation
**Success Criteria**: Can integrate with server in < 30 minutes using example client

### 3.2 Security Auditor
**Needs**: Verify implementation follows [OWASP](https://owasp.org/www-project-application-security-verification-standard/) identity best practices
**Pain Points**: Hardcoded secrets, missing [PKCE](https://datatracker.ietf.org/doc/html/rfc7636) enforcement, overly permissive scopes
**Success Criteria**: Can run security scanner (Project 3) and find zero critical issues

### 3.3 Platform Engineer
**Needs**: Scalable, observable, operationally excellent identity infrastructure
**Pain Points**: Stateful servers, no metrics, difficult to debug
**Success Criteria**: Can deploy multiple instances, monitor with [Prometheus](https://prometheus.io), scale horizontally

---

## 4. Functional Requirements

### 4.1 OAuth2 Authorization Code Flow ([RFC 6749 Section 4.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1))
**Priority**: P0 (Must Have)

**User Story**: As a web application, I want to obtain an access token via authorization code flow so that I can access protected resources on behalf of a user.

**Acceptance Criteria**:
- [ ] `/authorize` endpoint returns authorization code after user consent
- [ ] Authorization code expires in 10 minutes
- [ ] Authorization code is single-use (invalidated after token exchange)
- [ ] State parameter validated to prevent [CSRF](https://owasp.org/www-community/attacks/csrf)
- [ ] Redirect [URI](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier) validated against registered client URIs
- [ ] Scope parameter supported and validated

**Flow**:
```
1. Client redirects user to /authorize?response_type=code&client_id=X&redirect_uri=Y&scope=Z&state=RANDOM
2. User authenticates and grants consent
3. Server redirects back to client: redirect_uri?code=AUTH_CODE&state=RANDOM
4. Client exchanges code for token: POST /token with code, client_id, client_secret
5. Server returns access_token, refresh_token, expires_in
```

### 4.2 PKCE Extension ([RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636))
**Priority**: P0 (Must Have)

**User Story**: As a mobile app or [SPA](https://en.wikipedia.org/wiki/Single-page_application), I want [PKCE](https://datatracker.ietf.org/doc/html/rfc7636) protection so that authorization codes cannot be intercepted.

**Acceptance Criteria**:
- [ ] Support code_challenge and code_challenge_method in /authorize
- [ ] Support S256 ([SHA-256](https://en.wikipedia.org/wiki/SHA-2)) and plain methods
- [ ] Require PKCE for public clients (no client_secret)
- [ ] Validate code_verifier matches code_challenge in /token request
- [ ] Reject token exchange if PKCE validation fails

**Security Rationale**: Prevents authorization code interception attacks on public clients (mobile, [SPA](https://en.wikipedia.org/wiki/Single-page_application)) where client_secret cannot be kept confidential.

### 4.3 Client Credentials Flow ([RFC 6749 Section 4.4](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4))
**Priority**: P0 (Must Have)

**User Story**: As a backend service, I want to obtain an access token using my client credentials so that I can access [APIs](https://en.wikipedia.org/wiki/API) without user context.

**Acceptance Criteria**:
- [ ] POST /token with grant_type=client_credentials, client_id, client_secret
- [ ] Returns access_token with scope limited to client's registered scopes
- [ ] No refresh_token issued (client can request new access_token anytime)
- [ ] Access token includes client_id but no user_id
- [ ] Supports scope parameter to request subset of client's scopes

**Use Case**: Service-to-service authentication (e.g., background jobs, microservices)

### 4.4 Token Refresh Flow ([RFC 6749 Section 6](https://datatracker.ietf.org/doc/html/rfc6749#section-6))
**Priority**: P0 (Must Have)

**User Story**: As a client application, I want to refresh expired access tokens without user interaction so that my users don't have to re-authenticate frequently.

**Acceptance Criteria**:
- [ ] POST /token with grant_type=refresh_token, refresh_token
- [ ] Returns new access_token and optionally new refresh_token
- [ ] Refresh token is long-lived (30 days default)
- [ ] Refresh token can only be used once (token rotation)
- [ ] Scope cannot be expanded (can only request subset of original scope)

**Security**: Refresh token rotation prevents replay attacks.

### 4.5 OIDC ID Token ([OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html))
**Priority**: P0 (Must Have)

**User Story**: As a [relying party](https://openid.net/specs/openid-connect-core-1_0.html#Terminology), I want an [ID token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) containing user identity claims so that I can authenticate the user.

**Acceptance Criteria**:
- [ ] ID token returned when scope includes "openid"
- [ ] ID token is a signed [JWT](https://datatracker.ietf.org/doc/html/rfc7519) with claims: iss, sub, aud, exp, iat, nonce
- [ ] Optional claims: name, email, email_verified, profile, picture
- [ ] ID token signed with [RS256](https://datatracker.ietf.org/doc/html/rfc7518#section-3.3) (RSA-SHA256)
- [ ] ID token expires in 1 hour

**[OIDC](https://openid.net/specs/openid-connect-core-1_0.html) vs [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749)**: ID token is for authentication (who the user is), access token is for authorization (what they can access).

### 4.6 OIDC UserInfo Endpoint ([OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo))
**Priority**: P1 (Should Have)

**User Story**: As a relying party, I want to fetch user profile information using an access token so that I can get additional claims not in the ID token.

**Acceptance Criteria**:
- [ ] GET /userinfo with Authorization: Bearer ACCESS_TOKEN
- [ ] Returns JSON with user claims: sub, name, email, etc.
- [ ] Validates access token and checks "openid" scope
- [ ] Returns 401 if token invalid/expired, 403 if scope insufficient

### 4.7 Token Revocation
**Priority**: P1 (Should Have)

**User Story**: As a user or client, I want to revoke tokens when logging out or when security is compromised.

**Acceptance Criteria**:
- [ ] POST /revoke with token (access or refresh token)
- [ ] Token added to Redis blocklist
- [ ] Revoked tokens rejected in all future validations
- [ ] Blocklist TTL matches token expiration (no indefinite storage)

---

## 5. Non-Functional Requirements

### 5.1 Security
**Priority**: P0

- [ ] No hardcoded secrets (all from environment variables)
- [ ] [JWT](https://datatracker.ietf.org/doc/html/rfc7519) signed with [RS256](https://datatracker.ietf.org/doc/html/rfc7518#section-3.3) (asymmetric keys)
- [ ] State parameter required for authorization flow
- [ ] PKCE required for public clients
- [ ] Access tokens short-lived (15 min), refresh tokens long-lived (30 days)
- [ ] [HTTPS](https://en.wikipedia.org/wiki/HTTPS) required in production (HTTP allowed for local dev)
- [ ] No sensitive data in access tokens (opaque token preferred, but using JWT for learning)

### 5.2 Performance
**Priority**: P1

- [ ] Token validation < 10ms ([JWT](https://datatracker.ietf.org/doc/html/rfc7519) validation, no DB lookup)
- [ ] Authorization code generation < 50ms
- [ ] Support 100 req/sec on single instance (local dev)
- [ ] Stateless server (no in-memory sessions, all in Redis)

### 5.3 Scalability
**Priority**: P1

- [ ] Horizontal scaling (multiple server instances)
- [ ] [Redis](https://redis.io) for distributed state (auth codes, refresh tokens, revocation list)
- [ ] No local state (all session data in Redis)

### 5.4 Observability
**Priority**: P1

- [ ] Structured [JSON](https://www.json.org) logging
- [ ] Log levels: DEBUG, INFO, WARN, ERROR
- [ ] Metrics endpoint for [Prometheus](https://prometheus.io)
- [ ] Metrics: token_issued_total, token_validated_total, errors_total
- [ ] Request ID propagation for [distributed tracing](https://opentelemetry.io/docs/concepts/observability-primer/#distributed-traces)

### 5.5 Operability
**Priority**: P1

- [ ] [Docker Compose](https://docs.docker.com/compose/) one-liner setup
- [ ] [Makefile](https://www.gnu.org/software/make/manual/make.html) with common commands (run, test, build, clean)
- [ ] Graceful shutdown (finish in-flight requests)
- [ ] Health check endpoint: GET /health

---

## 6. Technical Design

### 6.1 Architecture

```
┌─────────────────┐      ┌──────────────────────┐      ┌─────────────┐
│  Client App     │─────▶│  Authorization       │─────▶│   Redis     │
│  (Web/Mobile)   │      │  Server (Go)         │      │  (Session)  │
│                 │◀─────│  OAuth2 + OIDC       │◀─────│             │
└─────────────────┘      └──────────────────────┘      └─────────────┘
   HTTP/HTTPS                Stateless Service         Distributed Store
```

**Components**:
1. **Authorization Server**: [Go](https://go.dev) [HTTP](https://en.wikipedia.org/wiki/HTTP) server with [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749)/[OIDC](https://openid.net/specs/openid-connect-core-1_0.html) handlers
2. **[Redis](https://redis.io)**: Stores authorization codes, refresh tokens, revocation list
3. **[JWT](https://datatracker.ietf.org/doc/html/rfc7519)**: Stateless access tokens and ID tokens ([RS256](https://datatracker.ietf.org/doc/html/rfc7518#section-3.3) signed)

### 6.2 Data Flow: Authorization Code Flow

```
1. User clicks "Login with OAuth" in client app
2. Client → /authorize (response_type=code, client_id, redirect_uri, scope, state, code_challenge)
3. Server authenticates user (simple login form for demo)
4. Server generates authorization code, stores in Redis with PKCE challenge
5. Server → Client redirect with code and state
6. Client → /token (grant_type=authorization_code, code, client_id, client_secret, code_verifier)
7. Server validates code, PKCE, client credentials
8. Server generates access_token (JWT), refresh_token, id_token (if openid scope)
9. Server stores refresh_token in Redis, invalidates authorization code
10. Server → Client with access_token, refresh_token, id_token
```

### 6.3 Technology Stack

| Component        | Technology                | Rationale                          |
|------------------|---------------------------|------------------------------------|
| Language         | [Go](https://go.dev) 1.21+                  | Fast, concurrent, strong stdlib    |
| HTTP Router      | [gorilla/mux](https://github.com/gorilla/mux)               | Mature, widely-used                |
| JWT              | [golang-jwt/jwt](https://github.com/golang-jwt/jwt) v5         | Standard [JWT](https://datatracker.ietf.org/doc/html/rfc7519) library               |
| Redis Client     | [go-redis/redis](https://github.com/redis/go-redis) v9         | Official [Redis](https://redis.io) client for Go       |
| Config           | [spf13/viper](https://github.com/spf13/viper)               | Env vars + [YAML](https://yaml.org) config             |
| Logging          | [slog](https://pkg.go.dev/log/slog) (Go 1.21+)           | Structured logging in stdlib       |
| Crypto           | [crypto/rand](https://pkg.go.dev/crypto/rand), [crypto/sha256](https://pkg.go.dev/crypto/sha256)| Go stdlib for security primitives  |

### 6.4 Storage Schema (Redis)

**Authorization Codes** (TTL: 10 minutes):
```
Key: authz:code:{code}
Value: JSON{client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, expires_at}
```

**Refresh Tokens** (TTL: 30 days):
```
Key: refresh:token:{token}
Value: JSON{client_id, user_id, scope, expires_at}
```

**Revocation List** (TTL: matches token expiration):
```
Key: revoked:{token}
Value: "1"
```

**Clients** (No TTL):
```
Key: client:{client_id}
Value: JSON{client_id, client_secret_hash, redirect_uris, name, type, scopes}
```

### 6.5 API Endpoints

| Endpoint         | Method | Purpose                              |
|------------------|--------|--------------------------------------|
| `/authorize`     | GET    | OAuth2 authorization request         |
| `/token`         | POST   | Token exchange (all grant types)     |
| `/userinfo`      | GET    | OIDC user information                |
| `/revoke`        | POST   | Token revocation                     |
| `/.well-known/openid-configuration` | GET | OIDC discovery |
| `/health`        | GET    | Health check                         |
| `/metrics`       | GET    | Prometheus metrics                   |

---

## 7. Success Metrics

### 7.1 Functional Completeness
- [ ] All 4 OAuth2 flows working end-to-end
- [ ] OIDC ID token generation and UserInfo endpoint
- [ ] PKCE validation working
- [ ] Token refresh working
- [ ] Token revocation working

### 7.2 Code Quality
- [ ] Unit tests for token generation/validation (>70% coverage)
- [ ] Integration tests for full flows
- [ ] No hardcoded secrets (ggshield passes)
- [ ] Go lint passes (golangci-lint)

### 7.3 Documentation
- [ ] Comprehensive README with architecture diagrams
- [ ] Sequence diagrams for each flow
- [ ] Security considerations documented
- [ ] Example client with clear instructions

### 7.4 Demo Readiness
- [ ] Can demo authorization code flow in < 2 minutes
- [ ] Can explain PKCE in < 1 minute
- [ ] Can explain OAuth2 vs OIDC difference in < 30 seconds

---

## 8. Timeline

**Total Time**: 6-8 hours

### Phase 1: Core OAuth2 (3 hours)
- [ ] Project setup, Go module, Redis connection
- [ ] Authorization code flow (authorize + token endpoints)
- [ ] JWT token generation/validation
- [ ] Basic error handling

### Phase 2: PKCE + Additional Flows (2 hours)
- [ ] PKCE implementation and validation
- [ ] Client credentials flow
- [ ] Token refresh flow

### Phase 3: OIDC Layer (2 hours)
- [ ] ID token generation with claims
- [ ] UserInfo endpoint
- [ ] OIDC discovery endpoint

### Phase 4: Polish (1-2 hours)
- [ ] Example client application
- [ ] Docker Compose setup
- [ ] README with diagrams
- [ ] Security documentation

---

## 9. Future Enhancements (Out of Scope for v1)

- Token introspection (RFC 7662)
- Device authorization flow (RFC 8628)
- JWT bearer grant (RFC 7523)
- Dynamic client registration (RFC 7591)
- User consent management UI
- Multi-tenancy support
- Rate limiting
- Audit logging

---

## 10. References

### Specifications
- **OAuth 2.0**: [RFC 6749 - The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- **PKCE**: [RFC 7636 - Proof Key for Code Exchange](https://datatracker.ietf.org/doc/html/rfc7636)
- **JWT**: [RFC 7519 - JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- **OIDC Core**: [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

### Security
- **OWASP ASVS**: [Application Security Verification Standard - Identity and Authentication](https://owasp.org/www-project-application-security-verification-standard/)
- **OAuth 2.0 Security Best Practices**: [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

### Learning Resources
- **Auth0 Docs**: [OAuth 2.0 and OpenID Connect](https://auth0.com/docs/authenticate/protocols/oauth)
- **Okta Developer**: [OAuth 2.0 and OIDC Overview](https://developer.okta.com/docs/concepts/oauth-openid/)
- **NIST Digital Identity Guidelines**: [SP 800-63B - Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

## Appendix A: Glossary

| Term              | Definition                                                                 |
|-------------------|---------------------------------------------------------------------------|
| **OAuth2**        | Authorization framework (RFC 6749) for delegated access                  |
| **OIDC**          | OpenID Connect, identity layer on top of OAuth2                          |
| **Authorization Code** | Short-lived code exchanged for access token                         |
| **Access Token**  | Token used to access protected resources (bearer token)                  |
| **Refresh Token** | Long-lived token used to obtain new access tokens                        |
| **ID Token**      | JWT containing user identity claims (OIDC)                               |
| **PKCE**          | Proof Key for Code Exchange, prevents code interception                 |
| **Scope**         | Permission requested by client (e.g., "read:profile")                   |
| **State**         | Random string to prevent CSRF attacks                                    |
| **Nonce**         | Random string to prevent replay attacks (OIDC)                           |
| **Client**        | Application requesting access on behalf of user or itself                |
| **Resource Owner**| User who authorizes access to their resources                            |
| **Authorization Server** | Issues tokens after authenticating user/client                    |
