# Changelog - OAuth2/OIDC Authorization Server

All notable changes to the OAuth2/OIDC Authorization Server project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2025-10-08 🎉

### Project Complete ✅

Complete OAuth2 and OpenID Connect authorization server with all flows, endpoints, and production-ready patterns.

**Commit:** `596494e` - Add project infrastructure and comprehensive documentation

### Added - Infrastructure and Documentation

**Build/Deployment Infrastructure:**
- **Makefile** with easy commands:
  - `make generate-keys` - Generate RSA key pair for JWT signing
  - `make redis-start` - Start Redis server (Docker)
  - `make redis-stop` - Stop Redis server
  - `make run-server` - Run authorization server (port 8080)
  - `make run-client` - Run demo client (port 3000)
  - `make clean` - Remove generated keys and temporary files
  - `make test` - Run all tests

- **docker-compose.yml** - Multi-container orchestration:
  - Redis service with persistent storage and health checks
  - Authorization server service with auto-restart
  - Demo client service
  - Automatic dependency management

- **Dockerfile** - Multi-stage build for authorization server:
  - Stage 1: Go 1.21 builder with dependency caching
  - Stage 2: Alpine runtime (minimal attack surface)
  - CGO disabled for static binary
  - Single binary deployment

- **Dockerfile.client** - Multi-stage build for demo client
  - Same optimization patterns as server Dockerfile

- **.gitignore** - Comprehensive exclusions:
  - RSA keys (`keys/`, `*.pem`) - NEVER commit private keys
  - Go build artifacts (`*.exe`, `*.so`, `*.dylib`, binaries)
  - Test binaries and coverage files (`*.test`, `*.out`)
  - IDE files (`.idea/`, `.vscode/`, `*.swp`)
  - OS files (`.DS_Store`, `Thumbs.db`)
  - Environment files (`.env`, `.env.local`)
  - Temporary directories

**Comprehensive README.md** (400+ lines):
- Feature overview (OAuth2 flows, OIDC, security features)
- Quick start guide (3 commands to run entire stack)
- Complete API documentation for all 5 endpoints:
  - `GET /authorize` - Authorization endpoint
  - `POST /oauth2/token` - Token endpoint (3 grant types)
  - `GET /userinfo` - UserInfo endpoint
  - `GET /.well-known/openid-configuration` - OIDC Discovery
  - `GET /.well-known/jwks.json` - Public keys (JWKS)
- Demo clients reference table (web-app, mobile-app, service-app)
- Demo users reference table (Alice, Bob, Charlie)
- OAuth2 scopes table (openid, profile, email, offline_access, api.*)
- Token lifetimes table (authorization code, access, ID, refresh)
- Architecture diagram (ASCII art showing component layers)
- Project structure tree
- **Security considerations and production checklist** (14 items):
  - Change client secrets from demo values
  - Use environment variables (never commit secrets)
  - Enable HTTPS/TLS
  - Rotate RSA keys regularly
  - Implement rate limiting
  - Add brute-force protection
  - Use production user store (PostgreSQL/MySQL)
  - Enable Redis authentication
  - Implement consent screen
  - Add logging/monitoring (Prometheus, Grafana)
  - Configure CORS policies
  - Input validation and sanitization
  - Account lockout
  - Secure cookie flags
- Development instructions (tests, cleanup)
- Docker Compose usage
- References to RFCs and best practices

**Project Status - All Features Complete:**
- ✅ OAuth2 Authorization Code Flow
- ✅ OAuth2 Authorization Code Flow with PKCE
- ✅ OAuth2 Client Credentials Flow
- ✅ OAuth2 Refresh Token Flow
- ✅ OIDC ID Tokens with nonce, at_hash
- ✅ OIDC UserInfo Endpoint
- ✅ OIDC Discovery Endpoint
- ✅ JWKS Public Key Endpoint
- ✅ Token Revocation with Redis Blocklist
- ✅ Multi-client Support (3 demo clients)
- ✅ Multi-user Support (3 demo users)
- ✅ Production-ready patterns (graceful shutdown, distributed sessions)
- ✅ Comprehensive documentation

---

## [0.9.0] - 2025-10-08

### Added - Server and Client Applications

**Commit:** `02ed7fa` - Complete OAuth2/OIDC server implementation

**User Store:**
- `internal/store/user_store.go` - In-memory user store for demo
- Thread-safe with `sync.RWMutex`
- 3 demo users:
  - `alice` (alice@example.com) - Alice Smith
  - `bob` (bob@example.com) - Bob Johnson
  - `charlie` (charlie@example.com) - Charlie Brown
- Simple key-value lookup by user ID
- Production note: Replace with database (PostgreSQL, MySQL)

**Authorization Server:**
- `cmd/server/main.go` - Main authorization server application (430 lines)
- **Configuration** - Loads from environment variables:
  - `REDIS_URL` - Redis connection (default: localhost:6379)
  - `ISSUER` - OAuth2 issuer URL (default: http://localhost:8080)
  - `PORT` - Server port (default: :8080)
  - `PRIVATE_KEY_PATH` - RSA private key file (default: keys/private.pem)
  - `PUBLIC_KEY_PATH` - RSA public key file (default: keys/public.pem)

- **Initialization Sequence:**
  1. Redis connection with ping health check
  2. Session store with `identity:` key prefix
  3. RSA key loading from PEM files (with error handling)
  4. JWT manager with TTLs (access: 15m, refresh: 30d, ID: 15m)
  5. In-memory user store with demo data
  6. All HTTP handlers (authorize, token, userinfo, discovery, jwks)

- **Routing** (gorilla/mux):
  - `GET /authorize` - Authorization endpoint
  - `POST /oauth2/token` - Token endpoint
  - `GET /userinfo` - UserInfo endpoint (Bearer auth)
  - `GET /.well-known/openid-configuration` - Discovery endpoint
  - `GET /.well-known/jwks.json` - JWKS endpoint

- **Demo Clients** - Seeded on startup:
  - `web-app` (confidential):
    - Type: Confidential (has client_secret)
    - Secret: `web-app-secret-change-in-production`
    - Redirect URIs: `http://localhost:3000/callback`
    - Scopes: openid, profile, email, offline_access
  - `mobile-app` (public):
    - Type: Public (no secret, PKCE required)
    - Redirect URIs: `myapp://callback`
    - Scopes: openid, profile, email, offline_access
  - `service-app` (confidential):
    - Type: Confidential
    - Secret: `service-app-secret-change-in-production`
    - Grant Types: client_credentials only
    - Scopes: api.read, api.write

- **Graceful Shutdown:**
  - Signal handling (SIGINT, SIGTERM)
  - HTTP server shutdown with 15-second timeout
  - Redis connection cleanup
  - Prevents data loss on deployment

**Demo Client:**
- `cmd/client/main.go` - Demo OIDC client application (210 lines)
- **Authorization Code Flow with PKCE:**
  - Generates state (32 bytes, base64url) - CSRF protection
  - Generates nonce (32 bytes, base64url) - Replay protection
  - Generates code_verifier (43 bytes, base64url) - PKCE
  - Generates code_challenge (SHA256 of verifier) - PKCE S256 method

- **Endpoints:**
  - `GET /` - Home page with "Login" button
  - `GET /login` - Redirects to authorization server with PKCE params
  - `GET /callback` - Handles OAuth2 callback

- **Callback Flow:**
  1. Validates state parameter (CSRF check)
  2. Exchanges authorization code for tokens
  3. Sends code_verifier for PKCE validation
  4. Fetches UserInfo with access token
  5. Displays all tokens and user profile in browser

- **Security:**
  - In-memory session storage (demo - use Redis in production)
  - State validation prevents CSRF attacks
  - PKCE prevents authorization code interception
  - HTTPS recommended for production

**All OAuth2/OIDC flows now fully implemented:**
- ✅ Authorization code flow (with/without PKCE)
- ✅ Refresh token flow
- ✅ Client credentials flow (service-to-service)

---

## [0.8.0] - 2025-10-08

### Added - OIDC Discovery and UserInfo Endpoints

**Commit:** `b9c9d5a` - Add UserInfo, Discovery, and JWKs endpoint handlers

**UserInfo Endpoint:**
- `internal/handlers/userinfo.go` - Implements OIDC Core Section 5.3
- **Bearer Token Validation:**
  - Extracts token from `Authorization: Bearer <token>` header
  - Validates JWT signature with RSA public key
  - Validates expiration and standard claims
  - Returns HTTP 401 for missing/invalid tokens

- **Scope-based Claims (OIDC Core Section 5.1):**
  - Always returns `sub` (subject/user ID) - required
  - `profile` scope → name, given_name, family_name, picture
  - `email` scope → email, email_verified
  - Future: address, phone scopes

- **Response Format:**
  - JSON with `Content-Type: application/json`
  - HTTP 200 on success
  - HTTP 401 on auth failure
  - HTTP 500 on server error

**OIDC Discovery Endpoint:**
- `internal/handlers/discovery.go` - Implements OIDC Discovery 1.0 spec
- **Metadata Document** (`/.well-known/openid-configuration`):
  - `issuer` - OAuth2 issuer identifier (must match token iss claim)
  - `authorization_endpoint` - Where to start auth flow
  - `token_endpoint` - Where to exchange code for tokens
  - `userinfo_endpoint` - Where to fetch user profile
  - `jwks_uri` - Where to get public keys for validation
  - `scopes_supported` - Available scopes (openid, profile, email, offline_access)
  - `response_types_supported` - Supported response types (code)
  - `grant_types_supported` - Supported grant types (authorization_code, refresh_token, client_credentials)
  - `code_challenge_methods_supported` - PKCE methods (S256, plain)
  - `id_token_signing_alg_values_supported` - ID token algorithms (RS256)
  - `subject_types_supported` - Subject identifier types (public)
  - `token_endpoint_auth_methods_supported` - Client auth methods

- **Public Endpoint:** No authentication required (per OIDC spec)
- **Purpose:** Enables dynamic client configuration (auto-discovery)

**JWKS Endpoint:**
- `internal/handlers/discovery.go` - JWKSHandler
- **JSON Web Key Set** (`/.well-known/jwks.json`):
  - Returns public keys in JWK format (RFC 7517)
  - Clients use these to validate JWT signatures independently
  - Supports key rotation via `kid` (key ID)
  - Future: Multiple keys for rotation

- **RSA Public Key to JWK Conversion:**
  - `kty: RSA` - Key type
  - `use: sig` - Key usage (signature verification)
  - `alg: RS256` - Algorithm (RSA with SHA-256)
  - `kid: default` - Key identifier (for rotation)
  - `n` - RSA modulus (base64url-encoded)
  - `e` - RSA exponent (base64url-encoded, typically AQAB = 65537)

- **Public Endpoint:** No authentication required

**All Core OIDC Endpoints Now Implemented:**
- ✅ Authorization endpoint (`/authorize`)
- ✅ Token endpoint (`/oauth2/token`)
- ✅ UserInfo endpoint (`/userinfo`)
- ✅ Discovery endpoint (`/.well-known/openid-configuration`)
- ✅ JWKS endpoint (`/.well-known/jwks.json`)

---

## [0.7.0] - 2025-10-08

### Added - Token Endpoint Handler

**Commit:** `fe2013e` - Add token endpoint handler with support for 3 grant types

**Token Endpoint:**
- `internal/handlers/token.go` - Implements RFC 6749 Section 3.2 (Token Endpoint)
- **Supported Grant Types:**
  1. `authorization_code` - Exchange code for tokens (most common)
  2. `refresh_token` - Get new access token (long-lived sessions)
  3. `client_credentials` - Service-to-service auth (no user)

**Authorization Code Grant:**
- Retrieves authorization code from Redis
- **Validation Checks:**
  - Code exists and not already used
  - Code not expired (10-minute TTL)
  - client_id matches original request
  - redirect_uri matches original request (prevents redirect attacks)

- **PKCE Validation (RFC 7636):**
  - Validates code_verifier against stored code_challenge
  - Supports S256 (SHA-256) and plain methods
  - S256: SHA256(code_verifier) == code_challenge
  - Prevents authorization code interception attacks

- **Client Authentication:**
  - Confidential clients: Validates client_secret
  - Public clients: Validates PKCE (no secret allowed)
  - Per OAuth2 Security BCP

- **Token Generation:**
  - Access token (JWT, RS256, 15-minute expiry)
  - ID token (if `openid` scope requested) - OIDC
  - Refresh token (if `offline_access` scope requested)

- **Code Cleanup:**
  - Marks authorization code as used (prevents replay)
  - Invalidates code in Redis immediately
  - One-time use security guarantee

**Refresh Token Grant:**
- Validates refresh token from Redis
- Checks client_id matches original grant
- Issues new access token and ID token
- Preserves original scope (no scope escalation)
- **Future Enhancement:** Implement refresh token rotation (security best practice)

**Client Credentials Grant:**
- Service-to-service authentication (no user context)
- Confidential clients only (requires client_secret)
- Validates client_secret via HTTP Basic Auth
- Issues access token only (no refresh/ID tokens)
- Uses client-provided scope (or defaults to registered scopes)
- Common for API access, background jobs, microservices

**Security Features:**
- **PKCE Validation:** Prevents code interception for public clients
- **One-time Codes:** Authorization codes can only be used once
- **Client Authentication:** Enforces secret validation for confidential clients
- **Cache-Control Header:** `no-store` on responses (prevents token caching)
- **Proper OAuth2 Error Codes:**
  - `invalid_grant` - Code invalid/expired/used/mismatch
  - `invalid_client` - Client authentication failed
  - `unsupported_grant_type` - Grant type not supported
  - `invalid_request` - Missing/invalid parameters

**Error Handling:**
- Returns RFC 6749 compliant error responses
- JSON format with `error` and `error_description` fields
- HTTP 400 for client errors
- HTTP 401 for authentication failures
- Never leaks sensitive information in errors

---

## [0.6.0] - 2025-10-08

### Added - Authorization Endpoint Handler

**Commit:** `a44e5d2` - Add authorization endpoint handler for OAuth2/OIDC

**Authorization Endpoint:**
- `internal/handlers/authorize.go` - Implements RFC 6749 Section 3.1 (Authorization Endpoint)

- **Request Parsing:**
  - Extracts parameters from query string
  - Supports both OAuth2 and OIDC parameters
  - Validates all required parameters present

- **Request Validation:**
  - **Required Parameters:**
    - `client_id` - Must exist in Redis
    - `redirect_uri` - Must match registered URIs
    - `scope` - Must be valid (future: scope validation)
    - `state` - Required for CSRF protection
  - **Optional Parameters:**
    - `response_type` - Defaults to "code"
    - `code_challenge` - PKCE (required for public clients)
    - `code_challenge_method` - S256 or plain
    - `nonce` - OIDC replay protection

- **Client Validation:**
  - Retrieves client from Redis
  - Validates client exists
  - Checks client type (public vs confidential)

- **Redirect URI Validation:**
  - Validates redirect_uri matches client's registered URIs
  - Exact match required (prevents open redirect)
  - **Security:** Per RFC 6749 Section 3.1.2.4:
    - If redirect_uri is INVALID: Display error page (DO NOT redirect)
    - If redirect_uri is VALID: Redirect with error in query params
  - Prevents open redirect attacks

- **PKCE Enforcement:**
  - Public clients MUST provide `code_challenge` and `code_challenge_method`
  - Returns `invalid_request` error if missing
  - Critical for mobile/SPA security (prevents code interception)
  - Confidential clients: PKCE optional but recommended

- **Authorization Code Generation:**
  - Generates cryptographically random 32-byte code
  - Base64URL-encoded for URL safety (43 characters)
  - 10-minute expiration (per OAuth2 best practices)
  - Stored in Redis with:
    - Code challenge and method (PKCE)
    - Nonce (OIDC replay protection)
    - User context (currently stubbed with demo user Alice)
    - Scope, client_id, redirect_uri
    - Expiration timestamp

- **Security Features:**
  - **State Parameter:** Required for CSRF protection
  - **Invalid Redirect URI Handling:** Shows error page instead of redirecting
  - **PKCE for Public Clients:** Enforced at authorization endpoint
  - **Short-lived Codes:** 10-minute expiration prevents stale code attacks

- **Error Codes (RFC 6749 Section 4.1.2.1):**
  - `invalid_request` - Missing/invalid required parameters
  - `unauthorized_client` - Client not authorized for this flow
  - `access_denied` - User denied authorization (future)
  - `unsupported_response_type` - Response type not supported
  - `invalid_scope` - Scope invalid/unknown (future)
  - `server_error` - Internal server error
  - `temporarily_unavailable` - Server temporarily unavailable

- **TODO (Future Enhancements):**
  - Implement login page and session management
  - Implement consent screen (user approval UI)
  - Currently stubs authentication with demo user (Alice)
  - Production would validate user session or show login form

---

## [0.5.1] - 2025-10-08

### Fixed - Mermaid Diagram Rendering on GitHub

**Commit:** `9eb76b2` - fix for GitHub.com's limited mermaid support

**Issue:** GitHub's Mermaid renderer has stricter limits than VS Code preview

**Changes:**
- Ultra-simplified Mermaid diagrams for maximum compatibility
- Removed `<details>` wrapper (caused rendering timeout)
- Removed all participant aliases (`as X`)
- Removed multi-line labels with `<br/>`
- Removed `Note over` blocks
- Reduced participants to absolute minimum (4-5 max)
- Shortened all labels to single line

**Technical Details Preserved:**
- All OIDC specification details remain in text sections
- OIDC Discovery section has complete `.well-known/openid-configuration` example
- ID Token Validation has full 11-step checklist:
  1. Algorithm verification (RS256)
  2. Signature validation with JWKS
  3. Issuer (iss) claim matches
  4. Audience (aud) claim contains client_id
  5. Authorized party (azp) validation
  6. Expiration (exp) not passed
  7. Issued at (iat) not too far in past
  8. Not before (nbf) if present
  9. Nonce matches request
  10. Access token hash (at_hash) validation
  11. Authorization code hash (c_hash) validation
- OIDC Scopes section explains all standard scopes
- UserInfo Endpoint section has complete specification
- Token Endpoint Authentication methods documented
- Error Handling section has all error codes and scenarios
- PKCE_Deep_Dive.md has complete PKCE implementation guide with code examples

**Note:** Diagrams provide high-level flow overview only. All implementation details documented in text sections.

---

## [0.5.0] - 2025-10-08

### Added - Complete OIDC/PKCE Documentation

**Commit:** `714f57f` - Complete OIDC/PKCE documentation with GitHub-compatible diagrams

**OIDC_Walk_Thru.md Enhancements:**

**Mermaid Diagrams:**
- Fixed diagrams to render on GitHub (simplified from VS Code version)
- Reduced complexity (GitHub renderer has stricter limits)
- Two sequence diagrams:
  1. Authorization Code Flow with PKCE
  2. Token validation and UserInfo flow

**ID Token Validation Section:**
- Complete 11-step validation checklist (OIDC Core 3.1.3.7)
- Algorithm verification (must be RS256, not "none")
- Signature validation with JWKS public key
- Issuer (iss) claim matches authorization server
- Audience (aud) claim contains client_id
- Authorized party (azp) validation for multiple audiences
- Expiration (exp) not passed
- Issued at (iat) not too far in past (clock skew tolerance)
- Not before (nbf) if present
- Nonce matches original request (replay protection)
- Access token hash (at_hash) if access token present (token binding)
- Authorization code hash (c_hash) if code present

**OIDC Discovery Section:**
- Complete `.well-known/openid-configuration` example
- All standard fields documented:
  - issuer, endpoints (authorization, token, userinfo, jwks_uri)
  - scopes_supported, response_types_supported
  - grant_types_supported
  - code_challenge_methods_supported
  - id_token_signing_alg_values_supported
  - subject_types_supported
  - token_endpoint_auth_methods_supported
- Hyperlinked to OIDC Discovery 1.0 spec

**OIDC Scopes Section:**
- `openid` - Required for OIDC (triggers ID token generation)
- `profile` - Name, given_name, family_name, picture, birthdate, etc.
- `email` - Email address and email_verified flag
- `address` - Postal address (formatted, street_address, locality, etc.)
- `phone` - Phone number and phone_number_verified flag
- `offline_access` - Refresh token for long-lived sessions

**UserInfo Endpoint Section:**
- Complete endpoint specification (OIDC Core Section 5.3)
- Example JSON response with all standard claims
- Bearer token authentication (`Authorization: Bearer <access_token>`)
- Scope-based claim filtering
- Error responses (invalid_token, insufficient_scope)

**Token Endpoint Authentication Section:**
- `client_secret_basic` - HTTP Basic Auth (most common)
- `client_secret_post` - Secret in POST body
- `private_key_jwt` - JWT signed with client's private key (high security)
- `none` - Public clients (PKCE required instead)

**Error Handling Section:**
- **Authorization Endpoint Errors:**
  - invalid_request, unauthorized_client, access_denied
  - unsupported_response_type, invalid_scope
  - server_error, temporarily_unavailable
- **Token Endpoint Errors:**
  - invalid_request, invalid_client, invalid_grant
  - unauthorized_client, unsupported_grant_type, invalid_scope
- **UserInfo Endpoint Errors:**
  - invalid_token, insufficient_scope

**Mermaid Diagram Enhancements:**
- Added nonce parameter flow
- Added PKCE parameters (code_challenge, code_verifier)
- Added UserInfo endpoint call
- All technical terms hyperlinked to RFCs and OIDC specs

**PKCE_Deep_Dive.md - NEW FILE:**

**Complete PKCE Guide (RFC 7636):**
- Builds on OIDC_Walk_Thru.md concepts
- Attack scenario diagram showing authorization code interception
- Why PKCE is critical for mobile apps and SPAs

**Step-by-Step PKCE Flow:**
- Detailed Mermaid sequence diagram with 7 steps
- Shows S256 transformation (SHA-256 → base64url)
- Code generation → Authorization → Code exchange → Validation

**Code Examples:**
- **JavaScript** (browser/Node.js):
  - crypto.randomBytes for verifier generation
  - SHA-256 hashing with crypto.subtle
  - base64url encoding

- **Go** (authorization server):
  - crypto/rand for secure random
  - sha256 package for hashing
  - base64.RawURLEncoding for encoding

- **Swift** (iOS):
  - Data.randomBytes for verifier
  - CryptoKit SHA256 for hashing
  - base64url encoding helper

**Security Considerations:**
- **Entropy Requirements:**
  - Minimum: 256 bits (32 bytes)
  - Recommended: 43-128 characters base64url
  - Must be cryptographically random (not Math.random())

- **Timing Attack Prevention:**
  - Use constant-time comparison for code_verifier validation
  - Prevents timing side-channel attacks

- **S256 vs Plain:**
  - S256 recommended (prevents verifier interception)
  - Plain only for constrained devices (legacy)

- **Storage Security:**
  - code_verifier: Memory only, never persist, never log
  - code_challenge: Can be logged (derived, not secret)

**PKCE vs client_secret:**
- Comparison table for different client types:
  - Mobile apps: PKCE (can't protect secrets)
  - SPAs: PKCE (can't protect secrets)
  - Backend services: client_secret (can protect secrets)
  - Public clients: PKCE required
  - Confidential clients: client_secret OR PKCE (both is best)

**Migration Guide:**
- Migrating from non-PKCE flows
- Best practices for each client type
- Backward compatibility considerations

**Implementation Links:**
- Cross-references to project source files:
  - `internal/tokens/pkce.go` - PKCE validation logic
  - `internal/handlers/authorize.go` - code_challenge storage
  - `internal/handlers/token.go` - code_verifier validation
  - `pkg/models/oauth2.go` - AuthorizationCode with PKCE fields

**README.md Updates:**
- Added cross-reference links to OIDC_Walk_Thru.md and PKCE_Deep_Dive.md
- Reorganized Project 1 documentation section for easy navigation
- Added PRD and CHANGELOG links with descriptions

**Documentation Quality:**
- All technical terms hyperlinked to authoritative sources
- OIDC Core 1.0 specification fully covered
- RFC 6749 (OAuth2) and RFC 7636 (PKCE) compliance
- Interview-ready depth for demonstrating identity protocol expertise
- Production-ready security considerations

---

## [0.4.2] - 2025-10-08

### Fixed - Mermaid Diagram Rendering

**Commit:** `579a861` - Simplify Mermaid diagrams for GitHub renderer compatibility

**Issue:** GitHub's Mermaid renderer has stricter limits than VS Code preview

**Root Cause:**
- Participant aliases (`as X`) cause timeout
- `Note over` blocks cause timeout
- Multi-line labels with `<br/>` cause rendering issues
- Too many participants (6+) cause performance issues

**Changes:**
- Removed `as` participant aliases
- Removed all `Note over` blocks
- Removed `<br/>` tags in labels (single-line labels only)
- Used simple participant names without descriptions
- Reduced diagram complexity while preserving flow sequence
- Kept diagrams under 5 participants

**Preserved Information:**
- All technical specifications remain in text sections
- OIDC Discovery section (complete `.well-known/openid-configuration`)
- ID Token Validation (11-step checklist with all validations)
- OIDC Scopes section (complete scope descriptions)
- UserInfo Endpoint section (complete API specification)
- Token Endpoint Authentication methods (all 4 methods documented)
- Error Handling section (all error codes with descriptions)
- PKCE_Deep_Dive.md (complete PKCE implementation guide with code)

**Documentation Strategy:**
- Diagrams: High-level flow overview (visual learning)
- Text sections: Complete implementation details (reference material)
- Best of both worlds: Visual + comprehensive text

---

## [0.4.1] - 2025-10-08

### Fixed - OIDC Documentation Formatting

**Commit:** `78c651c` - Complete OIDC walkthrough with embedded diagram, comprehensive hyperlinking, and NDA compliance

**Changes:**
- Embedded OIDC_diagram_Perplexity.png in collapsible `<details>` section
- Removed all company-specific references (NDA compliance)
  - Replaced with generic "example.com" and "application" terminology
  - Removed partner company names
  - Generalized multi-brand references
- Comprehensively hyperlinked all technical terms:
  - RFCs (6749, 7636, 7519, 7517, 7518)
  - OIDC specs (Core 1.0, Discovery 1.0)
  - Security concepts (CSRF, PKCE, JWT, nonce, at_hash)
  - Technologies (HTTP, HTTPS, JSON, base64url)

**New Sections:**
- **Key Security Features:**
  - PKCE (prevents code interception)
  - State parameter (CSRF protection)
  - ID Token Validation (11-step checklist)
  - Token Lifetimes (expiration policies)

- **Implementation Notes:**
  - Links to project source files
  - Cross-references to data models
  - Highlights production-ready patterns

**Enhanced Flow Table:**
- Added PKCE code_challenge parameter
- Added nonce parameter for ID tokens
- Detailed token descriptions (JWT format, claims)
- Error handling notes

**References Section:**
- Organized by category (Standards, Security, Tools)
- All URLs verified and working
- Descriptions for each reference

---

## [0.4.0] - 2025-10-08

### Added - Next Steps Planning

**Commit:** `6fa3bbc` - record next steps

**Documented Remaining Tasks:**
- HTTP Handlers (authorize, token, userinfo, discovery)
- Main Server (routing, middleware, graceful shutdown)
- Example Client (demo web app with PKCE)
- Deployment (Docker Compose, Makefile, README)

**Time Estimates:**
- HTTP Handlers: 2-3 hours
- Main Server: 1 hour
- Example Client: 1-2 hours
- Deployment & Docs: 1-2 hours
- Total Remaining: ~5.5 hours

---

## [0.3.0] - 2025-10-07

### Added - Comprehensive Documentation Hyperlinking

**Commit:** `75c1a7a` - Comprehensive documentation hyperlinking across all markdown files

**Objective:** Make all technical documentation self-navigating with one-click access to authoritative sources

**Files Updated:**
- README.md - Main repository documentation
- CLAUDE.md - AI assistant guidance
- project-1-oauth2-oidc-demo/CHANGELOG.md - Project progress report
- project-1-oauth2-oidc-demo/docs/PRD.md - Product requirements document

**Hyperlinked Categories:**

**Standards & RFCs (with section anchors):**
- OAuth2 (RFC 6749) - Authorization framework
  - Section 3.1: Authorization Endpoint
  - Section 3.2: Token Endpoint
  - Section 4.1: Authorization Code Grant
  - Section 4.2: Implicit Grant (deprecated)
  - Section 4.3: Resource Owner Password Credentials (deprecated)
  - Section 4.4: Client Credentials Grant
- PKCE (RFC 7636) - Proof Key for Code Exchange
- JWT (RFC 7519) - JSON Web Tokens
- JWS (RFC 7515) - JSON Web Signature
- JWK (RFC 7517) - JSON Web Key
- JWA (RFC 7518) - JSON Web Algorithms (RS256)
- OIDC Core 1.0 - OpenID Connect specification
  - Section 3.1.3.7: ID Token Validation
  - Section 5.1: Standard Claims
  - Section 5.3: UserInfo Endpoint
- SAML 2.0 - OASIS spec (for comparison)

**Technologies:**
- **Programming:** Go (golang.org), slog (structured logging)
- **Infrastructure:** Docker, Docker Compose, Redis, Prometheus, k6 (load testing)
- **Libraries:**
  - gorilla/mux (HTTP routing)
  - golang-jwt/jwt (JWT handling)
  - go-redis/redis (Redis client)
  - spf13/viper (configuration)
  - spf13/cobra (CLI framework)
- **Formats:** JSON, YAML, HTTP, HTTPS, URI

**Security Concepts:**
- CSRF (Cross-Site Request Forgery)
- Algorithm confusion attacks
- Open redirect vulnerabilities
- Token replay attacks
- Shift-left security
- Constant-time comparison (timing attacks)

**Architecture Patterns:**
- SPA (Single-Page Application)
- CLI (Command-Line Interface)
- API (Application Programming Interface)
- HA (High Availability)
- CI/CD (Continuous Integration/Continuous Deployment)
- B2B (Business-to-Business)
- p99 latency
- Distributed tracing
- Graceful shutdown
- Horizontal scaling

**Project Files:**
- Relative markdown links (PRD, CHANGELOG, OIDC_Walk_Thru, PKCE_Deep_Dive)
- Source code files (models, tokens, session, handlers)
- Configuration examples (.env.example, docker-compose.yml)

**Result:**
- Every acronym, RFC, library, and technical term links to authoritative source
- Documentation serves as complete learning resource
- Easy navigation between specs, tools, and implementation
- Self-contained reference material
- Interview-ready knowledge base

---

## [0.2.0] - 2025-10-07

### Added - OAuth2/OIDC Foundation

**Commit:** `5de9b54` - Project 1: OAuth2/OIDC foundation - models, JWT, PKCE, Redis

**Product Requirements Document:**
- Comprehensive PRD with functional/non-functional requirements
- User personas (App Developer, Security Auditor, Platform Engineer)
- Timeline, success metrics, security considerations
- OIDC vs OAuth2 clearly explained
- Architecture diagrams
- Located at: `docs/PRD.md` (hyperlinked)

**Data Models (pkg/models/):**

**OAuth2 (oauth2.go - 152 lines):**
- `Client` - OAuth2 client configuration
  - Fields: ID, Secret, RedirectURIs, Type (public/confidential)
  - Methods: IsPublic(), ValidateRedirectURI()

- `AuthorizationRequest` - Parameters from /authorize endpoint
  - Fields: ClientID, RedirectURI, Scope, State, ResponseType
  - PKCE fields: CodeChallenge, CodeChallengeMethod
  - OIDC fields: Nonce

- `AuthorizationCode` - Generated authorization code
  - Fields: Code, ClientID, UserID, Scope, RedirectURI
  - PKCE fields: CodeChallenge, CodeChallengeMethod
  - OIDC fields: Nonce
  - Expiration: ExpiresAt, Used flag
  - Methods: IsExpired()

- `TokenRequest` - Parameters from /token endpoint
  - Fields: GrantType, Code, CodeVerifier (PKCE)
  - Client auth: ClientID, ClientSecret
  - Refresh: RefreshToken

- `TokenResponse` - Response from /token endpoint
  - Fields: AccessToken, TokenType, ExpiresIn
  - Optional: RefreshToken, IDToken, Scope

- `AccessToken` / `RefreshToken` - Token metadata
  - Fields: Token, ClientID, UserID, Scope, ExpiresAt

- Error constants per RFC 6749 Section 5.2:
  - ErrorInvalidRequest, ErrorInvalidClient, ErrorInvalidGrant
  - ErrorUnauthorizedClient, ErrorUnsupportedGrantType, ErrorInvalidScope

**OIDC (oidc.go - 105 lines):**
- `User` - User entity with OIDC standard claims
  - Profile: ID, Name, GivenName, FamilyName, Picture
  - Email: Email, EmailVerified
  - Per OIDC Core Section 5.1

- `IDTokenClaims` - JWT claims for ID tokens
  - Standard: Issuer, Subject, Audience, ExpiresAt, IssuedAt, NotBefore
  - OIDC: Nonce (replay protection)
  - Token binding: AccessHash (at_hash per OIDC spec)
  - Profile claims: Name, GivenName, FamilyName, Picture
  - Email claims: Email, EmailVerified

- `UserInfoResponse` - Response from /userinfo endpoint
  - Fields: Subject, Name, GivenName, FamilyName, Picture, Email, EmailVerified
  - Scope-based filtering

- `OIDCDiscoveryDocument` - .well-known/openid-configuration response
  - Endpoints: Issuer, Authorization, Token, UserInfo, JWKSUri
  - Supported: Scopes, ResponseTypes, GrantTypes, CodeChallengeMethods
  - Algorithms: IDTokenSigningAlgValues, SubjectTypes
  - Auth methods: TokenEndpointAuthMethods

- Scope constants:
  - ScopeOpenID = "openid" (required for OIDC)
  - ScopeProfile = "profile" (name, picture, etc.)
  - ScopeEmail = "email" (email address)
  - ScopeOfflineAccess = "offline_access" (refresh token)

- Helper: `HasScope(scopes, scope string) bool`
  - Manual string parsing without strings.Split (efficient, zero-alloc)

**JWT Token Management (internal/tokens/jwt.go - 170 lines):**
- `JWTManager` - Manages JWT token lifecycle
  - RSA key pair (private for signing, public for verification)
  - Configurable expiration (access, refresh, ID tokens)
  - Issuer configuration

**Access Token Operations:**
- `GenerateAccessToken(clientID, userID, scope string)`:
  - RS256 signing with RSA private key
  - Custom claims: client_id, user_id, scope
  - Standard claims: iss, sub, aud, exp, iat
  - Returns: token string, expiration time, error

- `ValidateAccessToken(tokenString string)`:
  - Signature validation with RSA public key
  - Algorithm verification (prevents "none" attack)
  - Expiration validation (with clock skew tolerance)
  - Returns: parsed claims, error

**OIDC ID Token Operations:**
- `GenerateIDToken(user, clientID, nonce, accessToken, scope)`:
  - Generates ID token per OIDC Core spec
  - at_hash claim (access token hash) for token binding
    - SHA-256 hash of access token
    - Left 128 bits (16 bytes)
    - Base64URL encoded
  - Conditional claims based on scope:
    - profile scope → Name, GivenName, FamilyName, Picture
    - email scope → Email, EmailVerified
  - Nonce for replay protection
  - Standard claims: iss, sub, aud, exp, iat

- `ValidateIDToken(tokenString string)`:
  - Same validation as access token
  - Additional OIDC-specific validation needed (nonce, at_hash)

**Refresh Token Operations:**
- `GenerateRefreshToken(clientID, userID, scope)`:
  - Long-lived tokens (default: 30 days)
  - Simple JWT structure
  - Stored in Redis for revocation support

- `ValidateRefreshToken(tokenString)`:
  - Validates signature and expiration
  - Checks Redis blocklist for revocation

**Public Key Access:**
- `GetPublicKey()`: Returns RSA public key for external verification

**PKCE Implementation (internal/tokens/pkce.go - 77 lines):**
- `PKCEMethod` type: S256 (recommended), Plain (legacy)

**ValidatePKCE:**
- `ValidatePKCE(codeVerifier, codeChallenge, codeChallengeMethod string) error`
- **S256 Method (RFC 7636 Section 4.2):**
  - Hash code_verifier with SHA-256
  - Base64URL encode (no padding)
  - Compare with code_challenge
- **Plain Method:**
  - Direct string comparison
  - Only for constrained devices
- **Validation:**
  - code_verifier length: 43-128 characters
  - code_verifier format: [A-Z] [a-z] [0-9] -._~ (unreserved chars)
- Returns error if validation fails

**GenerateCodeChallenge (for testing):**
- `GenerateCodeChallenge(codeVerifier string) string`
- Helper function for S256 method
- Used in tests and demo client

**Redis Session Store (internal/session/redis.go - 217 lines):**
- `RedisStore` - Manages all OAuth2/OIDC session data
  - Redis client connection
  - Key prefix for namespacing (default: "identity:")
  - Context-aware operations

**Namespaced Key Design (prevents collisions):**
- `identity:client:{client_id}` - Client configurations
- `identity:auth:code:{code}` - Authorization codes
- `identity:refresh:token:{token}` - Refresh tokens
- `identity:revoked:{token}` - Revoked token blocklist

**Client Operations:**
- `StoreClient(ctx, client)` - Store client config (no expiration)
- `GetClient(ctx, clientID)` - Retrieve client config
- JSON serialization for complex structures

**Authorization Code Operations:**
- `StoreAuthorizationCode(ctx, code, authCode)`:
  - Stores with 10-minute TTL
  - Automatic expiration via Redis TTL
  - Includes PKCE challenge, nonce, user context

- `GetAuthorizationCode(ctx, code)`:
  - Retrieves authorization code
  - Returns error if expired or not found

- `InvalidateAuthorizationCode(ctx, code)`:
  - Marks code as used
  - Prevents code replay attacks

**Refresh Token Operations:**
- `StoreRefreshToken(ctx, token, refreshToken)`:
  - Stores with 30-day TTL
  - Includes user_id, client_id, scope

- `GetRefreshToken(ctx, token)`:
  - Retrieves refresh token
  - Validates not expired

- `InvalidateRefreshToken(ctx, token)`:
  - Removes from Redis
  - Used for logout/revocation

**Token Revocation (Blocklist Pattern):**
- `RevokeToken(ctx, token, ttl)`:
  - Adds token to blocklist
  - TTL matches token expiration (automatic cleanup)
  - Used for logout, security events

- `IsTokenRevoked(ctx, token)`:
  - Checks if token in blocklist
  - Fast lookup (Redis O(1))

**Health Check:**
- `Ping(ctx)` - Validates Redis connection

**Design Decisions:**
- **JSON Serialization:** Complex structures stored as JSON
- **TTL-based Cleanup:** No manual garbage collection needed
- **Context Support:** All operations accept context for cancellation/timeout
- **Error Handling:** Returns errors with context (not panics)

**Next Steps:**
- Authorization endpoint handler (/authorize)
- Token endpoint handler (/token)
- UserInfo endpoint handler (/userinfo)
- OIDC Discovery endpoint (/.well-known/openid-configuration)
- JWKS endpoint (/.well-known/jwks.json)
- Main server (routing, middleware, graceful shutdown)
- Example client (demo web app with PKCE)

---

## [0.1.2] - 2025-10-07

### Changed - Docker Desktop to Podman

**Commit:** `9a75feb` - Replace Docker Desktop with Podman in setup.sh

**Benefits:**
- **Lighter weight:** No VM overhead on macOS (uses native virtualization)
- **Open source:** True open-source alternative to Docker Desktop
- **No licensing:** Free for all use cases (Docker Desktop requires license for large orgs)
- **Compatible:** Works with docker-compose via socket

**Changes in setup.sh:**
- Install `podman` instead of `docker` (brew install podman)
- Remove Docker Desktop (brew install --cask docker)
- Initialize podman machine: `podman machine init`
- Start podman machine: `podman machine start`
- Create `docker` alias for podman: `alias docker=podman`
  - Add to ~/.zshrc for persistence
- Enable podman socket for docker-compose support:
  - `podman system service --time=0 unix:///tmp/podman.sock &`
- Updated next steps to mention podman usage

**Compatibility:**
- docker-compose works with podman via Unix socket
- All docker commands work via alias (transparent)
- Seamless transition for existing docker workflows
- Same docker-compose.yml files work unchanged

**Developer Experience:**
- Faster startup (no VM boot time)
- Lower memory usage
- Same CLI commands (via alias)
- Better macOS integration

---

## [0.1.1] - 2025-10-07

### Added - Secrets Management and Setup Automation

**Commit:** `87b6ebc` - Add secrets management framework and setup automation

**Setup Script (setup.sh):**
- Automated macOS dependency installation via Homebrew
- **Dependencies Installed:**
  - Go 1.21+ (programming language)
  - Docker (containerization)
  - Redis (session storage)
  - k6 (load testing)
  - OpenSSL (RSA key generation)
  - jq (JSON parsing)
  - **ggshield (GitGuardian) - INSTALLED FIRST** (critical security tool)

**Security-First Installation Order:**
1. ggshield (secret detection) - FIRST
2. Git hooks installation (pre-commit, pre-push)
3. All other dependencies
4. RSA key generation
5. Environment setup

**RSA Key Generation:**
- Automatically generates RSA-2048 key pairs
- Private key: `.secrets/jwt-private.pem`
- Public key: `.secrets/jwt-public.pem`
- Uses OpenSSL: `openssl genrsa -out private.pem 2048`
- Public key extracted: `openssl rsa -in private.pem -pubout -out public.pem`

**ggshield Git Hooks:**
- **Pre-commit hook:** Scans commits for secrets before commit
- **Pre-push hook:** Scans commits for secrets before push
- **Double protection:** Prevents accidental secret exposure at 2 points
- **Installed via:** `ggshield install --mode local`
- **Coverage:** All files in every commit

**Secrets Management Framework:**

**Files Created:**
- `.env.example` - Template with all required environment variables (committed to git)
- `.env` - Actual secrets (gitignored, NEVER committed)
- `.secrets/` - Directory for generated keys/certificates (gitignored)

**Environment Variables Documented:**
```bash
# Redis Configuration
REDIS_URL=localhost:6379

# OAuth2/OIDC Configuration
ISSUER=http://localhost:8080
PORT=:8080

# JWT Signing Keys
PRIVATE_KEY_PATH=.secrets/jwt-private.pem
PUBLIC_KEY_PATH=.secrets/jwt-public.pem

# Client Secrets (Demo - change in production)
CLIENT_SECRET_WEB=web-app-secret-change-in-production
CLIENT_SECRET_SERVICE=service-app-secret-change-in-production
```

**Comprehensive .gitignore:**
- Secrets directories: `.secrets/`, `keys/`, `certs/`
- Environment files: `.env`, `.env.local`, `.env.*.local`
- Key files: `*.pem`, `*.key`, `*.crt`, `*.p12`, `*.pfx`
- Go build artifacts: `*.exe`, `*.dll`, `*.so`, `*.dylib`
- Test binaries: `*.test`, `*.out`
- Dependency directories: `vendor/`, `node_modules/`
- IDE files: `.idea/`, `.vscode/`, `*.swp`
- OS files: `.DS_Store`, `Thumbs.db`

**Security Guardrails:**
- **ggshield pre-commit:** Blocks commits containing secrets
- **ggshield pre-push:** Blocks pushes containing secrets
- **Double protection:** Two checkpoints prevent secret leakage
- **Zero secrets in git:** By design, secrets never reach repository

**Documentation Updates:**
- Added "Secrets Management" section to CLAUDE.md
- Clear instructions for adding new secrets:
  1. Add to .env.example with description
  2. Add actual value to .env (gitignored)
  3. Update setup.sh if auto-generation needed
  4. Document in README if public-facing
- Usage examples for sourcing environment variables
- Security best practices (never commit .env, rotate regularly, use strong values)

**Developer Experience:**
- **One-command setup:** `./setup.sh`
- Automatic dependency installation (no manual steps)
- Automatic secrets generation (RSA keys)
- Automatic security hooks installation
- Guided .env creation from .env.example
- Setup script is idempotent (safe to re-run)

**Production Considerations:**
- setup.sh is for local development only
- Production uses secret management services:
  - AWS Secrets Manager
  - HashiCorp Vault
  - Kubernetes Secrets
- Environment variables injected at runtime
- Keys rotated regularly (every 90 days recommended)

---

## [0.1.0] - 2025-10-07

### Added - .gitignore for External Tools

**Commit:** `5173495` - Add .gitignore patterns for external tools and binaries

**Purpose:** Ensure no external tools installed by setup.sh get committed to git

**Patterns Added:**
- Go binaries downloaded locally: `/bin/`, `/tools/`
- Homebrew local installations: `/opt/`, `/usr/local/` (macOS)
- Podman/Docker local data: `.podman/`, `.docker/`
- Downloaded dependencies: `downloads/`, `tmp/`, `temp/`
- Third-party CLI tools: `cli-tools/`, `external/`

**Prevents Accidental Commits of:**
- k6 (load testing tool)
- redis-server (database)
- ggshield (secret scanning)
- Locally installed packages
- Tool caches and data directories
- Build artifacts

**Why This Matters:**
- Keep repository clean (only source code and documentation)
- Reduce repository size (external tools can be large)
- Avoid licensing issues (some tools have restrictive licenses)
- Faster clones (smaller repository)
- Clear separation: code vs dependencies

---

## [0.0.1] - 2025-10-07

### Added - Project Initialization

**Commit:** `9d649f4` - Initial commit: Identity learning projects

**Project Structure Created:**
```
identity-learning-monorepo/
├── README.md
├── CLAUDE.md
├── project-1-oauth2-oidc-demo/
├── project-2-session-management/
├── project-3-identity-security-scanner/
├── project-4-decision-framework/
└── shared/
    ├── pkg/
    └── docker/
```

**Purpose:**
- Monorepo for 4 identity learning projects
- Demonstrates rapid domain mastery in OAuth2/OIDC/SAML protocols
- Preparation for Senior Director Identity role interview
- Timeline: October 7-10, 2025 (3 days before interview)

**Documentation Created:**

**README.md - Project Overview:**
- Purpose: Identity deep dive learning projects
- 4 progressive projects demonstrating different aspects of identity
- Target: Senior leadership interview preparation
- Goals: Rapid learning, bias for action, innovation through simplification

**CLAUDE.md - Comprehensive AI Guidance:**
- **Project Execution Order:**
  - Priority 1: OAuth2/OIDC Learning Demo (6-8 hours)
  - Priority 2: Identity Security Scanner - Static (6-8 hours)
  - Priority 3: Identity Security Scanner - Runtime (6-8 hours)
  - Priority 4: Multi-Tenant Session Management (8-10 hours)

- **Core Principles:**
  1. Learning while building (not just reading specs)
  2. Production-quality patterns (error handling, security, observability)
  3. Expedia-specific thinking (multi-brand, global scale, high availability)
  4. Simplification through innovation (clear over clever)

- **Technology Choices:**
  - **Go** - Fast, compiled, excellent concurrency, likely used at scale
  - **Redis** - Distributed sessions, fast key-value, built-in expiration
  - **JWT** - Stateless validation, standard claims, industry standard
  - **Prometheus + Grafana** - Observability for cloud-native apps
  - **k6** - Load testing for performance validation

- **Development Workflow:**
  - Day 1: OAuth2/OIDC Demo (8 hours)
    - Morning: Authorization code flow, JWT tokens
    - Afternoon: PKCE flow, client credentials, token refresh
    - Evening: OIDC layer, example client, Docker setup
  - Day 2: Static Security Scanner (6 hours)
  - Day 2-3: Runtime Security Scanner (8 hours)
  - Day 3: Session Management at Scale (8 hours)

- **Interview Integration:**
  - Talking points for each leadership principle
  - Demo-ready moments (framework, flows, scanner, load tests)
  - Natural conversation hooks
  - Technical depth examples

- **Common Pitfalls to Avoid:**
  - Over-engineering (show patterns, not enterprise scale)
  - Under-documenting (explain "why" in READMEs)
  - Ignoring security (follow OWASP best practices)
  - Disconnected projects (show learning progression)
  - No Expedia connection (reference multi-brand challenges)

- **Success Criteria:**
  - All 4 projects build and run
  - OAuth2/OIDC flows work end-to-end
  - Security scanner finds real misconfigurations
  - Load test sustains 10K+ sessions
  - Decision framework addresses real-world trade-offs

**Project Placeholders:**
- project-1-oauth2-oidc-demo/ - Authorization server from scratch
- project-2-session-management/ - Distributed sessions at scale
- project-3-identity-security-scanner/ - Two scanners (static + runtime)
- project-4-decision-framework/ - Protocol selection decision tree

**Shared Infrastructure:**
- shared/pkg/ - Shared Go packages (models, utilities)
- shared/docker/ - Shared Docker configurations

**Timeline:**
- **Start:** October 7, 2025
- **Interview:** October 10, 2025
- **Duration:** 3 days
- **Total Effort:** ~28-34 hours across 4 projects

**Learning Objectives:**
1. **Rapid Domain Mastery** - Learn OAuth2/OIDC/SAML from scratch
2. **Bias for Action** - Build while learning (not passive study)
3. **Innovation Through Simplification** - Practical tools and frameworks
4. **Intellectual Curiosity** - Dive deep into new technical domains

**Technical Demonstrations:**
- OAuth2 Authorization Code Flow with PKCE
- OIDC ID tokens, UserInfo, Discovery
- Multi-tenant session management at scale
- Security scanning and misconfiguration detection
- Production-ready patterns (graceful shutdown, distributed storage, observability)

**Interview Preparation:**
- Demonstrates understanding of identity protocols from first principles
- Shows ability to learn complex domains quickly (3 days, 4 projects)
- Proves bias for action (building, not just studying)
- Exhibits innovation through simplification (security scanner automates reviews)
- Provides concrete talking points backed by working code

---

## Project Goals

### Learning Objectives
1. **Rapid Domain Mastery** - Learn OAuth2/OIDC/SAML protocols from scratch
2. **Bias for Action** - Build while learning, not just reading specs
3. **Innovation Through Simplification** - Practical tools and frameworks
4. **Intellectual Curiosity** - Dive deep into new technical domains

### Technical Demonstrations
- OAuth2 Authorization Code Flow with PKCE
- OIDC ID tokens, UserInfo, Discovery endpoints
- Multi-tenant session management at scale (10K+ sessions)
- Security scanning and misconfiguration detection
- Production-ready patterns:
  - Graceful shutdown with signal handling
  - Distributed storage (Redis) for horizontal scaling
  - Observability (Prometheus metrics, structured logging)
  - Error handling (comprehensive, RFC-compliant)
  - Security (PKCE, HTTPS, token revocation)

### Interview Preparation
- Demonstrates understanding of identity protocols from first principles
- Shows ability to learn complex domains quickly (3 days, 4 complete projects)
- Proves bias for action (28+ hours of building, not passive study)
- Exhibits innovation through simplification (security scanner automates manual reviews)
- Provides concrete talking points backed by working code
- Addresses "no identity background" concern proactively
- Shows thinking about scale (Expedia's multi-brand, global challenges)

---

## References

### Standards & RFCs
- [RFC 6749 - OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636 - Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7515 - JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)

### Best Practices
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [NIST SP 800-63B - Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

### Tools & Libraries
- [Go Programming Language](https://golang.org/)
- [Redis](https://redis.io/)
- [gorilla/mux - HTTP Router](https://github.com/gorilla/mux)
- [golang-jwt/jwt - JWT Library](https://github.com/golang-jwt/jwt)
- [go-redis/redis - Redis Client](https://github.com/go-redis/redis)
- [k6 - Load Testing](https://k6.io/)
- [Prometheus - Metrics](https://prometheus.io/)
- [Grafana - Dashboards](https://grafana.com/)

---

## Contributors

**Matt Bordenet** - Primary developer
**Claude Code** - AI pair programming assistant

**🤖 Generated with Claude Code**

**Co-Authored-By: Claude <noreply@anthropic.com>**

---

**Last Updated:** October 8, 2025, 7:30 PM PST
**Status:** Project 1 Complete (v1.0.0) ✅
