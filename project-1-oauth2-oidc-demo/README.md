# OAuth2/OIDC Authorization Server

A complete OAuth2 and OpenID Connect (OIDC) authorization server implementation in Go.

## Features

### OAuth2 Flows
- **Authorization Code Flow** - Most secure flow for web applications
- **Authorization Code Flow with PKCE** - Required for mobile and single-page apps
- **Client Credentials Flow** - Service-to-service authentication
- **Refresh Token Flow** - Long-lived sessions

### OIDC (OpenID Connect)
- **ID Tokens** - JWT-based identity tokens with standard claims
- **UserInfo Endpoint** - Retrieve user profile information
- **Discovery Endpoint** - `.well-known/openid-configuration` for dynamic client configuration
- **JWKS Endpoint** - Public key distribution for token validation

### Security Features
- **PKCE (RFC 7636)** - Prevents authorization code interception attacks
- **State Parameter** - CSRF protection for authorization flow
- **Nonce Parameter** - Replay protection for ID tokens
- **Token Hash (at_hash)** - Binds ID token to access token
- **JWT Signing (RS256)** - RSA-2048 asymmetric signing
- **Token Revocation** - Blocklist pattern with automatic expiration
- **Scope-based Authorization** - Fine-grained permissions

### Architecture
- **Stateless Tokens** - JWT tokens for horizontal scalability
- **Distributed Session Storage** - Redis for authorization codes and refresh tokens
- **Multi-tenant Ready** - Separate keys and scopes per client
- **Graceful Shutdown** - Proper cleanup on SIGINT/SIGTERM

## 🚀 Getting Started

The easiest way to run the entire stack (Authorization Server, Redis, and Demo Client) is using Podman Compose:

```bash
podman-compose up
```

Alternatively, you can run components individually:

### Prerequisites
- Go 1.21+
- Redis 7+ (or Podman)
- OpenSSL (for key generation)

### 1. Generate RSA Keys

```bash
make generate-keys
```

This creates `keys/private.pem` and `keys/public.pem` for JWT signing.

### 2. Start Redis

```bash
make redis-start
```

Or use your own Redis instance on `localhost:6379`.

### 3. Run Authorization Server

```bash
make run-server
```

Server starts on `http://localhost:8080`.

### 4. Run Demo Client (Optional)

In a separate terminal:

```bash
make run-client
```

Client starts on `http://localhost:3000`. Visit in your browser to see the complete OAuth2/OIDC flow.

## Usage

### Demo Client Flow

1. Visit `http://localhost:3000`
2. Click "Login with Authorization Server"
3. Server redirects to authorization endpoint with PKCE parameters
4. (In production: user would see login page here)
5. Server returns authorization code
6. Client exchanges code for tokens (access, ID, refresh)
7. Client fetches UserInfo with access token
8. Tokens and user profile displayed

### Direct API Usage

#### 1. Authorization Endpoint

**GET** `/authorize`

Start the authorization flow:

```
http://localhost:8080/authorize?
  response_type=code&
  client_id=web-app&
  redirect_uri=http://localhost:3000/callback&
  scope=openid%20profile%20email&
  state=abc123&
  nonce=xyz789&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256
```

**Parameters:**
- `response_type` - Always `code` for authorization code flow
- `client_id` - Client identifier (e.g., `web-app`, `mobile-app`)
- `redirect_uri` - Where to send authorization code (must be registered)
- `scope` - Space-separated scopes (e.g., `openid profile email`)
- `state` - CSRF protection token (client-generated)
- `nonce` - Replay protection for ID token (client-generated)
- `code_challenge` - PKCE code challenge (Base64URL(SHA256(code_verifier)))
- `code_challenge_method` - Always `S256` (SHA-256)

**Response:**
Redirects to `redirect_uri` with authorization code:
```
http://localhost:3000/callback?code=abc123&state=abc123
```

#### 2. Token Endpoint

**POST** `/oauth2/token`

Exchange authorization code for tokens:

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=abc123" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=web-app" \
  -d "client_secret=web-app-secret-change-in-production" \
  -d "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "openid profile email"
}
```

#### 3. UserInfo Endpoint

**GET** `/userinfo`

Retrieve user profile with access token:

```bash
curl -X GET http://localhost:8080/userinfo \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Response:**
```json
{
  "sub": "alice",
  "name": "Alice Smith",
  "given_name": "Alice",
  "family_name": "Smith",
  "email": "alice@example.com",
  "email_verified": true
}
```

#### 4. OIDC Discovery

**GET** `/.well-known/openid-configuration`

```bash
curl http://localhost:8080/.well-known/openid-configuration
```

**Response:**
```json
{
  "issuer": "http://localhost:8080",
  "authorization_endpoint": "http://localhost:8080/authorize",
  "token_endpoint": "http://localhost:8080/oauth2/token",
  "userinfo_endpoint": "http://localhost:8080/userinfo",
  "jwks_uri": "http://localhost:8080/.well-known/jwks.json",
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "code_challenge_methods_supported": ["S256", "plain"]
}
```

#### 5. JWKS (Public Keys)

**GET** `/.well-known/jwks.json`

```bash
curl http://localhost:8080/.well-known/jwks.json
```

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "default",
      "n": "xGOr-H7A...",
      "e": "AQAB"
    }
  ]
}
```

## Demo Clients

Three pre-configured clients are seeded on server startup:

### 1. web-app (Confidential Client)
- **Client ID:** `web-app`
- **Client Secret:** `web-app-secret-change-in-production`
- **Type:** Confidential (has client secret)
- **Redirect URIs:** `http://localhost:3000/callback`
- **Scopes:** `openid`, `profile`, `email`, `offline_access`

### 2. mobile-app (Public Client)
- **Client ID:** `mobile-app`
- **Type:** Public (no client secret, PKCE required)
- **Redirect URIs:** `myapp://callback`
- **Scopes:** `openid`, `profile`, `email`, `offline_access`

### 3. service-app (Confidential Client)
- **Client ID:** `service-app`
- **Client Secret:** `service-app-secret-change-in-production`
- **Type:** Confidential
- **Grant Types:** `client_credentials` only (no user context)
- **Scopes:** `api.read`, `api.write`

## Demo Users

Three demo users are available for testing:

| User ID | Email | Password | Name |
|---------|-------|----------|------|
| alice | alice@example.com | (auto-login in demo) | Alice Smith |
| bob | bob@example.com | (auto-login in demo) | Bob Johnson |
| charlie | charlie@example.com | (auto-login in demo) | Charlie Brown |

## OAuth2 Scopes

| Scope | Description |
|-------|-------------|
| `openid` | Required for OIDC - returns ID token |
| `profile` | User profile claims (name, given_name, family_name, picture) |
| `email` | Email address and verification status |
| `offline_access` | Request refresh token for long-lived sessions |
| `api.read` | Read access to protected APIs (service-app only) |
| `api.write` | Write access to protected APIs (service-app only) |

## Token Lifetimes

| Token Type | Default TTL | Configurable |
|------------|-------------|--------------|
| Authorization Code | 10 minutes | Yes (in code) |
| Access Token | 15 minutes | Yes (JWT manager) |
| ID Token | 15 minutes | Yes (JWT manager) |
| Refresh Token | 30 days | Yes (JWT manager) |

## Architecture

```
┌─────────────────┐
│   Demo Client   │
│  (Port 3000)    │
└────────┬────────┘
         │
         │ 1. GET /authorize (redirect)
         │ 2. POST /oauth2/token
         │ 3. GET /userinfo
         │
         ▼
┌─────────────────────────────────────┐
│  Authorization Server (Port 8080)   │
│                                     │
│  ┌──────────────────────────────┐  │
│  │  HTTP Handlers               │  │
│  │  - /authorize                │  │
│  │  - /oauth2/token            │  │
│  │  - /userinfo                │  │
│  │  - /.well-known/*           │  │
│  └──────────────────────────────┘  │
│               │                     │
│  ┌────────────┴──────────────────┐ │
│  │  Core Services               │ │
│  │  - JWT Manager (RS256)       │ │
│  │  - PKCE Validator            │ │
│  │  - Session Store (Redis)     │ │
│  │  - User Store (In-memory)    │ │
│  └──────────────────────────────┘ │
└──────────────┬──────────────────────┘
               │
               ▼
        ┌────────────┐
        │   Redis    │
        │ (Port 6379)│
        └────────────┘
```

## Project Structure

```
project-1-oauth2-oidc-demo/
├── cmd/
│   ├── server/          # Authorization server
│   │   └── main.go
│   └── client/          # Demo client
│       └── main.go
├── internal/
│   ├── handlers/        # HTTP request handlers
│   │   ├── authorize.go
│   │   ├── token.go
│   │   ├── userinfo.go
│   │   └── discovery.go
│   ├── session/         # Redis session storage
│   │   └── redis.go
│   ├── store/          # Data stores
│   │   └── user_store.go
│   └── tokens/         # JWT and PKCE
│       ├── jwt.go
│       └── pkce.go
├── pkg/
│   └── models/         # Data models
│       ├── oauth2.go
│       └── oidc.go
├── docs/               # Documentation
│   ├── PRD.md
│   ├── OIDC_Walk_Thru.md
│   └── PKCE_Deep_Dive.md
├── keys/               # RSA keys (git-ignored)
├── Makefile
├── compose.yaml
└── README.md
```

## Development

### Running Tests

```bash
make test
```

### Cleaning Up

Remove generated keys and temporary files:

```bash
make clean
```

Stop Redis:

```bash
make redis-stop
```

## Podman Compose

Run entire stack with one command:

```bash
podman-compose up
```

This starts:
- Redis on port 6379
- Authorization server on port 8080
- Demo client on port 3000

## Security Considerations

### Production Checklist

- [ ] Change all client secrets from demo values
- [ ] Use environment variables for secrets (never commit)
- [ ] Enable HTTPS/TLS (Let's Encrypt, AWS ACM, etc.)
- [ ] Rotate RSA keys regularly
- [ ] Implement rate limiting on token endpoint
- [ ] Add brute-force protection on login
- [ ] Use production-grade user store (PostgreSQL, MySQL)
- [ ] Enable Redis authentication and encryption
- [ ] Implement consent screen for authorization
- [ ] Add logging and monitoring (Prometheus, Grafana)
- [ ] Configure CORS policies
- [ ] Add input validation and sanitization
- [ ] Implement account lockout after failed attempts
- [ ] Enable secure cookie flags (HttpOnly, Secure, SameSite)

### Current Demo Limitations

⚠️ **This is a learning/demo project. DO NOT use in production without hardening.**

- Auto-login (no real authentication; demo server auto-authenticates as Alice)
- In-memory user store (lost on restart)
- HTTP instead of HTTPS
- Hardcoded client secrets
- No consent screen
- No rate limiting
- Minimal error handling
- No audit logging

## Documentation & References

### Project-Specific Documentation
- **[Product Requirements Document (PRD)](docs/PRD.md)** - High-level requirements and architecture
- **[OIDC Authorization Code Flow Walkthrough](docs/OIDC_Walk_Thru.md)** - Step-by-step OIDC flow explanation
- **[PKCE Deep Dive](docs/PKCE_Deep_Dive.md)** - PKCE attack scenarios and implementation

### RFCs and Standards
- [RFC 6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [RFC 7636 - OAuth 2.0 PKCE](https://tools.ietf.org/html/rfc7636)
- [RFC 7519 - JSON Web Tokens (JWT)](https://tools.ietf.org/html/rfc7519)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)

### Best Practices
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OAuth 2.0 Security Best Current Practice](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)
- [NIST SP 800-63B - Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

## License

MIT License - See LICENSE file for details.

## Contributing

Feedback and suggestions are welcome! Please feel free to open an issue.
