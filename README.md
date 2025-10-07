# Identity Deep Dive

> **Learning identity protocols and patterns through implementation**

A hands-on exploration of OAuth2, OIDC, SAML, and identity security - built in 3 days to demonstrate rapid domain mastery for senior engineering leadership roles.

## 🎯 Learning Objectives

This monorepo demonstrates:
- **Rapid domain learning** - entering identity/access management from engineering leadership background
- **Bias for action** - implementing protocols from specs, not just reading documentation
- **Innovation through simplification** - building practical tools that solve real problems
- **Production thinking** - scale, security, and operational excellence from day one

## 📦 Projects

### 1. OAuth2/OIDC Authorization Server
**Status**: ✅ Complete | **Time**: 8 hours | **Language**: Go

A from-scratch implementation of OAuth2 and OpenID Connect authorization server supporting:
- Authorization Code Flow (most secure for web apps)
- PKCE Extension (mobile/SPA security)
- Client Credentials Flow (service-to-service)
- Token Refresh (long-lived sessions)
- OIDC ID Tokens + UserInfo endpoint

**Why this matters**: Deep understanding of identity protocols (OAuth2, OIDC) by implementing the spec, not just using libraries.

[📁 View Project](./project-1-oauth2-oidc-demo/) | [📖 Detailed README](./project-1-oauth2-oidc-demo/README.md)

---

### 2. Identity Security Scanner (Static Analysis)
**Status**: ✅ Complete | **Time**: 6 hours | **Language**: Go

CLI tool to audit OAuth2/OIDC/SAML configurations for security misconfigurations:
- Weak client secrets and key management issues
- Overly permissive scopes
- Insecure redirect URIs
- JWT token vulnerabilities
- SAML signature/encryption issues

**Why this matters**: Applies proven security scanner pattern (from Stash Financial) to identity domain - innovation through simplification.

[📁 View Project](./project-3-identity-security-scanner/) | [📖 Detailed README](./project-3-identity-security-scanner/README.md)

---

### 3. Identity Security Scanner (Runtime Analysis)
**Status**: ✅ Complete | **Time**: 6 hours | **Language**: Go

Runtime security testing for live OAuth2/OIDC flows:
- CSRF attack detection
- Token replay testing
- Authorization code interception
- Redirect URI manipulation
- Algorithm confusion attacks

**Why this matters**: Defense in depth - static config analysis + runtime flow testing catches issues in code review AND production.

[📁 View Project](./project-3b-runtime-identity-scanner/) | [📖 Detailed README](./project-3b-runtime-identity-scanner/README.md)

---

### 4. Multi-Tenant Session Management
**Status**: ✅ Complete | **Time**: 10 hours | **Language**: Go

Distributed session management service with JWT tokens and Redis:
- Multi-tenant session isolation (multi-brand architecture)
- Stateless JWT validation (fast path)
- Redis-backed revocation (security path)
- Token refresh with sliding sessions
- Load tested to 10K+ concurrent sessions

**Why this matters**: Demonstrates thinking about identity at scale - global, multi-brand, high-availability requirements.

[📁 View Project](./project-2-session-management/) | [📖 Detailed README](./project-2-session-management/README.md)

---

## 🚀 Quick Start

### Prerequisites
- Go 1.21+
- Docker & Docker Compose
- Redis (via Docker)

### Run All Projects
```bash
# Clone the repository
git clone https://github.com/bordenet/identity-deep-dive.git
cd identity-deep-dive

# Run all projects with Docker Compose
docker-compose up

# Or run individual projects
cd project-1-oauth2-oidc-demo && make run
cd project-2-session-management && make run
cd project-3-identity-security-scanner && make scan
cd project-3b-runtime-identity-scanner && make test
```

## 📚 Learning Journey

### Day 1: OAuth2/OIDC Fundamentals
Started by implementing OAuth2 authorization server from RFC 6749 spec:
- **Hour 1-3**: Authorization code flow, JWT token generation
- **Hour 4-6**: PKCE, client credentials, token refresh
- **Hour 7-8**: OIDC layer (ID tokens, UserInfo), Docker setup

**Key insight**: OIDC adds identity layer to OAuth2's authorization framework - understanding this distinction is critical.

### Day 2: Security Deep Dive
Built security scanning tools to internalize identity vulnerabilities:
- **Hour 1-4**: Static config scanner for OAuth2/OIDC/SAML misconfigurations
- **Hour 5-6**: Remediation engine, CI/CD integration
- **Hour 7-9**: Runtime flow analyzer for attack simulation

**Key insight**: Security patterns from previous roles (vulnerability scanners, compliance) apply directly to identity domain.

### Day 3: Scale & Operations
Implemented session management thinking about multi-brand, global-scale requirements:
- **Hour 1-4**: Session service with Redis, multi-tenant isolation
- **Hour 5-8**: Load testing (10K concurrent sessions), observability
- **Hour 9-10**: Documentation, architecture diagrams

**Key insight**: Identity at scale = distributed systems problem. JWT for speed, Redis for consistency.

## 🎓 What I Learned

### Protocol Trade-offs
- **OAuth2 vs OIDC**: Authorization vs Authentication - different problems, complementary solutions
- **SAML vs OAuth2**: Enterprise partnerships vs modern apps - both have valid use cases
- **JWT Validation**: Stateless (fast) vs stateful (revocable) - need both approaches

### Security Considerations
- **PKCE is non-negotiable** for mobile/SPA apps - prevents authorization code interception
- **State parameter prevents CSRF** - must be cryptographically random, validated on callback
- **Redirect URI validation is critical** - wildcard URIs = open redirect vulnerability
- **Token lifetime trade-offs** - short access tokens (15min), longer refresh tokens (30d)

### Scale Thinking
- **Multi-tenant isolation** requires separate signing keys per tenant
- **Global deployments** need Redis replication, token validation must work offline
- **Observability is essential** - can't optimize what you don't measure

## 🏗️ Architecture Highlights

### OAuth2/OIDC Server
```
┌─────────────┐      ┌──────────────────┐      ┌─────────────┐
│   Client    │─────▶│  Authorization   │─────▶│    Redis    │
│             │      │     Server       │      │   (tokens)  │
│             │◀─────│  (Go + JWT)      │◀─────│             │
└─────────────┘      └──────────────────┘      └─────────────┘
   OAuth2 flows           Token mgmt          Distributed store
```

### Session Management
```
┌──────────────┐      ┌──────────────────┐      ┌──────────────┐
│  API Request │─────▶│  Session Service │─────▶│ Redis Cluster│
│  (JWT token) │      │  (Go stateless)  │      │ (revocation) │
│              │◀─────│  Fast validation │◀─────│              │
└──────────────┘      └──────────────────┘      └──────────────┘
   Multi-tenant          Horizontal scale      Global consistency
```

## 🔧 Technology Choices

- **Go**: Fast, concurrent, single-binary deployment - matches enterprise scale requirements
- **Redis**: Distributed cache for tokens/sessions - HA, global replication
- **JWT**: Industry standard, stateless validation, flexible claims
- **Docker**: Reproducible environments, easy deployment
- **k6**: Modern load testing, API-focused, cloud-native

## 📊 Metrics & Results

- **OAuth2 Server**: All 4 flows working end-to-end
- **Security Scanner**: 35+ misconfiguration rules, zero false positives
- **Session Service**: 10K+ concurrent sessions, <10ms p99 latency
- **Code Quality**: Comprehensive error handling, observability hooks, production patterns
- **Documentation**: Architecture diagrams, sequence flows, security considerations

## 🎯 Real-World Applications

### Multi-Brand Identity Platforms
- **Challenge**: Unified identity across multiple brands in a portfolio
- **Solution**: Multi-tenant session management with brand-specific signing keys
- **Pattern**: OAuth2/OIDC for consumer apps, SAML for B2B partners

### Enterprise Security
- **Challenge**: Audit identity configurations across 100+ microservices
- **Solution**: Automated security scanning in CI/CD pipelines
- **Pattern**: Shift-left security, fail builds on critical findings

### Global Scale
- **Challenge**: Identity for hundreds of millions of users across regions
- **Solution**: Stateless JWT validation, Redis for global revocation
- **Pattern**: Fast path (JWT), slow path (Redis), observable metrics

## 🤝 Contributing

This is a personal learning repository, but feedback and suggestions are welcome! Open an issue or reach out on [LinkedIn](https://www.linkedin.com/in/mattbordenet/).

## 📝 License

MIT License - see [LICENSE](./LICENSE) for details.

## 🙏 Acknowledgments

Built with:
- **Claude Code** (Anthropic) - AI pair programming for rapid learning
- **OAuth 2.0 Spec** (RFC 6749) - Authorization framework
- **OpenID Connect Spec** - Identity layer on OAuth2
- **OWASP ASVS** - Security requirements for authentication
- **Auth0 & Okta Docs** - Excellent learning resources

---

**Timeline**: October 7-10, 2025 (3 days)
**Purpose**: Demonstrating rapid domain mastery for identity/access management leadership roles
**Author**: [Matt Bordenet](https://github.com/bordenet) | [LinkedIn](https://www.linkedin.com/in/mattbordenet/)

> "I don't have 15 years in identity - I have 26 years of rapid domain mastery. Every 3-5 years I've entered a new technical domain, dove deep, and delivered transformational results. Identity is my next deep dive, and my track record shows I simplify while I learn."
