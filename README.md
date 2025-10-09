# Identity Deep Dive

> **Learning identity protocols through implementation**

## ⚠️ Important Context

**This is an AI-assisted learning exercise.** The code in this repository was generated using [Claude Code](https://claude.ai/claude-code) (Anthropic) for ~75% of the work and [Google Gemini](https://gemini.google.com) for ~25% as pair-programming tools. The goal is to break down core identity concepts into tangible, debuggable code for hands-on exploration and understanding.

This is a "vibe-coding" driven project focused on:
- **Learning by doing**: Stepping through working implementations with a debugger
- **Understanding trade-offs**: Exploring protocol design decisions through code
- **Building intuition**: Moving from abstract specs to concrete examples

This repository demonstrates domain exploration and AI-assisted development, not independent implementation from scratch.

---

Implementation of [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749), [OIDC](https://openid.net/specs/openid-connect-core-1_0.html), and identity security patterns.

**Note**: These projects cover core authentication and authorization patterns, but identity and access management is a vast domain. Topics like federation, directory services, certificate management, biometrics, risk-based authentication, and many other concepts are not explored here.

## 📑 Documentation

- **README** (this document) - Project overview and introduction
- **[Quick Start Guide](docs/QUICK_START.md)** - Setup instructions, build commands, and running projects
- **[Architecture & Design](docs/ARCHITECTURE.md)** - System architecture, technology choices, and design patterns
- **[Learning Journey](docs/LEARNING_JOURNEY.md)** - Three-day chronicle of building these projects
- **[External Resources](docs/RESOURCES.md)** - Curated learning materials, cheat sheets, and references

## Learning Objectives

This monorepo demonstrates:
- Domain learning in identity/access management
- Implementing protocols from RFCs and specifications
- Building practical security tools
- Production patterns: scale, security, and operational practices

## 📦 Projects

### 1. OAuth2/OIDC Authorization Server
**Language**: [Go](https://go.dev)

Implementation of [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749) and [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) authorization server:
- [Authorization Code Flow](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1)
- [PKCE Extension](https://datatracker.ietf.org/doc/html/rfc7636)
- [Client Credentials Flow](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)
- Token Refresh
- [OIDC](https://openid.net/specs/openid-connect-core-1_0.html) ID Tokens + UserInfo endpoint

Understanding identity protocols by implementing RFC specifications.

**📚 Documentation**:
- [📁 View Project](./project-1-oauth2-oidc-demo/) | [📖 Project README](./project-1-oauth2-oidc-demo/README.md)
- [📋 Product Requirements (PRD)](./project-1-oauth2-oidc-demo/docs/PRD.md) | [📝 Progress Tracking](./project-1-oauth2-oidc-demo/CHANGELOG.md)
- [🔐 OIDC Flow Walkthrough](./project-1-oauth2-oidc-demo/docs/OIDC_Walk_Thru.md) - Complete OIDC Authorization Code Flow with diagrams, security features, and error handling
- [🔑 PKCE Deep Dive](./project-1-oauth2-oidc-demo/docs/PKCE_Deep_Dive.md) - Comprehensive PKCE explanation with attack scenarios, code examples, and best practices

**Try It**:
```bash
cd project-1-oauth2-oidc-demo
docker-compose up
```

---

### 2. Identity Security Scanner (Static Analysis)
**Language**: [Go](https://go.dev)

[CLI](https://en.wikipedia.org/wiki/Command-line_interface) tool to audit [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749)/[OIDC](https://openid.net/specs/openid-connect-core-1_0.html)/[SAML](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html) configurations:
- Weak client secrets and key management
- Overly permissive scopes
- Insecure redirect [URIs](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier)
- [JWT](https://datatracker.ietf.org/doc/html/rfc7519) token vulnerabilities
- [SAML](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html) signature/encryption issues

Automated security scanning for identity configurations.

**📚 Documentation**:
- [📁 View Project](./project-2-identity-security-scanner/) | [📖 Project README](./project-2-identity-security-scanner/README.md)
- [📋 Product Requirements (PRD)](./project-2-identity-security-scanner/docs/PRD.md) | [📝 Progress Tracking (CHANGELOG)](./project-2-identity-security-scanner/CHANGELOG.md)

**Try It**:
```bash
cd project-2-identity-security-scanner
make scan-vulnerable  # Scan example config with 16 security issues
```

---

### 3. Identity Security Scanner (Runtime Analysis)
**Language**: [Go](https://go.dev)

Runtime security testing for live [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749)/[OIDC](https://openid.net/specs/openid-connect-core-1_0.html) flows:
- [CSRF](https://owasp.org/www-community/attacks/csrf) attack detection
- Token replay testing
- Authorization code interception
- Redirect [URI](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier) manipulation
- [Algorithm confusion attacks](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)

Dynamic testing of OAuth2/OIDC implementations.

**📚 Documentation**:
- [📁 View Project](./project-3-runtime-security-scanner/) | [📖 Project README](./project-3-runtime-security-scanner/README.md)
- [📋 Product Requirements (PRD)](./project-3-runtime-security-scanner/docs/PRD.md) | [📝 Progress Tracking (CHANGELOG)](./project-3-runtime-security-scanner/CHANGELOG.md)

**Try It**:
```bash
cd project-3-runtime-security-scanner
make build
./bin/scanner run http://localhost:8080
```

---

### 4. Multi-Tenant Session Management
**Language**: [Go](https://go.dev)

Distributed session management service with [JWT](https://datatracker.ietf.org/doc/html/rfc7519) tokens and [Redis](https://redis.io):
- Multi-tenant session isolation
- Stateless [JWT](https://datatracker.ietf.org/doc/html/rfc7519) validation
- [Redis](https://redis.io)-backed revocation
- Token refresh with sliding sessions

Multi-brand architecture patterns for distributed identity systems.

**📚 Documentation**:
- [📁 View Project](./project-4-session-management/) | [📖 Project README](./project-4-session-management/README.md)
- [📋 Product Requirements (PRD)](./project-4-session-management/docs/PRD.md) | [📝 Progress Tracking (CHANGELOG)](./project-4-session-management/CHANGELOG.md)

**Try It**:
```bash
cd project-4-session-management
make run
```

---

## 🚀 Getting Started

👉 **[Quick Start Guide](docs/QUICK_START.md)** - Complete setup instructions, prerequisites, and running all projects

**Quick Commands**:
```bash
# One-time setup (macOS)
./setup-macos.sh

# Build all projects
make build-all

# Run tests
make test-all

# Lint code
make lint-all
```

## 📚 Learning Resources

- **[Learning Journey](docs/LEARNING_JOURNEY.md)** - Day-by-day chronicle of building these projects with key insights
- **[Architecture & Design](docs/ARCHITECTURE.md)** - System design, technology choices, and trade-offs
- **[External Resources](docs/RESOURCES.md)** - Curated cheat sheets, security guides, and protocol comparisons

### Quick Links
- [LOGGING.md](./LOGGING.md) - Structured logging setup and debugging with breakpoints
- [CLAUDE.md](./CLAUDE.md) - Project execution guidelines and status

## 🤝 Contributing

This is a personal learning repository, but feedback and suggestions are welcome! Open an issue or reach out on [LinkedIn](https://www.linkedin.com/in/mattbordenet/).

## 📝 License

MIT License - see [LICENSE](./LICENSE) for details.

## 🙏 Acknowledgments

Built with:
- [Claude Code](https://claude.ai/claude-code) (Anthropic) - AI pair programming for rapid learning (~75% of code)
- [Google Gemini](https://gemini.google.com) - AI pair programming assistance (~25% of code)
- [RFC 6749 - OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636 - PKCE Extension](https://datatracker.ietf.org/doc/html/rfc7636)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OWASP ASVS - Identity and Authentication](https://owasp.org/www-project-application-security-verification-standard/)
- [Auth0 Docs](https://auth0.com/docs/authenticate/protocols/oauth) & [Okta Developer](https://developer.okta.com/docs/concepts/oauth-openid/)

---

**Purpose**: Learning identity/access management through implementation
**Author**: [Matt Bordenet](https://github.com/bordenet) | [LinkedIn](https://www.linkedin.com/in/mattbordenet/)
