# Identity Deep Dive

> **Learning identity protocols through implementation**

This repository contains a collection of projects built to explore and learn core identity and access management concepts. The primary focus is on implementing protocols like [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749) and [OIDC](https://openid.net/specs/openid-connect-core-1_0.html) from specifications, building practical security tools, and understanding production patterns for scale and security.

**This is an AI-assisted learning exercise.** The code was primarily generated with AI pair-programming tools ([Claude Code](https://claude.ai/claude-code) and [Google Gemini](https://gemini.google.com)) to accelerate learning and explore the domain, not to demonstrate implementation from scratch.

## Getting Started

Setup guide, build commands, and instructions for running all projects are available in the **[Quick Start Guide](docs/QUICK_START.md)**.

**Key Documentation:**
- **[Architecture & Design](docs/ARCHITECTURE.md)**: System architecture and design patterns.
- **[Learning Journey](docs/LEARNING_JOURNEY.md)**: A chronicle of the development process.
- **[External Resources](docs/RESOURCES.md)**: Curated learning materials.

## 📦 Projects

### 1. OAuth2/OIDC Authorization Server

An implementation of an [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749) and [OIDC](https://openid.net/specs/openid-connect-core-1_0.html) authorization server.
- **Features**: Authorization Code Flow with PKCE, Client Credentials, token refresh, and OIDC support.
- **Docs**: [Project README](./project-1-oauth2-oidc-demo/README.md), [OIDC Walkthrough](./project-1-oauth2-oidc-demo/docs/OIDC_Walk_Thru.md), [PKCE Deep Dive](./project-1-oauth2-oidc-demo/docs/PKCE_Deep_Dive.md).
- **Try It**: `cd project-1-oauth2-oidc-demo && podman-compose up`

### 2. Identity Security Scanner (Static Analysis)

A CLI tool for auditing OAuth2/OIDC/SAML configurations for common vulnerabilities.
- **Features**: Checks for weak client secrets, permissive scopes, insecure redirect URIs, and JWT vulnerabilities.
- **Docs**: [Project README](./project-2-identity-security-scanner/README.md).
- **Try It**: `cd project-2-identity-security-scanner && make scan-vulnerable`

### 3. Identity Security Scanner (Runtime Analysis)

A runtime security scanner for testing live OAuth2/OIDC implementations.
- **Features**: Detects CSRF, token replay, authorization code interception, and redirect URI manipulation.
- **Docs**: [Project README](./project-3-runtime-security-scanner/README.md).
- **Try It**: Requires Project 1 server running first. See [Project 3 README](./project-3-runtime-security-scanner/README.md) for setup.

### 4. Multi-Tenant Session Management

A distributed session management service using JWTs and Redis.
- **Features**: Multi-tenant session isolation, stateless JWT validation, Redis-backed revocation, and token refresh.
- **Docs**: [Project README](./project-4-session-management/README.md).
- **Try It**: `cd project-4-session-management && make run`

---

## Out of Scope

These projects cover core authentication and authorization patterns, but identity and access management is a vast domain. Topics like [federation](https://www.cloudflare.com/learning/access-management/what-is-federated-identity/), [directory services](https://www.techtarget.com/searchwindowsserver/definition/directory-service), [certificate management](https://www.techtarget.com/searchsecurity/definition/certificate-management), [SAML/OIDC brokers/bridges](https://medium.com/@curity.io/saml-and-oidc-bridging-and-brokering-d04946702937), popular [IdP vendor solutions](https://www.g2.com/categories/identity-provider-idp), [MFA/OTP/biometrics](https://www.cisa.gov/MFA), [risk-based authentication](https://www.pingidentity.com/en/resources/blog/post/what-is-risk-based-authentication.html), [step-up AuthZ](https://www.authress.io/knowledge-base/step-up-authentication-and-authorization), and numerous other concepts are not explored here.

---

## Contributing & License

This is a personal learning repository, but feedback and suggestions are welcome. Please feel free to open an issue.

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
