# Changelog

All notable changes to the Identity Security Scanner (Static Analysis) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Project initialization with comprehensive PRD
- PRD defining 25+ vulnerability checks across OAuth2, OIDC, JWT, and SAML
- Multiple output formats: human-readable, JSON, SARIF, Markdown
- CI/CD integration specifications
- Extensible rule engine design

## [0.1.0] - 2025-10-09

### Added
- Initial project structure created
- Comprehensive Product Requirements Document (PRD)
  - Executive summary and problem statement
  - 7 functional requirements (FR-1 through FR-7)
  - 4 non-functional requirements (performance, usability, maintainability, security)
  - Technical architecture with component design
  - 6-phase implementation plan (10 hours total)
  - Complete vulnerability checklist (25 checks)
  - Example configurations (vulnerable and secure)
  - Testing strategy and success metrics

### Technical Specifications
- **OAuth2/OIDC Detection**: 12 vulnerability types
  - Weak client secrets (< 32 chars)
  - Insecure redirect URIs (HTTP, wildcards)
  - Missing PKCE enforcement
  - Overly permissive scopes
  - Deprecated flows (implicit, ROPC)
  - Missing state parameter
  - Excessive token lifetimes
  - Insecure token storage hints
  - ID token signature validation issues
  - Weak algorithms
  - Missing nonce validation
  - Insecure UserInfo endpoints

- **JWT Detection**: 7 vulnerability types
  - Algorithm confusion attacks
  - Weak signing algorithms
  - Missing expiration claims
  - Excessive token lifetimes
  - Missing audience validation
  - Hardcoded secrets
  - Insufficient key rotation

- **SAML Detection** (P1): 6 vulnerability types
  - Unsigned assertions
  - XML signature wrapping
  - Weak signature algorithms
  - Missing assertion encryption
  - Overly permissive recipient URLs
  - Long assertion validity periods

### Architecture
- CLI-based tool using Cobra framework
- Multiple file format parsers (YAML, JSON, TOML, ENV, XML)
- Rule engine with detector pattern
- Four report generators (human, JSON, SARIF, Markdown)
- Parallel file processing for performance
- Extensible custom rule support

### Documentation
- docs/PRD.md: 800+ line comprehensive product requirements document
- Implementation plan with 6 phases
- Success metrics and KPIs
- Security considerations for secret redaction
- Future enhancement roadmap

[Unreleased]: https://github.com/mattgale/identity-deep-dive/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mattgale/identity-deep-dive/releases/tag/project-2-v0.1.0
