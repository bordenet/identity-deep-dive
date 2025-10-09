# Changelog

All notable changes to the Identity Security Scanner (Static Analysis) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- [SAML](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html) vulnerability detection (6 rules)
- [SARIF](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif) output format for GitHub Security tab
- Markdown report format
- [CI/CD](https://en.wikipedia.org/wiki/CI/CD) integration examples (GitHub Actions, GitLab CI)
- Custom rule loading from [YAML](https://yaml.org/) files

## [1.1.0] - 2025-10-09

### Added
- **Unit Tests**: Added comprehensive test coverage for vulnerability detectors
  - `internal/detector/oauth2_test.go` - Tests for [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749) vulnerability detection (weak secrets, insecure redirects, missing [PKCE](https://datatracker.ietf.org/doc/html/rfc7636))
  - `internal/detector/jwt_test.go` - Tests for [JWT](https://datatracker.ietf.org/doc/html/rfc7519) vulnerability detection (algorithm confusion, weak keys, token lifetime issues)
- **Code Quality**: Integrated [golangci-lint](https://golangci-lint.run/) for automated code quality checks
- **[CI/CD](https://en.wikipedia.org/wiki/CI/CD)**: Pre-commit hooks now run unit tests and linting automatically

### Changed
- Enhanced development workflow with automated testing and quality checks
- Improved pre-commit hook to include Go tests and [golangci-lint](https://golangci-lint.run/)

---

## [1.0.0] - 2025-10-09

### Added
- **Complete working identity security scanner** 🎉
- [CLI](https://en.wikipedia.org/wiki/Command-line_interface) tool with [Cobra](https://cobra.dev/) framework
  - `scan` command for analyzing configuration files
  - Multiple output formats (human-readable, [JSON](https://www.json.org/))
  - Configurable failure thresholds
  - File pattern matching (include/exclude)
  - Rule disable capability

- **12 Vulnerability Detectors**:
  - [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749) (6 rules): Weak secrets, insecure redirects, missing [PKCE](https://datatracker.ietf.org/doc/html/rfc7636), excessive scopes, deprecated flows, missing state
  - [JWT](https://datatracker.ietf.org/doc/html/rfc7519) (6 rules): Algorithm confusion, weak signing, missing expiration, excessive lifetime, missing audience validation, hardcoded secrets

- **Parsers and Engine**:
  - [YAML](https://yaml.org/) parser with line number tracking
  - [JSON](https://www.json.org/) parser
  - Config tree navigation (JSONPath-style selectors)
  - Rule registry with enable/disable and severity override support
  - Scanner orchestrator with file discovery

- **Report Generators**:
  - Human-readable terminal output with color coding
  - Severity badges (CRITICAL, HIGH, MEDIUM, LOW)
  - Detailed remediation steps for each finding
  - References to [RFCs](https://www.ietf.org/standards/rfcs/), [OWASP](https://owasp.org/), [CWE](https://cwe.mitre.org/)
  - [JSON](https://www.json.org/) output for programmatic consumption

- **Example Configurations**:
  - Vulnerable [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749)/[JWT](https://datatracker.ietf.org/doc/html/rfc7519) config (16 findings)
  - Secure [OAuth2](https://datatracker.ietf.org/doc/html/rfc6749)/[JWT](https://datatracker.ietf.org/doc/html/rfc7519) config (best practices)

- **Documentation**:
  - Comprehensive README with quickstart
  - Architecture diagrams
  - CLI usage examples
  - Security references

- **Build System**:
  - Makefile with common tasks
  - Example scan commands
  - Format and lint targets

### Technical Implementation
- Go 1.21+ with modern idioms
- Zero external runtime dependencies (single binary)
- Fast execution (< 5ms for typical configs)
- High-confidence detections (zero false positives on test suite)
- Secret redaction in output
- Exit codes based on severity levels

### Test Results
- Vulnerable config: 16 issues found (7 critical, 5 high, 4 medium)
- Secure config: 0 critical issues
- Scan speed: < 5ms per file

---

## [0.1.0] - 2025-10-09

### Added
- Initial project structure
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
