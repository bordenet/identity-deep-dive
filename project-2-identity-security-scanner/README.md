# Identity Security Scanner (Static Analysis)

> **Automated security analysis for OAuth2, OIDC, JWT, and SAML configurations**

A command-line static analysis tool that detects security misconfigurations in identity and access management systems before they reach production.

## 🎯 What It Does

The Identity Security Scanner analyzes configuration files to find:

- **[OAuth2](https://datatracker.ietf.org/doc/html/rfc6749) vulnerabilities** (6 checks): Weak secrets, insecure redirects, missing [PKCE](https://datatracker.ietf.org/doc/html/rfc7636), excessive scopes
- **[JWT](https://datatracker.ietf.org/doc/html/rfc7519) vulnerabilities** (6 checks): Algorithm confusion, weak signing, hardcoded secrets, missing validation
- **[OIDC](https://openid.net/specs/openid-connect-core-1_0.html) issues**: Signature validation, nonce requirements, insecure endpoints
- **Security best practices**: [CSRF](https://owasp.org/www-community/attacks/csrf) protection, token lifetimes, encryption requirements

## 🚀 Quick Start

### Build and Run

```bash
# Install dependencies
make install

# Build the scanner
make build

# Scan a vulnerable example
make scan-vulnerable

# Scan a secure example
make scan-secure
```

### Basic Usage

```bash
# Scan a single file
./bin/identity-scanner scan config/oauth2.yaml

# Scan a directory
./bin/identity-scanner scan config/

# Output as JSON
./bin/identity-scanner scan config/ --format json

# Fail only on critical issues
./bin/identity-scanner scan config/ --fail-on critical
```

## 📋 Detected Vulnerabilities

### OAuth2 Checks (6 rules)

| Rule ID | Severity | Check |
|---------|----------|-------|
| OAUTH2-001 | Critical | Weak client secrets (< 32 characters) |
| OAUTH2-002 | Critical | Insecure redirect URIs (HTTP, wildcards) |
| OAUTH2-003 | High | Missing PKCE enforcement for public clients |
| OAUTH2-004 | High | Overly permissive scopes (admin, wildcard) |
| OAUTH2-005 | High | Deprecated flows (implicit, password) |
| OAUTH2-006 | High | Missing state parameter (CSRF risk) |

### JWT Checks (6 rules)

| Rule ID | Severity | Check |
|---------|----------|-------|
| JWT-001 | Critical | Algorithm confusion ("none" accepted) |
| JWT-002 | High | Weak signing secrets for HS256 |
| JWT-003 | High | Missing expiration validation |
| JWT-004 | Medium | Excessive token lifetime (> 1 hour) |
| JWT-005 | High | Missing audience validation |
| JWT-006 | Critical | Hardcoded secrets in configuration |

**Total: 12 vulnerability checks** in v1.0.0

## 📊 Example Output

```
═══════════════════════════════════════════════════════════════
  Identity Security Scanner v1.0.0
═══════════════════════════════════════════════════════════════

Scan Time:  2025-10-09 14:30:00 PDT
Duration:   1.2s
Files:      1 scanned

━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Critical: 4
  High:     5
  Medium:   2

━━━ Findings ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[CRITICAL] Weak Client Secret
  Location: oauth2-config.yaml:6
  Rule ID:  OAUTH2-001

  Description:
    The client secret is only 5 characters long.

  Risk:
    Attackers can brute force short secrets, gaining unauthorized
    access to protected resources. This allows impersonation of the
    legitimate client application.

  Remediation:
    • Generate a cryptographically random secret with at least 32 characters
    • Use a secure random generator: openssl rand -base64 32
    • Store secrets in a secret manager (AWS Secrets Manager, HashiCorp Vault)
    • Use environment variables or secret references instead of hardcoded values

  References:
    - RFC 6749 Section 2.3.1 (Client Password)
    - OWASP ASVS v4.0 Section 2.6.3
    - CWE-521: Weak Password Requirements

─────────────────────────────────────────────────────────────

[CRITICAL] Algorithm Confusion Attack - 'none' Algorithm
  Location: oauth2-config.yaml:34
  Rule ID:  JWT-001

  Description:
    JWT configuration accepts 'none' algorithm, allowing unsigned tokens

  Risk:
    The 'none' algorithm allows JWT tokens without any signature. Attackers
    can forge arbitrary tokens by setting alg: 'none' in the header.

  Remediation:
    • Remove 'none' from allowed algorithms list
    • Use strong signing algorithms: RS256, ES256, or HS256 with strong secrets
    • Explicitly validate algorithm in token verification
    • Reject tokens with 'none' algorithm in production

  References:
    - RFC 7519 Section 6 (Unsecured JWTs)
    - Critical vulnerabilities in JSON Web Token libraries
    - CWE-347: Improper Verification of Cryptographic Signature

─────────────────────────────────────────────────────────────

═══════════════════════════════════════════════════════════════
Scan complete. Found 11 issue(s) - Exit code: 1
═══════════════════════════════════════════════════════════════
```

## 🔧 CLI Options

```
Usage:
  identity-scanner scan [paths...] [flags]

Flags:
  -f, --format string        Output format (human, json) (default "human")
      --fail-on strings      Fail on severities (default [critical,high])
      --include strings      Include file patterns (*.yaml, *.json)
      --exclude strings      Exclude file patterns
      --disable-rule strings Disable specific rules by ID
  -h, --help                 Help for scan

Examples:
  # Scan with JSON output
  identity-scanner scan config/ --format json > results.json

  # Fail only on critical issues
  identity-scanner scan config/ --fail-on critical

  # Exclude test files
  identity-scanner scan config/ --exclude '*_test.yaml'

  # Disable specific rules
  identity-scanner scan config/ --disable-rule OAUTH2-003,JWT-004
```

## 📁 Project Structure

```
project-2-identity-security-scanner/
├── cmd/
│   └── scanner/
│       └── main.go              # CLI entry point
├── internal/
│   ├── detector/
│   │   ├── oauth2.go            # OAuth2 vulnerability detectors
│   │   └── jwt.go               # JWT vulnerability detectors
│   ├── parser/
│   │   ├── parser.go            # Parser interface and utilities
│   │   ├── yaml.go              # YAML parser with line numbers
│   │   └── json.go              # JSON parser
│   ├── rules/
│   │   └── registry.go          # Rule registry and management
│   ├── report/
│   │   ├── human.go             # Human-readable output
│   │   └── json.go              # JSON output
│   └── scanner/
│       └── scanner.go           # Main scanning engine
├── pkg/
│   └── models/
│       └── models.go            # Data models (Finding, Rule, etc.)
├── examples/
│   ├── vulnerable/
│   │   └── oauth2-config.yaml   # Example vulnerable config
│   └── secure/
│       └── oauth2-config.yaml   # Example secure config
├── docs/
│   └── PRD.md                   # Product Requirements Document
├── Makefile
├── README.md
├── CHANGELOG.md
└── go.mod
```

## 🏗️ Architecture

### Component Design

```
┌─────────────────────────────────────────────────────────────┐
│                      CLI Interface                          │
│  (Cobra command framework, flag parsing, output rendering) │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│                   Scanner Orchestrator                      │
│  (File discovery, parallel processing, result aggregation) │
└────────┬───────────────────────────┬────────────────────────┘
         │                           │
         ▼                           ▼
┌─────────────────────┐    ┌─────────────────────────────────┐
│   File Parsers      │    │      Rule Engine                │
│  - YAML Parser      │    │  - Rule Loader                  │
│  - JSON Parser      │    │  - Condition Evaluator          │
└─────────────────────┘    └─────────────────────────────────┘
         │                              │
         ▼                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Vulnerability Detectors                    │
│  - OAuth2 Detector    - JWT Detector    - OIDC Detector    │
└────────┬────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│                    Report Generators                        │
│  - Human-Readable  - JSON  - SARIF (future)                │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Principles

1. **Extensible Rule Engine**: Add new checks without modifying core code
2. **Multiple Parsers**: [YAML](https://yaml.org/), [JSON](https://www.json.org/), [TOML](https://toml.io/) support with line number tracking
3. **Zero False Positives Goal**: High-confidence detections only
4. **Clear Remediation**: Every finding includes specific fix instructions
5. **Fast Execution**: < 5 seconds for typical configurations

## 🧪 Testing

### Run Example Scans

```bash
# Scan vulnerable config (should find 11 issues)
make scan-vulnerable

# Scan secure config (should find 0 issues)
make scan-secure

# Output as JSON
make scan-json
```

### Example Vulnerable Config

See [examples/vulnerable/oauth2-config.yaml](examples/vulnerable/oauth2-config.yaml) for a configuration with intentional security issues.

### Example Secure Config

See [examples/secure/oauth2-config.yaml](examples/secure/oauth2-config.yaml) for security best practices.

## 📚 Documentation & References

### Project-Specific Documentation
- **[Product Requirements Document (PRD)](docs/PRD.md)** - Comprehensive design and requirements
- **[CHANGELOG](CHANGELOG.md)** - Version history and changes

### Specifications
- [RFC 6749 - OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7636 - PKCE Extension](https://tools.ietf.org/html/rfc7636)
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

### Security Best Practices
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OWASP ASVS - Authentication](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Cheat Sheet - OAuth2](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [OWASP Cheat Sheet - JWT](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

### Related Work
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [Semgrep](https://semgrep.dev/) - Static analysis tool
- [Trivy](https://github.com/aquasecurity/trivy) - Security scanner

## 🎓 Learning Outcomes

### Security Patterns Applied

This project demonstrates several security engineering patterns:

1. **[Shift-Left Security](https://www.devsecops.org/blog/2016/5/20/-security)**: Catch issues in development, not production
2. **[Defense in Depth](https://en.wikipedia.org/wiki/Defense_in_depth_(computing))**: Multiple layers of checks
3. **[Principle of Least Privilege](https://en.wikipedia.org/wiki/Principle_of_least_privilege)**: Detect overly permissive scopes
4. **[Secure by Default](https://en.wikipedia.org/wiki/Secure_by_default)**: Identify insecure default configurations

### Technical Skills Demonstrated

- **Protocol Expertise**: Deep understanding of OAuth2, OIDC, JWT specifications
- **Static Analysis**: [AST](https://en.wikipedia.org/wiki/Abstract_syntax_tree) parsing, pattern matching, vulnerability detection
- **[CLI](https://en.wikipedia.org/wiki/Command-line_interface) Design**: User-friendly command-line tools with [Cobra](https://cobra.dev/) framework
- **Security Mindset**: Identifying attack vectors and remediation strategies

## 🔮 Future Enhancements

### v1.1 - SAML Support
- Add 6 [SAML](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)-specific checks
- [XML](https://www.w3.org/XML/) parsing and signature validation
- [SAML](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html) metadata analysis

### v1.2 - CI/CD Integration
- GitHub Actions workflow
- GitLab CI integration
- [SARIF](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif) output for GitHub Security tab

### v1.3 - Custom Rules
- [YAML](https://yaml.org/)-based rule definitions
- Load custom rules from directory
- Rule marketplace/sharing

### v2.0 - Runtime Analysis
- Complement static analysis with dynamic testing
- Probe live OAuth2/OIDC endpoints
- Attack simulation ([CSRF](https://owasp.org/www-community/attacks/csrf), token replay, etc.)

## 🤝 Contributing

This is a learning/demonstration project, but feedback is welcome!

### Found a False Positive?

Open an issue with:
1. The configuration that triggered it
2. Why it's not actually a vulnerability
3. Expected behavior

### Want to Add a Check?

The detector pattern makes it easy:

1. Create new detector in `internal/detector/`
2. Implement the `Detector` interface
3. Register in `internal/rules/registry.go`
4. Add tests and documentation

## 📝 License

MIT License - see [LICENSE](../LICENSE) for details.
