# Product Requirements Document: Identity Security Scanner (Static Analysis)

## Document Information

**Project**: Identity Security Scanner (Static Analysis)
**Version**: 1.0
**Author**: Matt Gale
**Date**: October 9, 2025
**Status**: Approved
**Target Audience**: Security Engineers, Platform Engineers, DevOps Teams

---

## Executive Summary

The Identity Security Scanner is a CLI-based static analysis tool that automatically detects security misconfigurations in OAuth2, OIDC, SAML, and JWT implementations. By scanning configuration files, source code, and infrastructure-as-code definitions, it identifies vulnerabilities before they reach production.

This tool embodies "innovation through simplification" by automating manual security reviews that currently require expert knowledge and hours of analysis. It integrates into CI/CD pipelines to shift identity security left in the development lifecycle.

**Key Value Propositions**:
- **Automated Security Reviews**: Replace manual OAuth2/OIDC/SAML configuration audits
- **Early Detection**: Find vulnerabilities in development, not production
- **Developer-Friendly**: Clear remediation guidance, not just error messages
- **CI/CD Integration**: Block deployments with critical security issues
- **Zero False Positives Goal**: High-confidence detections only

---

## Problem Statement

### Current State

Organizations implementing identity and access management systems face several challenges:

1. **Complex Security Requirements**: OAuth2, OIDC, and SAML have dozens of security considerations spread across RFCs, security advisories, and best practice documents
2. **Manual Reviews Are Slow**: Security teams manually reviewing identity configurations creates bottlenecks
3. **Late-Stage Discovery**: Identity misconfigurations often discovered in production or penetration tests
4. **Knowledge Silos**: Identity security expertise concentrated in few team members
5. **Configuration Drift**: Secure defaults get weakened over time through incremental changes

### Impact

Real-world consequences of identity misconfigurations:
- **Authorization Code Interception**: Missing PKCE in mobile apps allows token theft
- **Open Redirects**: Overly permissive redirect URIs enable phishing attacks
- **Token Leakage**: Implicit flow in modern SPAs exposes tokens in browser history
- **Weak Secrets**: Short or predictable client secrets enable brute force attacks
- **Algorithm Confusion**: JWT "none" algorithm acceptance bypasses signature validation
- **Excessive Scopes**: Over-permissioned tokens violate principle of least privilege

### Target Users

**Primary Persona: Platform Engineer (Sarah)**
- **Role**: Maintains identity infrastructure for 50+ microservices
- **Pain Points**: Can't manually review every service's OAuth2 configuration
- **Goals**: Automated scanning in CI/CD, clear remediation steps
- **Success Metric**: Zero critical identity vulnerabilities in production

**Secondary Persona: Security Engineer (James)**
- **Role**: Performs security reviews and threat modeling
- **Pain Points**: Identity reviews require deep protocol knowledge, time-consuming
- **Goals**: Automated first-pass scanning, focus on complex threats
- **Success Metric**: 80% reduction in time spent on identity config reviews

**Tertiary Persona: Application Developer (Priya)**
- **Role**: Builds microservices that integrate with OAuth2/OIDC
- **Pain Points**: Unclear security requirements, late-stage security feedback
- **Goals**: Pre-commit scanning, actionable error messages
- **Success Metric**: Pass security review on first submission

---

## Goals and Non-Goals

### Goals

1. **Detect Common Misconfigurations**: Identify 25+ critical OAuth2/OIDC/SAML/JWT vulnerabilities
2. **Zero False Positives**: High-confidence detections only (accept false negatives over false positives)
3. **Clear Remediation**: Each finding includes specific fix instructions and security context
4. **Fast Execution**: Scan typical configuration in < 5 seconds
5. **CI/CD Integration**: GitHub Actions, GitLab CI, Jenkins plugins with configurable failure thresholds
6. **Multiple Input Formats**: YAML, JSON, TOML, environment files, source code annotations
7. **Extensible Rule Engine**: Easy to add new checks without code changes

### Non-Goals

1. **Runtime Analysis**: This tool performs static analysis only (runtime testing is Project 3)
2. **Code Execution**: Does not run or test actual OAuth2 flows
3. **Network Scanning**: Does not probe live endpoints or APIs
4. **Compliance Certification**: Provides guidance, not compliance attestation
5. **Auto-Remediation**: Reports issues, does not automatically fix them (yet)

---

## Success Metrics

### Primary Metrics

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| **Detection Accuracy** | 95%+ precision on test suite | 100 known vulnerable configs, measure false positives |
| **Scan Performance** | < 5 seconds for 1000-line config | Benchmark on typical OAuth2 provider config |
| **Adoption Rate** | 20+ GitHub stars in first month | GitHub metrics |
| **CI/CD Integration** | Working examples for 3+ platforms | GitHub Actions, GitLab CI, Jenkins tested |

### Secondary Metrics

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| **Developer Satisfaction** | 4.5+/5 on "clarity of remediation guidance" | Survey (hypothetical) |
| **Time Savings** | 80% reduction vs manual review | Time manual review vs automated scan |
| **Coverage** | 25+ distinct vulnerability types | Rule count |
| **False Negative Rate** | < 10% on OWASP ASVS checks | Test against ASVS identity requirements |

---

## Functional Requirements

### FR-1: Configuration File Scanning

**Priority**: P0 (Must Have)

The scanner must analyze configuration files containing OAuth2, OIDC, SAML, and JWT settings.

**Acceptance Criteria**:
- Parse YAML, JSON, TOML, and .env file formats
- Extract identity-related configuration keys (client_id, client_secret, redirect_uris, token_endpoint, etc.)
- Handle nested configuration structures (e.g., provider configs within larger app configs)
- Support multi-document YAML files
- Gracefully handle malformed files with clear parse errors

**Input Examples**:
```yaml
# oauth2-config.yaml
oauth2:
  providers:
    - name: google
      client_id: "1234567890-abc.apps.googleusercontent.com"
      client_secret: "short"  # VULNERABILITY: Too short
      redirect_uris:
        - "http://localhost:3000/callback"  # VULNERABILITY: HTTP in production
        - "*"  # VULNERABILITY: Wildcard redirect
      scopes:
        - "openid"
        - "profile"
        - "email"
        - "admin"  # VULNERABILITY: Overly broad scope
      pkce_required: false  # VULNERABILITY: PKCE not enforced
```

```json
{
  "jwt": {
    "algorithm": "none",  // VULNERABILITY: Algorithm "none" allowed
    "secret": "secret123",  // VULNERABILITY: Weak secret
    "expiration": 31536000  // VULNERABILITY: 1 year expiration
  }
}
```

**Output Format**:
```
CRITICAL: Weak Client Secret (oauth2-config.yaml:6)
  The client secret "short" is only 5 characters long.

  Risk: Attackers can brute force short secrets, gaining unauthorized access.

  Remediation:
    1. Generate a cryptographically random secret with at least 32 characters
    2. Use a secure random generator: openssl rand -base64 32
    3. Store in a secret manager (AWS Secrets Manager, HashiCorp Vault)

  References:
    - RFC 6749 Section 2.3.1 (Client Password)
    - OWASP ASVS v4.0 Section 2.6.3
```

---

### FR-2: OAuth2/OIDC Vulnerability Detection

**Priority**: P0 (Must Have)

Detect security misconfigurations specific to OAuth2 and OpenID Connect implementations.

**Vulnerability Categories**:

#### OAuth2 Configuration Issues

1. **Weak Client Secrets**
   - **Check**: Secret length < 32 chars, low entropy, common patterns
   - **Severity**: Critical
   - **Example**: `client_secret: "password123"`

2. **Insecure Redirect URIs**
   - **Check**: HTTP scheme (non-localhost), wildcard domains, open redirect patterns
   - **Severity**: Critical
   - **Example**: `redirect_uri: "http://example.com/callback"` or `redirect_uri: "*"`

3. **Missing PKCE Enforcement**
   - **Check**: Public clients (mobile, SPA) without `pkce_required: true`
   - **Severity**: High
   - **Example**: `client_type: "public"` with `pkce_required: false`

4. **Overly Permissive Scopes**
   - **Check**: Admin/wildcard scopes, excessive default scopes
   - **Severity**: High
   - **Example**: `default_scopes: ["admin", "*"]`

5. **Deprecated Flows Enabled**
   - **Check**: Implicit flow, resource owner password credentials
   - **Severity**: High (Implicit), Medium (ROPC)
   - **Example**: `grant_types: ["implicit"]`

6. **Missing State Parameter**
   - **Check**: Authorization requests without state requirement
   - **Severity**: High
   - **Example**: `require_state: false`

7. **Long Token Lifetimes**
   - **Check**: Access tokens > 1 hour, refresh tokens > 90 days
   - **Severity**: Medium
   - **Example**: `access_token_ttl: "24h"`

8. **Insecure Token Storage**
   - **Check**: LocalStorage usage hints in config comments/docs
   - **Severity**: High
   - **Example**: `# Store tokens in localStorage for persistence`

#### OIDC-Specific Issues

9. **Missing ID Token Signature Validation**
   - **Check**: `verify_signature: false` or missing validation config
   - **Severity**: Critical
   - **Example**: `id_token_verification: { enabled: false }`

10. **Weak ID Token Algorithms**
    - **Check**: HS256 with shared secrets, "none" algorithm
    - **Severity**: Critical
    - **Example**: `id_token_signing_alg: "none"`

11. **Missing Nonce Validation**
    - **Check**: Nonce requirement disabled
    - **Severity**: High
    - **Example**: `require_nonce: false`

12. **Insecure UserInfo Endpoint**
    - **Check**: HTTP scheme for UserInfo endpoint
    - **Severity**: High
    - **Example**: `userinfo_endpoint: "http://api.example.com/userinfo"`

**Acceptance Criteria**:
- Detect all 12+ OAuth2/OIDC vulnerabilities listed above
- Provide severity classification (Critical/High/Medium/Low)
- Include remediation steps for each vulnerability
- Reference relevant RFC sections and OWASP guidelines
- Support custom severity overrides via configuration

---

### FR-3: JWT Token Analysis

**Priority**: P0 (Must Have)

Analyze JWT configuration and sample tokens for security issues.

**Vulnerability Categories**:

1. **Algorithm Confusion**
   - **Check**: "none" algorithm accepted, algorithm switching allowed
   - **Severity**: Critical
   - **Example**: `allowed_algorithms: ["HS256", "none"]`

2. **Weak Signing Algorithms**
   - **Check**: HS256 with short secrets (< 32 bytes), RSA < 2048 bits
   - **Severity**: High
   - **Example**: `algorithm: "HS256"` with `secret: "short"`

3. **Missing Expiration**
   - **Check**: Tokens without `exp` claim requirement
   - **Severity**: High
   - **Example**: `require_exp: false`

4. **Excessive Token Lifetime**
   - **Check**: `exp` - `iat` > 1 hour for access tokens
   - **Severity**: Medium
   - **Example**: JWT with `exp` 24 hours in future

5. **Missing Audience Validation**
   - **Check**: No `aud` claim validation configured
   - **Severity**: High
   - **Example**: `validate_audience: false`

6. **Hardcoded Secrets**
   - **Check**: Secret values in configuration files (not references)
   - **Severity**: Critical
   - **Example**: `jwt_secret: "my-secret-key-123"`

7. **Insufficient Key Rotation**
   - **Check**: No key rotation policy defined
   - **Severity**: Medium
   - **Example**: Missing `key_rotation_days` configuration

**Input Formats**:
- Configuration files with JWT settings
- Sample JWT tokens (Base64-encoded, will decode and analyze claims)
- JWKS (JSON Web Key Set) documents

**Acceptance Criteria**:
- Decode and parse JWT tokens without validation (analysis only, not usage)
- Extract header and payload claims
- Check for all 7+ JWT vulnerabilities
- Validate JWKS document structure
- Support RS256, HS256, ES256 algorithm detection

---

### FR-4: SAML Configuration Analysis

**Priority**: P1 (Should Have)

Detect security issues in SAML 2.0 configurations (Service Provider and Identity Provider).

**Vulnerability Categories**:

1. **Unsigned Assertions**
   - **Check**: `require_signed_assertions: false`
   - **Severity**: Critical
   - **Example**: SP config accepting unsigned assertions

2. **XML Signature Wrapping Vulnerability**
   - **Check**: No signature validation on specific elements
   - **Severity**: Critical
   - **Example**: Validating signature on `<Assertion>` but not checking `<Subject>`

3. **Weak Signature Algorithms**
   - **Check**: SHA1-based signatures
   - **Severity**: High
   - **Example**: `signature_algorithm: "rsa-sha1"`

4. **Missing Assertion Encryption**
   - **Check**: PII in assertions without encryption requirement
   - **Severity**: High
   - **Example**: `encrypt_assertions: false` with `<Attribute Name="SSN">`

5. **Overly Permissive Recipient URLs**
   - **Check**: Wildcard or HTTP recipient URLs
   - **Severity**: High
   - **Example**: `recipient_url: "http://*.example.com/saml/acs"`

6. **Long Assertion Validity**
   - **Check**: `NotOnOrAfter` - `NotBefore` > 5 minutes
   - **Severity**: Medium
   - **Example**: Assertion valid for 24 hours

**Input Formats**:
- SAML metadata XML files
- Service Provider configuration files
- Identity Provider configuration files

**Acceptance Criteria**:
- Parse SAML metadata XML (SP and IdP)
- Extract security-relevant attributes
- Detect all 6+ SAML vulnerabilities
- Handle XML namespaces correctly
- Provide SAML-specific remediation guidance

**Note**: SAML support is P1 (should have) due to complexity and lower usage compared to OAuth2/OIDC in modern applications.

---

### FR-5: Reporting and Output Formats

**Priority**: P0 (Must Have)

Generate security scan reports in multiple formats for different audiences.

**Output Formats**:

#### 1. Human-Readable (Default)

```
Identity Security Scanner v1.0.0
Scanned: oauth2-config.yaml
Duration: 1.2s

Summary:
  Critical: 2
  High:     3
  Medium:   1
  Low:      0

Findings:

[CRITICAL] Weak Client Secret (oauth2-config.yaml:6)
  The client secret "short" is only 5 characters long.

  Risk: Attackers can brute force short secrets, gaining unauthorized
        access to protected resources.

  Remediation:
    1. Generate a cryptographically random secret: openssl rand -base64 32
    2. Update configuration with new secret
    3. Store secret in secure secret manager (AWS Secrets Manager, Vault)

  References:
    - RFC 6749 Section 2.3.1
    - OWASP ASVS v4.0 Section 2.6.3
    - CWE-521: Weak Password Requirements

[CRITICAL] Insecure Redirect URI (oauth2-config.yaml:8)
  HTTP redirect URI detected: http://localhost:3000/callback

  Risk: HTTP allows man-in-the-middle attacks to intercept authorization
        codes, leading to account takeover.

  Remediation:
    1. Use HTTPS for all redirect URIs in production
    2. Exception: localhost is acceptable for development only
    3. Update configuration: https://localhost:3000/callback or https://example.com/callback

  References:
    - RFC 6749 Section 3.1.2.1
    - OAuth 2.0 Security Best Current Practice (draft-ietf-oauth-security-topics)

---
Scan complete. Found 6 issues across 3 severity levels.
Exit code: 1 (critical issues found)
```

#### 2. JSON Format

```json
{
  "scanner_version": "1.0.0",
  "scan_time": "2025-10-09T10:30:00Z",
  "duration_ms": 1200,
  "files_scanned": ["oauth2-config.yaml"],
  "summary": {
    "critical": 2,
    "high": 3,
    "medium": 1,
    "low": 0
  },
  "findings": [
    {
      "id": "OAUTH2-001",
      "title": "Weak Client Secret",
      "severity": "critical",
      "file": "oauth2-config.yaml",
      "line": 6,
      "column": 18,
      "description": "The client secret \"short\" is only 5 characters long.",
      "risk": "Attackers can brute force short secrets, gaining unauthorized access to protected resources.",
      "remediation": [
        "Generate a cryptographically random secret: openssl rand -base64 32",
        "Update configuration with new secret",
        "Store secret in secure secret manager (AWS Secrets Manager, Vault)"
      ],
      "references": [
        "RFC 6749 Section 2.3.1",
        "OWASP ASVS v4.0 Section 2.6.3",
        "CWE-521"
      ],
      "cwe": "CWE-521",
      "confidence": "high"
    }
  ]
}
```

#### 3. SARIF Format (GitHub Security Tab)

SARIF (Static Analysis Results Interchange Format) enables integration with GitHub Security tab.

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Identity Security Scanner",
          "version": "1.0.0",
          "informationUri": "https://github.com/mattgale/identity-security-scanner"
        }
      },
      "results": [
        {
          "ruleId": "OAUTH2-001",
          "level": "error",
          "message": {
            "text": "Weak client secret detected (5 characters)"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "oauth2-config.yaml"
                },
                "region": {
                  "startLine": 6,
                  "startColumn": 18
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

#### 4. Markdown Format (Documentation)

```markdown
# Identity Security Scan Report

**Scanned**: oauth2-config.yaml
**Date**: 2025-10-09 10:30:00 UTC
**Duration**: 1.2s

## Summary

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High     | 3 |
| Medium   | 1 |
| Low      | 0 |

## Findings

### [CRITICAL] Weak Client Secret

**Location**: oauth2-config.yaml:6
**Rule ID**: OAUTH2-001

The client secret "short" is only 5 characters long.

**Risk**: Attackers can brute force short secrets...

**Remediation**:
1. Generate a cryptographically random secret: `openssl rand -base64 32`
2. Update configuration with new secret
3. Store secret in secure secret manager

**References**:
- [RFC 6749 Section 2.3.1](https://tools.ietf.org/html/rfc6749#section-2.3.1)
- [OWASP ASVS v4.0 Section 2.6.3](https://owasp.org/www-project-application-security-verification-standard/)
```

**Acceptance Criteria**:
- Support all 4 output formats (human-readable, JSON, SARIF, Markdown)
- Configurable via CLI flag: `--format=json`
- Exit code based on severity: 0 (no issues), 1 (critical/high), 2 (medium/low only)
- Summary statistics in all formats
- Unique rule IDs for each vulnerability type

---

### FR-6: CI/CD Integration

**Priority**: P0 (Must Have)

Enable integration into continuous integration pipelines with configurable failure thresholds.

**GitHub Actions Example**:

```yaml
name: Identity Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Identity Security Scanner
        uses: mattgale/identity-security-scanner-action@v1
        with:
          config-paths: |
            config/oauth2.yaml
            config/jwt.yaml
          format: sarif
          fail-on: critical,high
          output: results.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

**Configuration Options**:

```yaml
# .identity-scanner.yaml
scanner:
  # Paths to scan (glob patterns supported)
  include:
    - "config/**/*.yaml"
    - "config/**/*.json"
    - ".env*"

  # Paths to exclude
  exclude:
    - "node_modules/**"
    - "vendor/**"
    - "**/*_test.yaml"

  # Failure threshold
  fail_on:
    - critical
    - high

  # Output format
  format: json

  # Custom severity overrides
  severity_overrides:
    OAUTH2-003:  # PKCE not required
      severity: critical  # Upgrade from high to critical

  # Disable specific rules
  disabled_rules:
    - SAML-001  # Not using SAML in this project
```

**Acceptance Criteria**:
- GitHub Actions workflow example in repository
- GitLab CI example in repository
- Jenkins pipeline example in repository
- Configuration file support (`.identity-scanner.yaml`)
- Glob pattern support for file selection
- Configurable failure thresholds
- Exit codes match severity levels
- SARIF output works with GitHub Security tab

---

### FR-7: Extensible Rule Engine

**Priority**: P1 (Should Have)

Allow custom rules to be defined without modifying source code.

**Rule Definition Format (YAML)**:

```yaml
# rules/custom/my-org-oauth2.yaml
rules:
  - id: CUSTOM-001
    name: "Company-Specific Client ID Pattern"
    description: "Client IDs must follow company naming convention"
    severity: medium
    category: oauth2

    # JSONPath-like selector for configuration
    selector: "$.oauth2.providers[*].client_id"

    # Validation conditions
    conditions:
      - type: regex
        pattern: "^[a-z0-9]{8}-[a-z0-9]{4}-company$"
        message: "Client ID must match pattern: xxxxxxxx-xxxx-company"

    remediation: |
      Client IDs must follow the company naming convention:
      1. 8 lowercase alphanumeric characters
      2. Hyphen separator
      3. 4 lowercase alphanumeric characters
      4. "-company" suffix

      Example: a1b2c3d4-5678-company

    references:
      - "Internal Wiki: OAuth2 Standards"
      - "https://wiki.company.com/oauth2"

  - id: CUSTOM-002
    name: "Require MFA Scope"
    description: "All OAuth2 providers must request MFA scope"
    severity: high
    category: oauth2

    selector: "$.oauth2.providers[*]"

    conditions:
      - type: contains
        field: "scopes"
        value: "mfa"
        message: "Provider must include 'mfa' in scopes array"

    remediation: |
      Add "mfa" to the scopes array for this provider to enforce
      multi-factor authentication per company security policy.
```

**Acceptance Criteria**:
- Load custom rules from directory: `~/.identity-scanner/rules/` and `./.identity-scanner/rules/`
- Support YAML rule definitions with validation
- JSONPath-style selectors for configuration navigation
- Multiple condition types: regex, contains, range, custom functions
- Merge custom rules with built-in rules
- Rule validation on startup (fail fast for malformed rules)
- `--list-rules` CLI command to show all active rules

---

## Non-Functional Requirements

### NFR-1: Performance

| Requirement | Target | Rationale |
|-------------|--------|-----------|
| **Scan Speed** | < 5 seconds for 1000-line config | Fast enough for pre-commit hooks |
| **Memory Usage** | < 100 MB for typical workloads | Run on developer laptops and CI runners |
| **Startup Time** | < 500ms | Minimal overhead for small files |
| **Concurrency** | Scan 10 files in parallel | Speed up monorepo scans |

**Acceptance Criteria**:
- Benchmark suite included in repository
- Performance regression tests in CI/CD
- Profiling data available for optimization

---

### NFR-2: Usability

| Requirement | Target | Rationale |
|-------------|--------|-----------|
| **Installation** | Single binary, no dependencies | Easy adoption, works on any platform |
| **Documentation** | Comprehensive README + examples | Self-service onboarding |
| **Error Messages** | Clear, actionable, no jargon | Accessible to non-security experts |
| **Configuration** | Zero-config default, optional customization | Works out of the box |

**Acceptance Criteria**:
- Binaries for Linux, macOS, Windows in GitHub releases
- README with quickstart (5 minutes to first scan)
- 10+ example vulnerable configurations
- `--help` output explains all options

---

### NFR-3: Maintainability

| Requirement | Target | Rationale |
|-------------|--------|-----------|
| **Code Coverage** | > 80% | Confident refactoring |
| **Documentation** | Inline code comments + architecture doc | Onboard contributors |
| **Linting** | Pass `golangci-lint` with strict config | Code quality |
| **Dependencies** | Minimal, well-maintained only | Reduce supply chain risk |

**Acceptance Criteria**:
- Unit tests for all rule logic
- Integration tests for file parsing
- Architecture diagram in docs/
- Contributing guide

---

### NFR-4: Security

| Requirement | Target | Rationale |
|-------------|--------|-----------|
| **Secret Handling** | Never log secrets in output | Prevent accidental disclosure |
| **File Access** | Respect .gitignore | Don't scan secrets that shouldn't exist |
| **Supply Chain** | Verify dependency checksums | Prevent malicious dependencies |
| **Least Privilege** | Read-only file access | No writes during scan |

**Acceptance Criteria**:
- Secrets redacted in all output formats (show "[REDACTED]" instead of actual secret)
- Respect `.gitignore` and `.dockerignore` patterns
- `go.sum` checked into repository
- File system access limited to specified paths

---

## Technical Architecture

### System Overview

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
│  - TOML Parser      │    │  - Severity Classifier          │
│  - ENV Parser       │    │  - Custom Rule Support          │
│  - XML Parser       │    └─────────────────────────────────┘
└─────────────────────┘                 │
         │                              │
         ▼                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Vulnerability Detectors                    │
│  - OAuth2 Detector    - JWT Detector    - SAML Detector    │
└────────┬────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│                    Report Generators                        │
│  - Human-Readable  - JSON  - SARIF  - Markdown             │
└─────────────────────────────────────────────────────────────┘
```

### Component Design

#### 1. File Parsers

**Responsibility**: Parse various configuration file formats into unified internal representation.

```go
type ConfigParser interface {
    Parse(filename string, content []byte) (*ConfigTree, error)
    SupportsFormat(filename string) bool
}

type ConfigTree struct {
    Root     map[string]interface{}
    Metadata FileMetadata
}

type FileMetadata struct {
    Filename string
    Format   string // "yaml", "json", "toml", "env", "xml"
    LineMap  map[string]int // JSONPath -> line number mapping
}
```

**Implementations**:
- `YAMLParser`: Uses `gopkg.in/yaml.v3` for YAML parsing with line number tracking
- `JSONParser`: Uses `encoding/json` with custom decoder for line numbers
- `TOMLParser`: Uses `github.com/BurntSushi/toml` for TOML files
- `ENVParser`: Custom parser for .env files (KEY=VALUE format)
- `XMLParser`: Uses `encoding/xml` for SAML metadata (P1)

---

#### 2. Rule Engine

**Responsibility**: Load, validate, and execute security rules against parsed configuration.

```go
type Rule struct {
    ID          string
    Name        string
    Description string
    Severity    Severity
    Category    Category
    Detector    Detector
    Remediation string
    References  []string
}

type Detector interface {
    Detect(tree *ConfigTree) []Finding
}

type Finding struct {
    RuleID      string
    Severity    Severity
    File        string
    Line        int
    Column      int
    Title       string
    Description string
    Risk        string
    Remediation []string
    References  []string
    Confidence  Confidence
}

type Severity string
const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
)
```

**Rule Categories**:
- `CategoryOAuth2`: OAuth 2.0 configuration issues
- `CategoryOIDC`: OpenID Connect issues
- `CategoryJWT`: JWT token configuration issues
- `CategorySAML`: SAML 2.0 configuration issues (P1)

---

#### 3. Vulnerability Detectors

**Responsibility**: Implement specific security checks for each vulnerability type.

```go
// Example: Weak client secret detector
type WeakClientSecretDetector struct {
    MinLength int // Default: 32
}

func (d *WeakClientSecretDetector) Detect(tree *ConfigTree) []Finding {
    findings := []Finding{}

    // Navigate tree to find client_secret fields
    secrets := tree.SelectAll("$.oauth2.providers[*].client_secret")

    for _, secret := range secrets {
        if len(secret.Value) < d.MinLength {
            findings = append(findings, Finding{
                RuleID:   "OAUTH2-001",
                Severity: SeverityCritical,
                File:     tree.Metadata.Filename,
                Line:     secret.Line,
                Column:   secret.Column,
                Title:    "Weak Client Secret",
                Description: fmt.Sprintf(
                    "The client secret \"%s\" is only %d characters long.",
                    redactSecret(secret.Value), len(secret.Value),
                ),
                Risk: "Attackers can brute force short secrets...",
                Remediation: []string{
                    "Generate a cryptographically random secret: openssl rand -base64 32",
                    "Update configuration with new secret",
                    "Store secret in secure secret manager",
                },
                References: []string{
                    "RFC 6749 Section 2.3.1",
                    "OWASP ASVS v4.0 Section 2.6.3",
                    "CWE-521",
                },
                Confidence: ConfidenceHigh,
            })
        }
    }

    return findings
}
```

**Detector Implementations** (25+ total):
- OAuth2: 8 detectors (weak secrets, insecure redirects, PKCE, scopes, deprecated flows, state, token lifetimes, storage)
- OIDC: 4 detectors (signature validation, algorithms, nonce, UserInfo endpoint)
- JWT: 7 detectors (algorithm confusion, weak algorithms, expiration, lifetime, audience, hardcoded secrets, key rotation)
- SAML: 6 detectors (unsigned assertions, signature wrapping, weak algorithms, encryption, recipient URLs, validity) - P1

---

#### 4. Report Generators

**Responsibility**: Format findings into various output formats.

```go
type ReportGenerator interface {
    Generate(findings []Finding, metadata ScanMetadata) ([]byte, error)
    Format() string // "human", "json", "sarif", "markdown"
}

type ScanMetadata struct {
    ScannerVersion string
    ScanTime       time.Time
    Duration       time.Duration
    FilesScanned   []string
    Summary        SeveritySummary
}

type SeveritySummary struct {
    Critical int
    High     int
    Medium   int
    Low      int
}
```

**Implementations**:
- `HumanReportGenerator`: Color-coded terminal output with box drawing
- `JSONReportGenerator`: Structured JSON for programmatic consumption
- `SARIFReportGenerator`: SARIF 2.1.0 format for GitHub Security integration
- `MarkdownReportGenerator`: GitHub-flavored markdown for documentation

---

### Data Flow

```
1. CLI Invocation
   $ identity-scanner scan config/ --format=sarif --fail-on=critical,high

2. File Discovery
   - Glob pattern matching: config/**/*.yaml, config/**/*.json
   - Respect .gitignore patterns
   - Filter by supported formats

3. Parallel Parsing
   - Spawn goroutines for each file
   - Parse into ConfigTree with line number mapping
   - Collect parse errors

4. Rule Execution
   - Load built-in rules (25+)
   - Load custom rules from config
   - For each rule, run detector against each ConfigTree
   - Collect findings

5. Severity Filtering
   - Apply custom severity overrides
   - Filter disabled rules
   - Aggregate findings

6. Report Generation
   - Group findings by file and severity
   - Generate summary statistics
   - Format output (SARIF in this example)
   - Write to stdout or file

7. Exit Code
   - 0: No issues or only info/low
   - 1: Critical or high issues found
   - 2: Medium issues found (if --fail-on=medium)
```

---

### Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| **Language** | Go 1.21+ | Fast, single binary, great stdlib, concurrency |
| **CLI Framework** | Cobra | Industry standard, excellent UX |
| **Config** | Viper | Flexible config loading, env var support |
| **YAML Parser** | gopkg.in/yaml.v3 | Line number tracking, stable |
| **JSON Parser** | encoding/json (stdlib) | No dependencies, fast |
| **TOML Parser** | github.com/BurntSushi/toml | Canonical Go TOML library |
| **XML Parser** | encoding/xml (stdlib) | For SAML metadata |
| **Testing** | testify | Assertions and mocking |
| **Linting** | golangci-lint | Comprehensive linter aggregator |

---

## Implementation Plan

### Phase 1: Foundation (2 hours)

**Goal**: Working CLI skeleton with file parsing.

**Deliverables**:
- [ ] Project structure (`cmd/`, `internal/`, `pkg/`)
- [ ] Cobra CLI with `scan` command
- [ ] YAML and JSON parsers with line number tracking
- [ ] ConfigTree internal representation
- [ ] Unit tests for parsers
- [ ] Basic human-readable output

**Acceptance Criteria**:
- `identity-scanner scan config.yaml` runs without errors
- Parses YAML/JSON into ConfigTree
- Prints parsed tree structure

---

### Phase 2: OAuth2/OIDC Detection (2.5 hours)

**Goal**: Detect top 12 OAuth2/OIDC vulnerabilities.

**Deliverables**:
- [ ] Rule engine with Detector interface
- [ ] 8 OAuth2 detectors (weak secrets, redirects, PKCE, scopes, flows, state, lifetimes, storage)
- [ ] 4 OIDC detectors (signature, algorithms, nonce, UserInfo)
- [ ] Finding struct with all metadata
- [ ] Unit tests with vulnerable example configs

**Acceptance Criteria**:
- All 12 OAuth2/OIDC rules detect known vulnerabilities
- Zero false positives on secure configs
- Line numbers correctly mapped to findings

---

### Phase 3: JWT Detection (1.5 hours)

**Goal**: Detect JWT configuration issues.

**Deliverables**:
- [ ] 7 JWT detectors (algorithm confusion, weak algorithms, expiration, lifetime, audience, secrets, rotation)
- [ ] JWT token decoder (Base64, JSON parsing)
- [ ] JWT claim analysis
- [ ] Unit tests with vulnerable JWTs

**Acceptance Criteria**:
- Detect all 7 JWT vulnerabilities
- Decode sample JWT tokens and analyze claims
- Handle malformed tokens gracefully

---

### Phase 4: Reporting (1.5 hours)

**Goal**: Multiple output formats with excellent UX.

**Deliverables**:
- [ ] Human-readable report generator (color, formatting)
- [ ] JSON report generator
- [ ] SARIF report generator
- [ ] Markdown report generator
- [ ] Exit code logic based on severity
- [ ] Summary statistics

**Acceptance Criteria**:
- All 4 formats generate valid output
- SARIF validates against schema
- Human output is readable and helpful
- Exit codes match severity levels

---

### Phase 5: CI/CD Integration (1 hour)

**Goal**: Easy integration into pipelines.

**Deliverables**:
- [ ] GitHub Actions workflow example
- [ ] GitLab CI example
- [ ] Configuration file support (`.identity-scanner.yaml`)
- [ ] Glob pattern file selection
- [ ] Failure threshold configuration
- [ ] Docker image (optional)

**Acceptance Criteria**:
- GitHub Actions example works in demo repo
- SARIF upload to GitHub Security tab succeeds
- Configuration file overrides defaults
- Glob patterns select correct files

---

### Phase 6: Polish (1.5 hours)

**Goal**: Production-ready tool.

**Deliverables**:
- [ ] Comprehensive README with examples
- [ ] 10+ vulnerable config examples
- [ ] 5+ secure config examples
- [ ] Architecture documentation
- [ ] Installation instructions
- [ ] Benchmark suite
- [ ] CHANGELOG.md

**Acceptance Criteria**:
- README enables someone to scan in < 5 minutes
- Example configs demonstrate all vulnerability types
- Documentation explains architecture
- Benchmarks show < 5 second scan time

---

**Total Estimated Time**: 10 hours

---

## Testing Strategy

### Unit Tests

**Coverage Target**: 80%+

**Test Categories**:
1. **Parser Tests**: Verify each parser handles valid/invalid input
2. **Detector Tests**: Each detector has test cases for vulnerable and secure configs
3. **Report Generator Tests**: Each format generates valid output
4. **Rule Engine Tests**: Rule loading, execution, filtering

**Example Test Case**:
```go
func TestWeakClientSecretDetector(t *testing.T) {
    tests := []struct {
        name           string
        config         string
        expectedFindings int
        expectedSeverity Severity
    }{
        {
            name: "short secret (5 chars)",
            config: `
oauth2:
  client_secret: "short"
`,
            expectedFindings: 1,
            expectedSeverity: SeverityCritical,
        },
        {
            name: "strong secret (32 chars)",
            config: `
oauth2:
  client_secret: "abcdefghijklmnopqrstuvwxyz123456"
`,
            expectedFindings: 0,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            tree := parseYAML(tt.config)
            detector := WeakClientSecretDetector{MinLength: 32}
            findings := detector.Detect(tree)

            assert.Len(t, findings, tt.expectedFindings)
            if len(findings) > 0 {
                assert.Equal(t, tt.expectedSeverity, findings[0].Severity)
            }
        })
    }
}
```

---

### Integration Tests

**Goal**: Test end-to-end scanning workflow.

**Test Scenarios**:
1. **Scan vulnerable config**: Expect findings with correct line numbers
2. **Scan secure config**: Expect zero findings
3. **Scan multiple files**: Aggregate results correctly
4. **Output format switching**: All formats work
5. **Exit code logic**: Correct exit codes for different severity levels
6. **Configuration overrides**: Custom config changes behavior

---

### Benchmark Tests

**Goal**: Ensure performance requirements are met.

**Benchmarks**:
```go
func BenchmarkScanLargeConfig(b *testing.B) {
    config := generateLargeConfig(1000) // 1000 lines

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        scanner := NewScanner()
        scanner.ScanFile("large-config.yaml", config)
    }
}

// Target: < 5 seconds for 1000-line config
// Acceptable: ~1 second per file
```

---

## Security Considerations

### Secret Redaction

All output must redact sensitive values:

```go
func redactSecret(secret string) string {
    if len(secret) <= 4 {
        return "[REDACTED]"
    }
    // Show first 2 and last 2 characters
    return secret[:2] + "..." + secret[len(secret)-2:]
}

// Example: "my-secret-key-12345" -> "my...45"
```

### File Access Restrictions

- **Read-only access**: Never write to scanned files
- **Respect .gitignore**: Don't scan files Git ignores
- **No network access**: Static analysis only, no HTTP requests
- **Sandboxing**: Consider running in restricted environment for untrusted configs

### Supply Chain Security

- **Dependency pinning**: Use `go.sum` to lock dependency versions
- **Minimal dependencies**: Only essential libraries
- **Automated updates**: Dependabot for security patches
- **SBOM generation**: Publish Software Bill of Materials with releases

---

## Future Enhancements (Out of Scope for v1.0)

### v1.1: SAML Support
- Implement 6 SAML detectors
- XML parsing and analysis
- SAML metadata validation

### v1.2: Auto-Remediation
- `--fix` flag to automatically remediate certain issues
- Safe transformations only (e.g., generate strong secrets, fix redirect URIs)
- Diff preview before applying changes

### v1.3: IDE Integration
- VS Code extension for inline warnings
- IntelliJ plugin
- Language Server Protocol (LSP) implementation

### v1.4: Continuous Monitoring
- Watch mode for local development
- Webhook integration for config changes
- Slack/PagerDuty notifications

### v2.0: Runtime Analysis
- Complement static analysis with dynamic testing (Project 3)
- Probe live OAuth2/OIDC endpoints
- Simulate attacks (CSRF, token replay, etc.)

---

## Appendix

### A. Complete Vulnerability Checklist

#### OAuth2 (8 checks)
- [ ] OAUTH2-001: Weak client secrets (< 32 chars)
- [ ] OAUTH2-002: Insecure redirect URIs (HTTP, wildcards)
- [ ] OAUTH2-003: Missing PKCE for public clients
- [ ] OAUTH2-004: Overly permissive scopes (admin, wildcards)
- [ ] OAUTH2-005: Deprecated flows enabled (implicit, ROPC)
- [ ] OAUTH2-006: Missing state parameter requirement
- [ ] OAUTH2-007: Excessive token lifetimes (> 1 hour access, > 90 days refresh)
- [ ] OAUTH2-008: Insecure token storage hints (localStorage)

#### OIDC (4 checks)
- [ ] OIDC-001: ID token signature validation disabled
- [ ] OIDC-002: Weak ID token algorithms (none, HS256 with shared secret)
- [ ] OIDC-003: Missing nonce validation
- [ ] OIDC-004: Insecure UserInfo endpoint (HTTP)

#### JWT (7 checks)
- [ ] JWT-001: Algorithm confusion ("none" accepted)
- [ ] JWT-002: Weak signing algorithms (HS256 with short secret, RSA < 2048)
- [ ] JWT-003: Missing expiration claim requirement
- [ ] JWT-004: Excessive token lifetime (> 1 hour)
- [ ] JWT-005: Missing audience validation
- [ ] JWT-006: Hardcoded secrets in config
- [ ] JWT-007: No key rotation policy

#### SAML (6 checks - P1)
- [ ] SAML-001: Unsigned assertions accepted
- [ ] SAML-002: XML signature wrapping vulnerability
- [ ] SAML-003: Weak signature algorithms (SHA1)
- [ ] SAML-004: Missing assertion encryption
- [ ] SAML-005: Overly permissive recipient URLs
- [ ] SAML-006: Long assertion validity (> 5 minutes)

**Total**: 25 vulnerability checks in v1.0

---

### B. Example Configurations

#### Vulnerable OAuth2 Config

```yaml
# VULNERABLE: DO NOT USE IN PRODUCTION
oauth2:
  providers:
    - name: google
      client_id: "1234567890-abc.apps.googleusercontent.com"
      client_secret: "short"  # OAUTH2-001: Too short
      redirect_uris:
        - "http://localhost:3000/callback"  # OAUTH2-002: HTTP
        - "*"  # OAUTH2-002: Wildcard
      scopes:
        - "openid"
        - "profile"
        - "email"
        - "admin"  # OAUTH2-004: Overly broad
      pkce_required: false  # OAUTH2-003: PKCE not enforced
      grant_types:
        - "authorization_code"
        - "implicit"  # OAUTH2-005: Deprecated flow
      require_state: false  # OAUTH2-006: State not required
      token_lifetimes:
        access_token: "24h"  # OAUTH2-007: Too long
        refresh_token: "365d"  # OAUTH2-007: Too long

jwt:
  algorithm: "none"  # JWT-001: Algorithm confusion
  secret: "secret123"  # JWT-006: Hardcoded secret
  expiration: 31536000  # JWT-004: 1 year
  validate_audience: false  # JWT-005: No audience check
  require_exp: false  # JWT-003: Expiration not required
```

**Expected Findings**: 12 critical/high severity issues

#### Secure OAuth2 Config

```yaml
# SECURE CONFIGURATION
oauth2:
  providers:
    - name: google
      client_id: "1234567890-abc.apps.googleusercontent.com"
      client_secret_ref: "${SECRET_MANAGER_REF}"  # Stored securely
      redirect_uris:
        - "https://app.example.com/callback"  # HTTPS only
      scopes:
        - "openid"
        - "profile"
        - "email"
      pkce_required: true  # Enforced for all clients
      grant_types:
        - "authorization_code"  # Only secure flow
      require_state: true  # CSRF protection
      token_lifetimes:
        access_token: "15m"  # Short-lived
        refresh_token: "30d"  # Reasonable

jwt:
  algorithm: "RS256"  # Asymmetric signing
  private_key_ref: "${SECRET_MANAGER_REF}"
  expiration: 900  # 15 minutes
  validate_audience: true
  validate_issuer: true
  require_exp: true
  key_rotation_days: 90
```

**Expected Findings**: 0 issues

---

### C. References

#### Specifications
- [RFC 6749 - OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7636 - OAuth 2.0 PKCE](https://tools.ietf.org/html/rfc7636)
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [SAML 2.0](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)

#### Security Best Practices
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OAuth 2.0 for Browser-Based Apps](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps)
- [OAuth 2.0 for Native Apps](https://tools.ietf.org/html/rfc8252)
- [OWASP ASVS v4.0 - Authentication](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Cheat Sheet - OAuth2](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [NIST SP 800-63B - Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

#### SARIF Format
- [SARIF 2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [GitHub SARIF Support](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)

---

## Document History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-10-09 | Initial PRD | Matt Gale |

---

**Sign-off**:
- [ ] Product Owner: ____________________
- [ ] Security Lead: ____________________
- [ ] Engineering Lead: ____________________
