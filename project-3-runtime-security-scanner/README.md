# Identity Security Scanner (Runtime Analysis)

> **Automated security analysis for live OAuth2/OIDC endpoints**

A command-line runtime analysis tool that detects security misconfigurations in identity and access management systems by simulating common attack scenarios.

## What It Does

The Identity Security Scanner analyzes live OAuth2/OIDC endpoints to find:

- **[CSRF](https://owasp.org/www-community/attacks/csrf) vulnerabilities**: Attempts to initiate authorization flows without a state parameter.
- **Authorization Code Interception**: Simulates an attacker intercepting an authorization code and exchanging it for tokens.
- **Token Replay**: Attempts to use the same token multiple times.

## Quick Start

### Build and Run

```bash
# Build the scanner
make build

# Run the scanner against a target issuer
./bin/scanner run http://localhost:8080
```

## Detected Vulnerabilities

| Rule ID | Severity | Check |
|---------|----------|-------|
| RUNTIME-001 | High | Missing CSRF protection (no state parameter) |
| RUNTIME-002 | Critical | Authorization code interception possible (no PKCE) |
| RUNTIME-003 | High | Token replay possible |

## CLI Options

```
Usage:
  scanner run [issuer] [flags]

Flags:
  -h, --help   Help for run
```

## Project Structure

```
project-3-runtime-security-scanner/
├── cmd/
│   └── scanner/
│       └── main.go              # CLI entry point
├── internal/
│   └── scanner/
│       ├── csrf.go              # CSRF attack simulation
│       ├── discovery.go         # OIDC discovery client
│       ├── scanner.go           # Main scanning engine
│       └── scanner_test.go      # Tests for the scanner
├── pkg/
│   └── models/
│       └── oidc.go              # OIDC data models
├── docs/
│   └── PRD.md                   # Product Requirements Document
├── Makefile
├── README.md
├── CHANGELOG.md
└── go.mod
```

## Architecture

### Component Design

```
┌──────────────────┐      ┌──────────────────────┐
│  Scanner (Go)    │─────▶│ Target AuthZ Server  │
│                  │      │ (OAuth2/OIDC)        │
│                  │◀─────│                      │
└──────────────────┘      └──────────────────────┘
```

## Testing

### Run Tests

```bash
make test
```

## Documentation & References

### Project-Specific Documentation
- **[Product Requirements Document (PRD)](docs/PRD.md)** - Design and requirements
- **[CHANGELOG](CHANGELOG.md)** - Version history and changes

### Specifications
- [RFC 6749 - OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

### Security Best Practices
- [OWASP Cheat Sheet - OAuth2](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)

## Learning Outcomes

### Security Patterns Applied

1.  **Active Scanning**: Simulating real-world attacks to validate security controls.
2.  **Black-Box Testing**: Testing the system from the outside without knowledge of the internal implementation.

### Technical Skills Practiced

- **Protocol Knowledge**: OAuth2 and OIDC specifications.
- **[CLI](https://en.wikipedia.org/wiki/Command-line_interface) Design**: Command-line tools with [Cobra](https://cobra.dev/) framework.
- **Security Mindset**: Identifying attack vectors and remediation strategies.

## Future Enhancements

- **Authorization Code Interception with PKCE**: Add a check for PKCE bypass vulnerabilities.
- **Token Replay with Caching**: Implement a more sophisticated token replay check.

## Contributing

This is a learning/demonstration project, but feedback is welcome!

## License

MIT License - see [LICENSE](../LICENSE) for details.
