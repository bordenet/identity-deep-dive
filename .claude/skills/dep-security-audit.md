# Dependency Security Audit Skill

**Purpose**: Audit all Go dependencies across all projects for security vulnerabilities, upgrade vulnerable dependencies, run tests, lint, and push changes to GitHub.

## Execution Steps

### 1. Scan All Projects for Vulnerabilities

For each project directory:
- `project-1-oauth2-oidc-demo`
- `project-2-identity-security-scanner`
- `project-3-runtime-security-scanner`
- `project-4-session-management`

Run security audit:
```bash
cd <project-dir>
go list -json -m all | nancy sleuth
```

Alternative (built-in Go vulnerability scanner):
```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

### 2. Review Vulnerability Report

Analyze output for:
- CVE identifiers
- Severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- Affected packages
- Fixed versions available
- Exploit likelihood

Create summary table:
| Project | Package | CVE | Severity | Current | Fixed | Action |
|---------|---------|-----|----------|---------|-------|--------|

### 3. Upgrade Dependencies

For each vulnerable dependency:

**Option A: Targeted upgrade**
```bash
go get -u <package>@<fixed-version>
go mod tidy
```

**Option B: Full upgrade (if safe)**
```bash
go get -u ./...
go mod tidy
```

**Check for breaking changes**:
```bash
go mod graph | grep <package>
```

### 4. Run Full Test Suite

For each project:
```bash
cd <project-dir>
make test
```

If tests fail:
- Review breaking changes in upgraded dependencies
- Update code to match new API contracts
- Fix tests
- Re-run until green

### 5. Run Linting

For each project:
```bash
cd <project-dir>
make lint
```

Fix any new linting issues introduced by upgrades.

### 6. Build and Validate

For each project:
```bash
cd <project-dir>
make build
```

Ensure binaries compile successfully.

### 7. Run Integration Tests (if applicable)

For projects with integration tests:
```bash
cd <project-dir>
make integration-test
```

Or manual smoke tests:
- Project 1: Start OAuth2 server, test auth code flow
- Project 2: Run scanner against example configs
- Project 3: Run runtime scanner against Project 1
- Project 4: Start session service, create/validate/revoke session

### 8. Generate Dependency Report

Create upgrade summary:
```bash
echo "# Dependency Security Audit - $(date +%Y-%m-%d)" > SECURITY_AUDIT.md
echo "" >> SECURITY_AUDIT.md
echo "## Vulnerabilities Found" >> SECURITY_AUDIT.md
# Add findings
echo "" >> SECURITY_AUDIT.md
echo "## Upgrades Applied" >> SECURITY_AUDIT.md
# Add upgrade details
echo "" >> SECURITY_AUDIT.md
echo "## Test Results" >> SECURITY_AUDIT.md
# Add test status
```

### 9. Commit Changes

```bash
git add .
git commit -m "security: Upgrade dependencies to fix CVE-XXXX-XXXXX

- Upgraded package1 from v1.2.3 to v1.2.4 (fixes CVE-2024-XXXXX)
- Upgraded package2 from v2.3.4 to v2.4.0 (fixes CVE-2024-YYYYY)
- All tests passing
- No breaking changes

Audit report: SECURITY_AUDIT.md"
```

### 10. Push to GitHub

```bash
git push origin main
```

## Security Advisory Sources

Check these sources for Go-specific vulnerabilities:
- [Go Vulnerability Database](https://pkg.go.dev/vuln/)
- [GitHub Advisory Database](https://github.com/advisories)
- [Sonatype OSS Index](https://ossindex.sonatype.org/)
- [Snyk Vulnerability DB](https://snyk.io/vuln/)

## Common Go Package Vulnerabilities to Watch

### JWT Libraries
- `golang-jwt/jwt` - Algorithm confusion, weak validation
- Check: https://github.com/golang-jwt/jwt/security/advisories

### HTTP Libraries
- `gorilla/mux` - Path traversal, regex DoS
- `gorilla/websocket` - Memory exhaustion
- Check: https://github.com/gorilla/mux/security/advisories

### Crypto Libraries
- `golang.org/x/crypto` - Timing attacks, weak algorithms
- Check: https://pkg.go.dev/golang.org/x/crypto

### Redis Clients
- `go-redis/redis` - Command injection, connection hijacking
- Check: https://github.com/redis/go-redis/security/advisories

## Rollback Plan

If upgrades break critical functionality:

1. **Revert commits**:
```bash
git reset --hard HEAD~1
```

2. **Targeted fix**:
```bash
go get <package>@<previous-version>
go mod tidy
```

3. **Document decision**:
```markdown
## Deferred Upgrades

- `package-name` v1.2.3 → v1.2.4: Breaking changes in API X
  - CVE-2024-XXXXX: LOW severity, low exploit likelihood
  - Mitigation: Input validation at boundary
  - Upgrade planned for: Q1 2025
```

## Automation Notes

This skill should be run:
- **Weekly**: For security-critical projects
- **Monthly**: For internal tools
- **Immediately**: When CVE alerts are received
- **Before releases**: As part of release checklist

## Expected Output

The skill should produce:
1. **SECURITY_AUDIT.md**: Detailed findings and actions
2. **Updated go.mod/go.sum**: New dependency versions
3. **Passing tests**: All test suites green
4. **Clean lint**: No new linting errors
5. **Git commit**: Descriptive commit with CVE references
6. **GitHub push**: Changes pushed to remote

## Success Criteria

- All CRITICAL and HIGH vulnerabilities resolved
- All tests passing (100% success rate)
- No new linting errors
- Code compiles successfully
- Changes committed and pushed to GitHub
- SECURITY_AUDIT.md documents all actions taken
