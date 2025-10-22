# Claude Skills for Identity Deep Dive

This directory contains Claude Code skills for automating common maintenance and security tasks across all identity learning projects.

## Available Skills

### `dep-security-audit.md`

**Purpose**: Comprehensive dependency security audit, upgrade, test, and deployment workflow.

**When to use**:
- Weekly security maintenance
- Before major releases
- After security advisory notifications
- As part of CI/CD pipeline

**What it does**:
1. Scans all Go projects for CVE vulnerabilities using [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
2. Identifies vulnerable dependencies and available fixes
3. Upgrades dependencies to patched versions
4. Runs full test suite to catch breaking changes
5. Runs linting to ensure code quality
6. Generates detailed security audit report
7. Commits and pushes changes to GitHub

**How to invoke**:

In Claude Code, type:
```
Run the dependency security audit skill
```

Or manually:
```bash
# Install govulncheck if not already installed
go install golang.org/x/vuln/cmd/govulncheck@latest

# Add to PATH
export PATH=$PATH:$(go env GOPATH)/bin

# Scan a project
cd project-1-oauth2-oidc-demo
govulncheck ./...

# If vulnerabilities found, upgrade
go get -u <package>@<version>
go mod tidy

# Test
make test
make lint
make build

# Commit and push
git add .
git commit -m "security: Upgrade dependencies to fix CVE-XXXX-XXXXX"
git push origin main
```

**Expected output**:
- Console report showing vulnerabilities (if any)
- `SECURITY_AUDIT.md` file with detailed findings
- Updated `go.mod` and `go.sum` files
- Git commit with security fixes
- GitHub push

**Last run**: 2025-10-21
**Projects scanned**: 1 (project-1-oauth2-oidc-demo)
**Vulnerabilities found**: 0
**Status**: All dependencies clean

## Creating New Skills

Skills are markdown files in [`.claude/skills/`](./) that Claude Code can execute as workflows.

**Template**:
```markdown
# Skill Name

**Purpose**: Brief description

## Execution Steps

### 1. Step Name
Description and commands

### 2. Next Step
...

## Expected Output
What should be produced

## Success Criteria
How to verify success
```

**Best practices**:
- Include all commands needed
- Document prerequisites
- Provide rollback procedures
- Link to authoritative references
- Include success criteria
- Add examples where helpful

## Skill Ideas for Future

- **License audit**: Scan dependencies for license compliance
- **Performance regression**: Benchmark all endpoints before/after changes
- **Documentation sync**: Ensure README/PRD/CHANGELOG are in sync
- **Security hardening**: Run [gosec](https://github.com/securego/gosec) static analysis
- **Dependency freshness**: Report outdated dependencies (not just vulnerable ones)
- **API contract testing**: Validate OAuth2/OIDC endpoints against RFC specs
- **Load testing**: Run [k6](https://k6.io/) load tests on all services
- **Container security**: Scan Podman images with [trivy](https://github.com/aquasecurity/trivy)

## References

- [Go Vulnerability Database](https://pkg.go.dev/vuln/)
- [govulncheck Documentation](https://go.dev/blog/vuln)
- [GitHub Advisory Database](https://github.com/advisories)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
