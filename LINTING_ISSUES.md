# Linting Issues To Fix

## Critical: 20 Linting Errors in Project 1

### Status
**BLOCKED**: Cannot commit changes until these are fixed (per CLAUDE.md code quality standards)

### Breakdown

#### Errcheck Issues (15 total)
Unchecked error returns - all need proper error handling

1. `cmd/client/main.go:56` - `fmt.Fprint(w, html)`
2. `cmd/client/main.go:172` - `resp.Body.Close()`
3. `cmd/client/main.go:196` - `resp.Body.Close()`
4. `cmd/client/main.go:248` - `fmt.Fprint(w, html)`
5. `cmd/client/main.go:253` - `rand.Read(b)`
6. `cmd/server/main.go:37` - `redisClient.Close()`
7. `cmd/server/main.go:78` - `fmt.Fprint(w, "OK")`
8. `internal/handlers/authorize.go:193` - `fmt.Fprintf` (error response)
9. `internal/handlers/authorize.go:200` - `fmt.Fprintf` (HTML response)
10. `internal/handlers/discovery.go:95` - `json.NewEncoder(w).Encode(doc)`
11. `internal/handlers/discovery.go:126` - `json.NewEncoder(w).Encode(jwks)`
12. `internal/handlers/token.go:366` - `json.NewEncoder(w).Encode(tokenResp)`
13. `internal/handlers/token.go:379` - `json.NewEncoder(w).Encode(errorResp)`
14. `internal/handlers/userinfo.go:63` - `json.NewEncoder(w).Encode(userInfo)`
15. `internal/handlers/userinfo.go:127` - `json.NewEncoder(w).Encode(errorResp)`

#### Staticcheck Issues (5 total)

1. `cmd/server/main.go:191` - SA5011: Possible nil pointer dereference on `block.Bytes`
   - Related check at line 185: `if block == nil`

2. `cmd/server/main.go:220` - SA5011: Possible nil pointer dereference on `block.Bytes`
   - Related check at line 214: `if block == nil`

3. `internal/handlers/authorize.go:129` - SA9003: Empty branch
   ```go
   if authReq.Nonce == "" {
       // Empty - should either add logic or remove check
   }
   ```

### Fixes Needed

#### For Errcheck Issues

**Pattern 1: HTTP Response Writers** (items 1, 4, 7-15)
```go
// Before:
fmt.Fprint(w, html)

// After:
if _, err := fmt.Fprint(w, html); err != nil {
    log.Error().Err(err).Msg("Failed to write HTTP response")
    // Note: Response already started, can't send error to client
}
```

**Pattern 2: Deferred Close** (items 2, 3, 6)
```go
// Before:
defer resp.Body.Close()

// After:
defer func() {
    if err := resp.Body.Close(); err != nil {
        log.Warn().Err(err).Msg("Failed to close response body")
    }
}()
```

**Pattern 3: Crypto Random** (item 5)
```go
// Before:
rand.Read(b)

// After:
if _, err := rand.Read(b); err != nil {
    log.Fatal().Err(err).Msg("Failed to generate random bytes")
}
```

#### For Staticcheck Issues

**SA5011: Nil pointer dereference**
```go
// Current code checks for nil but still has dereference warning
// Need to restructure to satisfy static analysis

// Before:
block, _ := pem.Decode(privateKeyData)
if block == nil {
    log.Fatal().Msg("Failed to parse PEM block")
}
parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes) // Warning here

// After:
block, _ := pem.Decode(privateKeyData)
if block == nil {
    log.Fatal().Msg("Failed to parse PEM block")
    return nil, nil // Unreachable but satisfies staticcheck
}
parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
```

**SA9003: Empty branch**
```go
// Before:
if authReq.Nonce == "" {
    // Empty
}

// After - Option 1: Add logic
if authReq.Nonce == "" {
    log.Debug().Msg("No nonce provided (optional for code flow)")
}

// After - Option 2: Remove if not needed
// Just delete the empty if block
```

### Impact

- **Pre-commit hooks**: Will block all commits until fixed
- **CI/CD**: Would fail if integrated
- **Code quality**: Demonstrates production-ready error handling

### Priority

**HIGH** - Blocks all development until resolved

### Estimated Time

- Errcheck fixes: ~30-45 minutes (15 instances × 2-3 min each)
- Staticcheck fixes: ~15-20 minutes (5 instances)
- **Total**: ~1 hour

### Action Plan

1. Fix all errcheck issues in handlers (items 8-15) - most critical
2. Fix errcheck issues in main files (items 1-7)
3. Fix staticcheck nil pointer issues (items 1-2)
4. Fix staticcheck empty branch (item 3)
5. Run `make lint-all` to verify
6. Commit with proper error handling

### Notes

- Cannot disable linting per CLAUDE.md code quality standards
- All HTTP response write errors should be logged but not Fatal (response already started)
- All deferred Close() calls should check errors
- Cryptographic operations (rand.Read) should Fatal on error
