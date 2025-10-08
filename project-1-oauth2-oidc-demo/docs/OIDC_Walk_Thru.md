# [OIDC](https://openid.net/specs/openid-connect-core-1_0.html) Authorization Code Flow Walkthrough

This document walks through the [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) (OIDC) authentication flow step-by-step, showing both native authentication and third-party [federated identity](https://en.wikipedia.org/wiki/Federated_identity) scenarios.

<details>
    <summary>OIDC Flow Diagram</summary>

![OIDC Authorization Code Flow](OIDC_diagram_Perplexity.png)

This diagram illustrates the complete [OIDC](https://openid.net/specs/openid-connect-core-1_0.html) [Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth) with [PKCE](https://datatracker.ietf.org/doc/html/rfc7636), showing browser redirects, backend token exchange, and [ID token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) validation.

</details>

---

## Flow Comparison: Native vs Federated Authentication

| Step | Native [OIDC](https://openid.net/specs/openid-connect-core-1_0.html) Authentication | Third-Party [OIDC](https://openid.net/specs/openid-connect-core-1_0.html) ([Google](https://developers.google.com/identity/protocols/oauth2/openid-connect)) |
|------|----------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| 1    | User opens application page in browser. | User opens application page in browser. |
| 2    | Application detects no active session and redirects browser to Authorization Server:<br>`https://auth.example.com/authorize?client_id=app-client&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&scope=openid%20profile%20email&state=xyz&response_type=code&code_challenge=ABC&code_challenge_method=S256` | Application detects no active session and redirects browser to Authorization Server:<br>`https://auth.example.com/authorize?...` (may include [IdP](https://en.wikipedia.org/wiki/Identity_provider) hint) |
| 3    | Authorization Server shows login page (email/password fields). | Authorization Server shows login page with "Sign in with [Google](https://developers.google.com/identity/protocols/oauth2/openid-connect)" button. |
| 4    | User submits credentials. | Application redirects to [Google's Authorization Server](https://accounts.google.com):<br>`https://accounts.google.com/o/oauth2/v2/auth?client_id=google-client-id&redirect_uri=https://app.example.com/callback&scope=openid%20email%20profile&response_type=code&state=abc&nonce=nnn` |
| 5    | Authorization Server validates credentials. | [Google](https://developers.google.com/identity/protocols/oauth2/openid-connect) shows user login and consent screens. |
| 6    | On success, Authorization Server redirects browser back to application:<br>`https://app.example.com/callback?code=abc123&state=xyz` ([authorization code](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)) | On success, [Google](https://developers.google.com/identity/protocols/oauth2/openid-connect) redirects browser back to application:<br>`https://app.example.com/callback?code=xyz987&state=abc` ([authorization code](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)) |
| 7    | Application backend sends [POST](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST) request to Token Endpoint:<br>`https://auth.example.com/oauth2/token`<br>with [authorization code](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth) `abc123`, client credentials, [redirect_uri](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2), [code_verifier](https://datatracker.ietf.org/doc/html/rfc7636#section-4.1) ([PKCE](https://datatracker.ietf.org/doc/html/rfc7636)).<br>Response includes:<br>- [ID token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) (user identity, [JWT](https://datatracker.ietf.org/doc/html/rfc7519))<br>- [Access token](https://datatracker.ietf.org/doc/html/rfc6749#section-1.4) ([API](https://en.wikipedia.org/wiki/API) access)<br>- [Refresh token](https://datatracker.ietf.org/doc/html/rfc6749#section-1.5) (optional, long-lived sessions) | Application backend sends [POST](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST) request to [Google Token Endpoint](https://oauth2.googleapis.com/token):<br>`https://oauth2.googleapis.com/token`<br>with [authorization code](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth) `xyz987`, client credentials, [redirect_uri](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2).<br>Response includes:<br>- [ID token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) ([Google](https://developers.google.com/identity/protocols/oauth2/openid-connect) user identity, [JWT](https://datatracker.ietf.org/doc/html/rfc7519))<br>- [Access token](https://datatracker.ietf.org/doc/html/rfc6749#section-1.4)<br>Application maps [Google](https://developers.google.com/identity/protocols/oauth2/openid-connect) identity to local user account. |
| 8    | Application validates [ID token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) signature ([RS256](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1)), creates session, sets [HttpOnly](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies) cookies, and serves protected page. | Application validates [Google ID token](https://developers.google.com/identity/protocols/oauth2/openid-connect#validatinganidtoken) signature, creates session, sets [HttpOnly](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies) cookies, and serves protected page. |

---

## Key Security Features

### [PKCE](https://datatracker.ietf.org/doc/html/rfc7636) (Proof Key for Code Exchange)
- **Prevents**: [Authorization code interception attacks](https://datatracker.ietf.org/doc/html/rfc7636#section-1) on public clients (mobile, [SPA](https://en.wikipedia.org/wiki/Single-page_application))
- **Method**: [S256](https://datatracker.ietf.org/doc/html/rfc7636#section-4.2) ([SHA-256](https://en.wikipedia.org/wiki/SHA-2)) recommended over `plain`
- **Flow**: Client generates random `code_verifier` → sends `code_challenge = BASE64URL(SHA256(code_verifier))` → server validates match

### [State Parameter](https://datatracker.ietf.org/doc/html/rfc6749#section-10.12)
- **Prevents**: [CSRF attacks](https://owasp.org/www-community/attacks/csrf) during authorization flow
- **Implementation**: Cryptographically random value, stored in session, validated on callback

### [ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
- **Signature**: Verify [RS256](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1) signature using [Authorization Server](https://openid.net/specs/openid-connect-core-1_0.html#Terminology)'s public key ([JWK](https://datatracker.ietf.org/doc/html/rfc7517))
- **Claims**: Validate `iss` (issuer), `aud` (audience), `exp` (expiration), `iat` (issued at)
- **Nonce**: Prevents [token replay attacks](https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes)
- **at_hash**: Binds [access token](https://datatracker.ietf.org/doc/html/rfc6749#section-1.4) to [ID token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) (prevents substitution)

### [Token Lifetimes](https://datatracker.ietf.org/doc/html/rfc6749#section-10.3)
- **Access Token**: Short-lived (15 minutes) - minimizes exposure
- **Refresh Token**: Longer-lived (30 days) - enables [token rotation](https://datatracker.ietf.org/doc/html/rfc6749#section-10.4)
- **ID Token**: Matches access token lifetime

---

## Implementation Notes

This walkthrough demonstrates the [OIDC Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth) as implemented in [Project 1](../README.md). For complete implementation details, see:

- [PRD](PRD.md) - Product Requirements Document
- [../pkg/models/oidc.go](../pkg/models/oidc.go) - [OIDC](https://openid.net/specs/openid-connect-core-1_0.html) data models
- [../internal/tokens/jwt.go](../internal/tokens/jwt.go) - [JWT](https://datatracker.ietf.org/doc/html/rfc7519) token generation/validation
- [../internal/tokens/pkce.go](../internal/tokens/pkce.go) - [PKCE](https://datatracker.ietf.org/doc/html/rfc7636) validation

---

## References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 Authorization Framework (RFC 6749)](https://datatracker.ietf.org/doc/html/rfc6749)
- [PKCE Extension (RFC 7636)](https://datatracker.ietf.org/doc/html/rfc7636)
- [JSON Web Token (RFC 7519)](https://datatracker.ietf.org/doc/html/rfc7519)
- [Google OpenID Connect](https://developers.google.com/identity/protocols/oauth2/openid-connect)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)