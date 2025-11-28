// Package main provides the OAuth2/OIDC demo client.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/pkg/models"
)

const (
	authzServerURL = "http://localhost:8080"
	clientID       = "web-app"
	//nolint:gosec // G101: Demo client secret for learning purposes only.
	clientSecret = "web-app-secret-change-in-production"
	redirectURI  = "http://localhost:3000/callback"
	serverPort   = ":3000"
)

var (
	// Store state and code_verifier in memory (use sessions in production).
	sessionStore = make(map[string]*Session)
)

type Session struct {
	State        string
	CodeVerifier string
	Nonce        string
}

func main() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)

	log.Printf("Client app listening on %s", serverPort)
	log.Printf("Visit http://localhost:3000 to start OAuth2/OIDC flow")

	// Create server with timeouts.
	srv := &http.Server{
		Addr:              serverPort,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func handleHome(w http.ResponseWriter, _ *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head><title>OAuth2/OIDC Demo Client</title></head>
<body>
<h1>OAuth2/OIDC Demo Client</h1>
<p>This is a demo client application that demonstrates OAuth2/OIDC Authorization Code Flow with PKCE.</p>
<a href="/login"><button>Login with Authorization Server</button></a>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	if _, err := fmt.Fprint(w, html); err != nil {
		log.Printf("ERROR: Failed to write HTTP response: %v", err)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate state (CSRF protection)
	state := generateRandomString(32)

	// Generate nonce (replay protection for ID token)
	nonce := generateRandomString(32)

	// Generate PKCE code_verifier and code_challenge.
	codeVerifier := generateRandomString(43)
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Store session.
	sessionID := generateRandomString(16)
	sessionStore[sessionID] = &Session{
		State:        state,
		CodeVerifier: codeVerifier,
		Nonce:        nonce,
	}

	// Set session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   600, // 10 minutes
		HttpOnly: true,
	})

	// Build authorization URL.
	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s&nonce=%s&code_challenge=%s&code_challenge_method=S256",
		authzServerURL,
		clientID,
		url.QueryEscape(redirectURI),
		url.QueryEscape("openid profile email offline_access"),
		state,
		nonce,
		codeChallenge,
	)

	// Redirect to authorization server.
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	// Get session.
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "Session not found", http.StatusBadRequest)
		return
	}

	session, ok := sessionStore[cookie.Value]
	if !ok {
		http.Error(w, "Invalid session", http.StatusBadRequest)
		return
	}

	// Parse query parameters.
	query := r.URL.Query()
	code := query.Get("code")
	state := query.Get("state")
	errorCode := query.Get("error")

	// Check for errors from authorization server.
	if errorCode != "" {
		errorDesc := query.Get("error_description")
		http.Error(w, fmt.Sprintf("Authorization error: %s - %s", errorCode, errorDesc), http.StatusBadRequest)
		return
	}

	// Validate state (CSRF protection)
	if state != session.State {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Exchange authorization code for tokens.
	tokens, err := exchangeCodeForTokens(code, session.CodeVerifier)
	if err != nil {
		http.Error(w, fmt.Sprintf("Token exchange failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Fetch user info.
	userInfo, err := fetchUserInfo(tokens.AccessToken)
	if err != nil {
		log.Printf("Failed to fetch user info: %v", err)
		userInfo = map[string]any{"error": err.Error()}
	}

	// Display results.
	displayTokens(w, tokens, userInfo)
}

func exchangeCodeForTokens(code, codeVerifier string) (*TokenResponse, error) {
	// Build token request.
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("code_verifier", codeVerifier)

	// Send POST request to token endpoint.
	resp, err := http.Post(
		authzServerURL+"/oauth2/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("WARN: Failed to close response body: %v", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d: %s", models.ErrTokenEndpointFailed, resp.StatusCode, string(body))
	}

	var tokens TokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, err
	}

	return &tokens, nil
}

func fetchUserInfo(accessToken string) (map[string]any, error) {
	req, err := http.NewRequest("GET", authzServerURL+"/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("WARN: Failed to close response body: %v", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d: %s", models.ErrUserInfoEndpointFailed, resp.StatusCode, string(body))
	}

	var userInfo map[string]any
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}

	return userInfo, nil
}

func displayTokens(w http.ResponseWriter, tokens *TokenResponse, userInfo map[string]any) {
	userInfoJSON, err := json.MarshalIndent(userInfo, "", "  ")
	if err != nil {
		log.Printf("WARN: Failed to marshal user info: %v", err)
		userInfoJSON = []byte("{}")
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Authentication Successful</title></head>
<body>
<h1>✅ Authentication Successful!</h1>

<h2>Tokens Received:</h2>
<h3>Access Token:</h3>
<pre style="background: #f4f4f4; padding: 10px; overflow-x: auto;">%s</pre>

<h3>ID Token:</h3>
<pre style="background: #f4f4f4; padding: 10px; overflow-x: auto;">%s</pre>

<h3>Refresh Token:</h3>
<pre style="background: #f4f4f4; padding: 10px; overflow-x: auto;">%s</pre>

<h3>Expires In:</h3>
<p>%d seconds</p>

<h2>User Info (from /userinfo endpoint):</h2>
<pre style="background: #f4f4f4; padding: 10px; overflow-x: auto;">%s</pre>

<a href="/"><button>Start Over</button></a>
</body>
</html>`,
		tokens.AccessToken,
		tokens.IDToken,
		tokens.RefreshToken,
		tokens.ExpiresIn,
		string(userInfoJSON),
	)

	w.Header().Set("Content-Type", "text/html")
	if _, err := fmt.Fprint(w, html); err != nil {
		log.Printf("ERROR: Failed to write HTTP response: %v", err)
	}
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("Failed to generate random bytes: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)[:length]
}

func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}
