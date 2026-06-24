package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/mattermost/mattermost/server/public/model"
	"golang.org/x/oauth2"
)

const (
	// stateExpiry is how long an OAuth state token is valid.
	stateExpiry = 10 * time.Minute
)

// OAuthState represents the state parameter stored in KV during the OAuth flow.
type OAuthState struct {
	Token    string `json:"token"`
	CreateAt int64  `json:"create_at"`
	ReturnTo string `json:"return_to"`
	// MobileRedirect, when set, is the native app's custom URL scheme callback
	// (e.g. mmauth://callback). Its presence switches the callback into mobile
	// mode: instead of setting a session cookie, the token is handed back to the
	// app via the deep link, mirroring core's /oauth/<service>/mobile_login flow.
	MobileRedirect string `json:"mobile_redirect,omitempty"`
}

// allowedMobileSchemes are the exact custom-scheme callback URLs the native
// Mattermost apps register for SSO deep links (mmauth:// = production app,
// mmauthbeta:// = beta build). The native app always sends the bare callback;
// we append the token query ourselves.
var allowedMobileSchemes = []string{"mmauth://callback", "mmauthbeta://callback"}

// isAllowedMobileScheme reports whether the redirect target is one of the known
// app callback URLs. It matches the full base (optionally followed by a query)
// rather than a loose prefix, so a crafted host/path such as
// "mmauth://callback.evil.com" is rejected.
func isAllowedMobileScheme(redirect string) bool {
	for _, s := range allowedMobileSchemes {
		if redirect == s || strings.HasPrefix(redirect, s+"?") {
			return true
		}
	}
	return false
}

// OIDCUserInfo holds the user information extracted from OIDC claims.
type OIDCUserInfo struct {
	Subject   string `json:"sub"`
	Email     string `json:"email"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// handleOAuth2Connect initiates the OIDC login flow by redirecting the user
// to the identity provider's authorization endpoint.
func (p *Plugin) handleOAuth2Connect(w http.ResponseWriter, r *http.Request) {
	config := p.getConfiguration()
	if !config.Enable {
		http.Error(w, "OIDC authentication is not enabled", http.StatusBadRequest)
		return
	}

	oauthConfig := p.getOAuthConfig()
	if oauthConfig == nil {
		http.Error(w, "OIDC provider not initialized. Check plugin configuration.", http.StatusInternalServerError)
		return
	}

	// Generate a secure state token
	stateToken, err := generateRandomKey(16)
	if err != nil {
		p.API.LogError("Failed to generate state token", "error", err.Error())
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Sign the state token with HMAC to prevent tampering
	signedState := p.signState(stateToken)

	// Store state in KV with expiry information
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" || !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") || strings.ContainsRune(returnTo, '\\') {
		returnTo = "/"
	}

	// Mobile login: the native app reaches this endpoint (via the front proxy
	// rewriting /oauth/openid/mobile_login) and passes its custom-scheme callback
	// as mobile_redirect. Reject anything that is not a known app scheme.
	mobileRedirect := r.URL.Query().Get("mobile_redirect")
	if mobileRedirect != "" && !isAllowedMobileScheme(mobileRedirect) {
		p.API.LogWarn("Rejected mobile_redirect with disallowed scheme", "redirect", mobileRedirect)
		mobileRedirect = ""
	}

	state := OAuthState{
		Token:          stateToken,
		CreateAt:       time.Now().UnixMilli(),
		ReturnTo:       returnTo,
		MobileRedirect: mobileRedirect,
	}

	stateBytes, err := json.Marshal(state)
	if err != nil {
		p.API.LogError("Failed to marshal state", "error", err.Error())
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	kvKey := KVOAuthStatePrefix + stateToken
	if appErr := p.API.KVSetWithExpiry(kvKey, stateBytes, int64(stateExpiry.Seconds())); appErr != nil {
		p.API.LogError("Failed to store OAuth state", "error", appErr.Error())
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Redirect to the OIDC provider
	authURL := oauthConfig.AuthCodeURL(signedState, oauth2.AccessTypeOnline)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOAuth2Callback processes the callback from the OIDC provider after
// the user has authenticated. It validates the state, exchanges the code
// for tokens, verifies the ID token, and either creates or updates the
// Mattermost user account.
func (p *Plugin) handleOAuth2Callback(w http.ResponseWriter, r *http.Request) {
	config := p.getConfiguration()
	if !config.Enable {
		http.Error(w, "OIDC authentication is not enabled", http.StatusBadRequest)
		return
	}

	// Check for errors from the OIDC provider
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		p.API.LogError("OIDC provider returned an error", "error", errParam, "description", errDesc)
		p.renderError(w, "Authentication failed. Check the server logs for details.")
		return
	}

	// Validate the state parameter
	signedState := r.URL.Query().Get("state")
	stateToken, err := p.verifyAndExtractState(signedState)
	if err != nil {
		p.API.LogError("Invalid OAuth state", "error", err.Error())
		p.renderError(w, "Invalid authentication state. Please try again.")
		return
	}

	// Retrieve and atomically consume state from KV.
	// KVCompareAndDelete ensures only the first concurrent callback wins;
	// a second request with the same state token gets deleted=false and is rejected.
	kvKey := KVOAuthStatePrefix + stateToken
	stateBytes, appErr := p.API.KVGet(kvKey)
	if appErr != nil || stateBytes == nil {
		p.API.LogError("OAuth state not found or expired")
		p.renderError(w, "Authentication session expired. Please try again.")
		return
	}
	deleted, delErr := p.API.KVCompareAndDelete(kvKey, stateBytes)
	if delErr != nil {
		p.API.LogError("Failed to consume OAuth state from KV", "key", kvKey, "error", delErr.Error())
		p.renderError(w, "Internal error")
		return
	}
	if !deleted {
		p.API.LogWarn("OAuth state already consumed — possible replay attempt", "key", kvKey)
		p.renderError(w, "Authentication session expired. Please try again.")
		return
	}

	var state OAuthState
	if err := json.Unmarshal(stateBytes, &state); err != nil {
		p.API.LogError("Failed to unmarshal OAuth state", "error", err.Error())
		p.renderError(w, "Internal error")
		return
	}

	// Check state expiry
	if time.Since(time.UnixMilli(state.CreateAt)) > stateExpiry {
		p.renderError(w, "Authentication session expired. Please try again.")
		return
	}

	// Exchange the authorization code for tokens
	code := r.URL.Query().Get("code")
	if code == "" {
		p.renderError(w, "No authorization code received")
		return
	}

	oauthConfig := p.getOAuthConfig()
	if oauthConfig == nil {
		p.API.LogError("OIDC provider not initialized during callback")
		p.renderError(w, "OIDC provider not initialized. Check plugin configuration.")
		return
	}

	verifier := p.getOIDCVerifier()
	if verifier == nil {
		p.API.LogError("OIDC verifier not initialized during callback")
		p.renderError(w, "OIDC provider not initialized. Check plugin configuration.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	token, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		p.API.LogError("Failed to exchange authorization code", "error", err.Error())
		p.renderError(w, "Failed to complete authentication. Please try again.")
		return
	}

	// Extract and verify the ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		p.API.LogError("No ID token in token response")
		p.renderError(w, "Authentication failed: no ID token received")
		return
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		p.API.LogError("Failed to verify ID token", "error", err.Error())
		p.renderError(w, "Authentication failed: invalid ID token")
		return
	}

	// Extract user claims
	userInfo, err := p.extractUserInfo(ctx, idToken, token, config)
	if err != nil {
		p.API.LogError("Failed to extract user info", "error", err.Error())
		p.renderError(w, "Failed to read user information from identity provider")
		return
	}

	// Find or create the Mattermost user
	mmUser, err := p.getOrCreateUser(userInfo, config)
	if err != nil {
		p.API.LogError("Failed to get or create user", "error", err.Error(), "email", userInfo.Email)
		p.renderError(w, "Failed to create or update your account. Contact your administrator.")
		return
	}

	if mmUser.DeleteAt > 0 {
		p.API.LogWarn("Deactivated user attempted OIDC login", "user_id", mmUser.Id, "email", userInfo.Email)
		p.renderError(w, "Your account has been deactivated. Contact your administrator.")
		return
	}
	if mmUser.IsBot {
		p.API.LogWarn("Bot account attempted OIDC login", "user_id", mmUser.Id, "email", userInfo.Email)
		p.renderError(w, "Bot accounts cannot log in via OIDC.")
		return
	}

	// Create a user session with expiry from Mattermost config.
	// Mobile logins use the (typically longer) mobile session length.
	mmConfig := p.API.GetConfig()
	isMobile := state.MobileRedirect != ""

	sessionLengthHours := 720 // fallback: 30 days
	if mmConfig != nil {
		if isMobile && mmConfig.ServiceSettings.SessionLengthMobileInHours != nil {
			sessionLengthHours = *mmConfig.ServiceSettings.SessionLengthMobileInHours
		} else if mmConfig.ServiceSettings.SessionLengthWebInHours != nil {
			sessionLengthHours = *mmConfig.ServiceSettings.SessionLengthWebInHours
		}
	}

	userAgent := r.UserAgent()
	if len(userAgent) > 256 {
		userAgent = userAgent[:256]
	}

	// The native app refuses to complete login unless MMCSRF is non-empty. Bearer-token
	// (mobile) API calls are not CSRF-checked server-side, but we persist the token in
	// session Props so Session.GetCSRF() stays consistent with what we hand the app.
	csrfToken := model.NewId()

	// IsOAuth must be false: it is reserved for sessions backed by a Mattermost
	// OAuth-app access token. Our session has no OAuthAccessData row, so setting
	// IsOAuth=true makes logout's RevokeSession → RevokeAccessToken fail with
	// "could not get token" (HTTP 500). Core SSO logins also use IsOAuth=false and
	// flag OAuth via the isOAuthUser session prop instead.
	session, appErr := p.API.CreateSession(&model.Session{
		UserId:        mmUser.Id,
		Roles:         mmUser.GetRawRoles(),
		IsOAuth:       false,
		ExpiresAt:     model.GetMillis() + int64(sessionLengthHours)*60*60*1000,
		ExpiredNotify: false,
		Props: model.StringMap{
			"platform":                    "oidc_plugin",
			"os":                          userAgent,
			"csrf":                        csrfToken,
			model.UserAuthServiceIsOAuth:  "true",
			model.UserAuthServiceIsMobile: strconv.FormatBool(isMobile),
		},
	})
	if appErr != nil {
		p.API.LogError("Failed to create session", "error", appErr.Error(), "user_id", mmUser.Id)
		p.renderError(w, "Failed to create session. Please try again.")
		return
	}

	// Mobile login: hand the session token back to the native app through its custom
	// URL scheme, mirroring core's /oauth/<service>/mobile_login (token + CSRF appended
	// to the deep link, delivered via an HTML auto-redirect page rather than a 302 —
	// a custom-scheme navigation must originate from within the page).
	if isMobile {
		p.renderMobileAuthComplete(w, state.MobileRedirect, session.Token, csrfToken)
		return
	}

	// Web/desktop: set the session token cookie and redirect.
	siteURL := p.getSiteURL()
	p.setSessionCookie(w, r, session, siteURL)

	returnTo := state.ReturnTo
	if returnTo == "" || !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") || strings.ContainsRune(returnTo, '\\') {
		returnTo = "/"
	}

	http.Redirect(w, r, siteURL+returnTo, http.StatusFound)
}

// renderMobileAuthComplete renders an HTML page that redirects the in-app browser to the
// native app's custom URL scheme with the session token (MMAUTHTOKEN) and CSRF token
// (MMCSRF) attached. This mirrors Mattermost core's utils.RenderMobileAuthComplete:
// a custom-scheme navigation has to come from within the page (meta refresh / link),
// not an HTTP 302, for the app's ASWebAuthenticationSession to intercept it.
func (p *Plugin) renderMobileAuthComplete(w http.ResponseWriter, redirectTo, token, csrf string) {
	u, err := url.Parse(redirectTo)
	if err != nil {
		p.API.LogError("Invalid mobile redirect target", "redirect", redirectTo, "error", err.Error())
		p.renderError(w, "Invalid mobile redirect target")
		return
	}

	q := u.Query()
	q.Set(model.SessionCookieToken, token) // MMAUTHTOKEN
	q.Set(model.SessionCookieCsrf, csrf)   // MMCSRF
	u.RawQuery = q.Encode()
	link := u.String()

	// This page carries the session token + CSRF in the deep-link URL. Prevent any
	// caching and referrer leakage of those secrets.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta http-equiv="refresh" content="0; url=%s">
	<title>Authentication complete</title>
</head>
<body style="font-family: sans-serif; max-width: 600px; margin: 50px auto; text-align: center;">
	<h2>Authentication complete</h2>
	<p>Redirecting you back to the app&hellip;</p>
	<p><a href="%s">Tap here if you are not redirected automatically</a></p>
</body>
</html>`, html.EscapeString(link), html.EscapeString(link))
}

// extractUserInfo parses the OIDC claims into an OIDCUserInfo struct.
func (p *Plugin) extractUserInfo(ctx context.Context, idToken *oidc.IDToken, oauthToken *oauth2.Token, config *Configuration) (*OIDCUserInfo, error) {
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	// Also try to get claims from userinfo endpoint for additional data
	provider := p.getOIDCProvider()
	if provider != nil && oauthToken != nil && oauthToken.AccessToken != "" {
		tokenSource := oauth2.StaticTokenSource(oauthToken)
		userInfoResp, err := provider.UserInfo(ctx, tokenSource)
		if err == nil {
			var uiClaims map[string]interface{}
			if err := userInfoResp.Claims(&uiClaims); err == nil {
				// Merge userinfo claims into ID token claims (ID token takes priority)
				for k, v := range uiClaims {
					if _, exists := claims[k]; !exists {
						claims[k] = v
					}
				}
			}
		}
	}

	claimKeys := make([]string, 0, len(claims))
	for k := range claims {
		claimKeys = append(claimKeys, k)
	}
	p.API.LogDebug("OIDC claims received", "claim_keys", strings.Join(claimKeys, ", "))

	info := &OIDCUserInfo{
		Subject:   idToken.Subject,
		Email:     getStringClaim(claims, config.EmailClaim),
		Username:  getStringClaim(claims, config.UsernameClaim),
		FirstName: getStringClaim(claims, config.FirstNameClaim),
		LastName:  getStringClaim(claims, config.LastNameClaim),
	}

	// Fallback: use email prefix as username if no username claim found
	if info.Username == "" && info.Email != "" {
		parts := strings.SplitN(info.Email, "@", 2)
		info.Username = parts[0]
	}

	// Sanitize username for Mattermost compatibility
	info.Username = sanitizeUsername(info.Username)

	if info.Subject == "" {
		return nil, fmt.Errorf("OIDC subject (sub) claim is empty")
	}

	if info.Email == "" {
		return nil, fmt.Errorf("email claim '%s' is empty or not present in the ID token", config.EmailClaim)
	}
	if _, err := mail.ParseAddress(info.Email); err != nil {
		return nil, fmt.Errorf("OIDC provider returned invalid email address: %w", err)
	}

	return info, nil
}

// KVOIDCUserPrefix is the KV store key prefix for mapping OIDC subjects to Mattermost user IDs.
const KVOIDCUserPrefix = "oidc_user_"

// getOrCreateUser finds an existing user by OIDC subject (via KV mapping) or email, or creates a new one.
func (p *Plugin) getOrCreateUser(userInfo *OIDCUserInfo, config *Configuration) (*model.User, error) {
	// First, try to find user by OIDC subject via KV mapping
	kvKey := KVOIDCUserPrefix + userInfo.Subject
	if userIDBytes, appErr := p.API.KVGet(kvKey); appErr == nil && userIDBytes != nil {
		userID := string(userIDBytes)
		user, getErr := p.API.GetUser(userID)
		if getErr == nil && user != nil {
			return p.updateUserIfChanged(user, userInfo)
		}
		// User was deleted — clean up stale mapping
		if delErr := p.API.KVDelete(kvKey); delErr != nil {
			p.API.LogWarn("Failed to delete stale OIDC user mapping", "key", kvKey, "error", delErr.Error())
		}
	}

	// Try to find by email and optionally link to OIDC
	user, appErr := p.API.GetUserByEmail(userInfo.Email)
	if appErr == nil && user != nil {
		if !config.AutoLinkByEmail {
			return nil, fmt.Errorf("user with email %s exists but auto-linking is disabled", userInfo.Email)
		}
		p.API.LogInfo("Linking existing user to OIDC", "user_id", user.Id, "email", userInfo.Email)
		_, updateErr := p.API.UpdateUserAuth(user.Id, &model.UserAuth{
			AuthService: AuthService,
			AuthData:    model.NewPointer(userInfo.Subject),
		})
		if updateErr != nil {
			return nil, fmt.Errorf("failed to link user to OIDC: %s", updateErr.Error())
		}
		// Store OIDC subject → user ID mapping
		if setErr := p.API.KVSet(kvKey, []byte(user.Id)); setErr != nil {
			p.API.LogWarn("Failed to store OIDC user mapping", "key", kvKey, "error", setErr.Error())
		}
		return p.updateUserIfChanged(user, userInfo)
	}

	// User doesn't exist — create if enabled
	if !config.AutoCreateAccounts {
		return nil, fmt.Errorf("user with email %s not found and auto-creation is disabled", userInfo.Email)
	}

	newUser := &model.User{
		Email:         userInfo.Email,
		Username:      userInfo.Username,
		FirstName:     userInfo.FirstName,
		LastName:      userInfo.LastName,
		AuthService:   AuthService,
		AuthData:      model.NewPointer(userInfo.Subject),
		EmailVerified: true,
	}

	createdUser, appErr := p.API.CreateUser(newUser)
	if appErr != nil {
		// Username conflict? Try appending a random suffix.
		if strings.Contains(appErr.Message, "username") || appErr.Id == "app.user.save.username_exists.app_error" {
			suffix, _ := generateRandomKey(3)
			newUser.Username = newUser.Username + "_" + suffix
			createdUser, appErr = p.API.CreateUser(newUser)
			if appErr != nil {
				return nil, fmt.Errorf("failed to create user (with suffix): %s", appErr.Error())
			}
		} else {
			return nil, fmt.Errorf("failed to create user: %s", appErr.Error())
		}
	}

	p.API.LogInfo("Created new user via OIDC", "user_id", createdUser.Id, "email", createdUser.Email)

	// Store OIDC subject → user ID mapping
	if setErr := p.API.KVSet(kvKey, []byte(createdUser.Id)); setErr != nil {
		p.API.LogWarn("Failed to store OIDC user mapping for new user", "key", kvKey, "error", setErr.Error())
	}

	// Auto-join the default team if configured
	if config.DefaultTeam != "" {
		team, teamErr := p.API.GetTeamByName(config.DefaultTeam)
		if teamErr == nil && team != nil {
			_, memberErr := p.API.CreateTeamMember(team.Id, createdUser.Id)
			if memberErr != nil {
				p.API.LogWarn("Failed to add user to default team",
					"user_id", createdUser.Id,
					"team", config.DefaultTeam,
					"error", memberErr.Error(),
				)
			}
		} else {
			p.API.LogWarn("Default team not found", "team", config.DefaultTeam)
		}
	}

	return createdUser, nil
}

// updateUserIfChanged updates the Mattermost user profile if OIDC claims have changed.
func (p *Plugin) updateUserIfChanged(user *model.User, info *OIDCUserInfo) (*model.User, error) {
	changed := false

	if info.Email != "" && user.Email != info.Email {
		user.Email = info.Email
		changed = true
	}
	if info.FirstName != "" && user.FirstName != info.FirstName {
		user.FirstName = info.FirstName
		changed = true
	}
	if info.LastName != "" && user.LastName != info.LastName {
		user.LastName = info.LastName
		changed = true
	}

	if !changed {
		return user, nil
	}

	updatedUser, appErr := p.API.UpdateUser(user)
	if appErr != nil {
		return nil, fmt.Errorf("failed to update user: %s", appErr.Error())
	}
	return updatedUser, nil
}

// handleGetPublicConfig returns the publicly visible configuration (button text/color, enable status).
func (p *Plugin) handleGetPublicConfig(w http.ResponseWriter, r *http.Request) {
	config := p.getConfiguration()

	publicConfig := map[string]interface{}{
		"enable":       config.Enable,
		"button_text":  config.ButtonText,
		"button_color": config.ButtonColor,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(publicConfig); err != nil {
		p.API.LogError("Failed to encode public config", "error", err.Error())
	}
}

// signState creates an HMAC-signed state string.
func (p *Plugin) signState(token string) string {
	mac := hmac.New(sha256.New, []byte(p.getEncryptionKey()))
	mac.Write([]byte(token))
	signature := hex.EncodeToString(mac.Sum(nil))
	return token + ":" + signature
}

// verifyAndExtractState verifies the HMAC signature and extracts the state token.
func (p *Plugin) verifyAndExtractState(signedState string) (string, error) {
	parts := strings.SplitN(signedState, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("malformed state parameter")
	}

	token := parts[0]
	expectedSigned := p.signState(token)

	if !hmac.Equal([]byte(signedState), []byte(expectedSigned)) {
		return "", fmt.Errorf("state signature verification failed")
	}

	return token, nil
}

// setSessionCookie writes the Mattermost session token as a cookie.
func (p *Plugin) setSessionCookie(w http.ResponseWriter, r *http.Request, session *model.Session, siteURL string) {
	secure := strings.HasPrefix(siteURL, "https")

	cookie := &http.Cookie{
		Name:     "MMAUTHTOKEN",
		Value:    session.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	// Also set MMUSERID cookie for the webapp
	// (The webapp uses this to know that a user is logged in)
	useridCookie := &http.Cookie{
		Name:     "MMUSERID",
		Value:    session.UserId,
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, useridCookie)
}

// renderError renders a simple error page to the user.
func (p *Plugin) renderError(w http.ResponseWriter, message string) {
	siteURL := p.getSiteURL()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Authentication Error</title></head>
<body style="font-family: sans-serif; max-width: 600px; margin: 50px auto; text-align: center;">
	<h2>Authentication Error</h2>
	<p>%s</p>
	<p><a href="%s/login">Back to Login</a></p>
</body>
</html>`, html.EscapeString(message), html.EscapeString(siteURL))
}

// getStringClaim safely extracts a string claim from a claims map.
func getStringClaim(claims map[string]interface{}, key string) string {
	if val, ok := claims[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// sanitizeUsername makes a username compatible with Mattermost's requirements.
func sanitizeUsername(username string) string {
	username = strings.ToLower(username)
	username = strings.TrimSpace(username)

	// Replace disallowed characters with underscores
	var sanitized strings.Builder
	for _, r := range username {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			sanitized.WriteRune(r)
		} else {
			sanitized.WriteRune('_')
		}
	}

	result := sanitized.String()

	// Must start with a letter
	if len(result) > 0 && (result[0] < 'a' || result[0] > 'z') {
		result = "u" + result
	}

	// Minimum length 3
	for len(result) < 3 {
		result += "_"
	}

	// Maximum length 64
	if len(result) > 64 {
		result = result[:64]
	}

	return result
}
