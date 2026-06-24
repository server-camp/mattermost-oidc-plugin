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

	state := OAuthState{
		Token:    stateToken,
		CreateAt: time.Now().UnixMilli(),
		ReturnTo: returnTo,
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

	// Create a user session with expiry from Mattermost config
	mmConfig := p.API.GetConfig()
	sessionLengthHours := 720 // fallback: 30 days
	if mmConfig != nil && mmConfig.ServiceSettings.SessionLengthWebInHours != nil {
		sessionLengthHours = *mmConfig.ServiceSettings.SessionLengthWebInHours
	}

	userAgent := r.UserAgent()
	if len(userAgent) > 256 {
		userAgent = userAgent[:256]
	}

	session, appErr := p.API.CreateSession(&model.Session{
		UserId:        mmUser.Id,
		Roles:         mmUser.GetRawRoles(),
		IsOAuth:       true,
		ExpiresAt:     model.GetMillis() + int64(sessionLengthHours)*60*60*1000,
		ExpiredNotify: false,
		Props: model.StringMap{
			"platform": "oidc_plugin",
			"os":       userAgent,
		},
	})
	if appErr != nil {
		p.API.LogError("Failed to create session", "error", appErr.Error(), "user_id", mmUser.Id)
		p.renderError(w, "Failed to create session. Please try again.")
		return
	}

	// Set the session token cookie and redirect
	siteURL := p.getSiteURL()
	p.setSessionCookie(w, r, session, siteURL)

	returnTo := state.ReturnTo
	if returnTo == "" || !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") || strings.ContainsRune(returnTo, '\\') {
		returnTo = "/"
	}

	http.Redirect(w, r, siteURL+returnTo, http.StatusFound)
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
	config := p.getConfiguration()
	mac := hmac.New(sha256.New, []byte(config.EncryptionKey))
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
