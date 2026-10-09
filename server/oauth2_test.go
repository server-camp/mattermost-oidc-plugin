package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin/plugintest"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

func TestGetStringClaim(t *testing.T) {
	claims := map[string]interface{}{
		"sub":                "user-123",
		"email":              "test@example.com",
		"preferred_username": "testuser",
		"position":           "Software Engineer",
		"job_title":          "DevOps Lead",
		"numeric_value":      42,
		"nil_value":          nil,
	}

	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{"existing string claim", "sub", "user-123"},
		{"existing email claim", "email", "test@example.com"},
		{"existing position claim", "position", "Software Engineer"},
		{"existing job_title claim", "job_title", "DevOps Lead"},
		{"non-existent claim", "missing", ""},
		{"numeric claim returns empty", "numeric_value", ""},
		{"nil claim returns empty", "nil_value", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStringClaim(claims, tt.key)
			if result != tt.expected {
				t.Errorf("getStringClaim(%q) = %q, want %q", tt.key, result, tt.expected)
			}
		})
	}
}

func TestGetBoolClaim(t *testing.T) {
	claims := map[string]interface{}{
		"email_verified": true,
		"verified_str":   "true",
		"false_str":      "false",
		"numeric_value":  1,
	}

	tests := []struct {
		name     string
		key      string
		expected *bool
	}{
		{"bool true", "email_verified", model.NewPointer(true)},
		{"string true", "verified_str", model.NewPointer(true)},
		{"string false", "false_str", model.NewPointer(false)},
		{"missing claim", "missing", nil},
		{"empty key", "", nil},
		{"unexpected type", "numeric_value", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getBoolClaim(claims, tt.key)
			switch {
			case tt.expected == nil && got != nil:
				t.Errorf("getBoolClaim(%q) = %v, want nil", tt.key, *got)
			case tt.expected != nil && got == nil:
				t.Errorf("getBoolClaim(%q) = nil, want %v", tt.key, *tt.expected)
			case tt.expected != nil && got != nil && *got != *tt.expected:
				t.Errorf("getBoolClaim(%q) = %v, want %v", tt.key, *got, *tt.expected)
			}
		})
	}
}

func TestGenerateRandomKey(t *testing.T) {
	key1, err := generateRandomKey(16)
	if err != nil {
		t.Fatalf("generateRandomKey failed: %v", err)
	}

	if len(key1) != 32 { // 16 bytes = 32 hex characters
		t.Errorf("key length = %d, want 32", len(key1))
	}

	// Two keys should be different
	key2, err := generateRandomKey(16)
	if err != nil {
		t.Fatalf("generateRandomKey failed: %v", err)
	}

	if key1 == key2 {
		t.Error("Two generated keys should not be identical")
	}
}

func TestStateSignAndVerify(t *testing.T) {
	p := &Plugin{}
	p.encryptionKey = "test-encryption-key-1234567890abcdef"

	token := "test-state-token"
	signed := p.signState(token)

	// Should contain the token and a signature
	if signed == token {
		t.Error("Signed state should differ from raw token")
	}

	// Verification should succeed
	extracted, err := p.verifyAndExtractState(signed)
	if err != nil {
		t.Fatalf("verifyAndExtractState failed: %v", err)
	}
	if extracted != token {
		t.Errorf("extracted token = %q, want %q", extracted, token)
	}

	// Tampered state should fail
	_, err = p.verifyAndExtractState("tampered-token:invalidsignature")
	if err == nil {
		t.Error("Tampered state should fail verification")
	}

	// Malformed state should fail
	_, err = p.verifyAndExtractState("noseparator")
	if err == nil {
		t.Error("Malformed state should fail verification")
	}
}

func TestRenderPopupAuthComplete(t *testing.T) {
	p := &Plugin{}

	rec := httptest.NewRecorder()
	p.renderPopupAuthComplete(rec, "https://mm.example.com", "/team/channel")

	res := rec.Result()
	if res.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if cc := res.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want it to contain no-store", cc)
	}

	body := rec.Body.String()

	// The target must be embedded as a safe JS string literal (json-encoded).
	if !strings.Contains(body, `var target = "https://mm.example.com/team/channel"`) {
		t.Errorf("body missing json-encoded target; got:\n%s", body)
	}
	// The popup hands control back to the opener and broadcasts via localStorage.
	if !strings.Contains(body, "window.opener") {
		t.Error("body should navigate window.opener")
	}
	if !strings.Contains(body, "mattermost_oidc_login") {
		t.Error("body should broadcast completion via localStorage key")
	}
}

// TestRenderPopupAuthCompleteNoScriptInjection ensures a return path crafted to
// break out of the <script> block is neutralised by the json/HTML escaping.
func TestRenderPopupAuthCompleteNoScriptInjection(t *testing.T) {
	p := &Plugin{}

	rec := httptest.NewRecorder()
	// A hostile-looking path (it would already be rejected upstream, but the render
	// must be safe regardless of what reaches it).
	p.renderPopupAuthComplete(rec, "https://mm.example.com", `/x</script><script>alert(1)</script>`)

	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Errorf("unescaped </script> breakout present in body:\n%s", body)
	}
}

func TestStateCookieMatches(t *testing.T) {
	const token = "abc123deadbeef"

	newReq := func(cookieVal *string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/oauth2/callback", nil)
		if cookieVal != nil {
			r.AddCookie(&http.Cookie{Name: oidcStateCookie, Value: *cookieVal})
		}
		return r
	}
	strp := func(s string) *string { return &s }

	tests := []struct {
		name   string
		cookie *string // nil = no cookie set
		want   bool
	}{
		{"matching cookie", strp(token), true},
		{"missing cookie", nil, false},
		{"empty cookie", strp(""), false},
		{"mismatched cookie", strp("wrong-token"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := stateCookieMatches(newReq(tc.cookie), token); got != tc.want {
				t.Errorf("stateCookieMatches() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUpdateUserIfChanged(t *testing.T) {
	t.Run("no changes", func(t *testing.T) {
		p := &Plugin{}
		user := &model.User{
			Id:        "user-1",
			Email:     "user@example.com",
			FirstName: "John",
			LastName:  "Doe",
			Position:  "Software Engineer",
		}
		info := &OIDCUserInfo{
			Email:     "user@example.com",
			FirstName: "John",
			LastName:  "Doe",
			Position:  "Software Engineer",
		}

		updated, err := p.updateUserIfChanged(user, info)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if updated.Position != "Software Engineer" {
			t.Errorf("Position = %q, want 'Software Engineer'", updated.Position)
		}
	})

	t.Run("position changed", func(t *testing.T) {
		api := &plugintest.API{}
		p := &Plugin{}
		p.SetAPI(api)

		user := &model.User{
			Id:        "user-1",
			Email:     "user@example.com",
			FirstName: "John",
			LastName:  "Doe",
			Position:  "Junior Developer",
		}
		info := &OIDCUserInfo{
			Email:     "user@example.com",
			FirstName: "John",
			LastName:  "Doe",
			Position:  "Senior Developer",
		}

		api.On("UpdateUser", mock.MatchedBy(func(u *model.User) bool {
			return u.Id == "user-1" && u.Position == "Senior Developer"
		})).Return(func(u *model.User) *model.User {
			return u
		}, nil)

		updated, err := p.updateUserIfChanged(user, info)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if updated.Position != "Senior Developer" {
			t.Errorf("Position = %q, want 'Senior Developer'", updated.Position)
		}
		api.AssertExpectations(t)
	})

	t.Run("empty position claim does not overwrite existing position", func(t *testing.T) {
		p := &Plugin{}
		user := &model.User{
			Id:        "user-1",
			Email:     "user@example.com",
			FirstName: "John",
			LastName:  "Doe",
			Position:  "Product Manager",
		}
		info := &OIDCUserInfo{
			Email:     "user@example.com",
			FirstName: "John",
			LastName:  "Doe",
			Position:  "",
		}

		updated, err := p.updateUserIfChanged(user, info)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if updated.Position != "Product Manager" {
			t.Errorf("Position = %q, want 'Product Manager'", updated.Position)
		}
	})

	t.Run("all fields updated when changed", func(t *testing.T) {
		api := &plugintest.API{}
		p := &Plugin{}
		p.SetAPI(api)

		user := &model.User{
			Id:        "user-1",
			Email:     "old@example.com",
			FirstName: "OldFirst",
			LastName:  "OldLast",
			Position:  "OldPos",
		}
		info := &OIDCUserInfo{
			Email:     "new@example.com",
			FirstName: "NewFirst",
			LastName:  "NewLast",
			Position:  "NewPos",
		}

		api.On("UpdateUser", mock.MatchedBy(func(u *model.User) bool {
			return u.Email == "new@example.com" &&
				u.FirstName == "NewFirst" &&
				u.LastName == "NewLast" &&
				u.Position == "NewPos"
		})).Return(func(u *model.User) *model.User {
			return u
		}, nil)

		updated, err := p.updateUserIfChanged(user, info)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if updated.Email != "new@example.com" || updated.FirstName != "NewFirst" || updated.LastName != "NewLast" || updated.Position != "NewPos" {
			t.Errorf("user fields not updated correctly: %+v", updated)
		}
		api.AssertExpectations(t)
	})

	t.Run("api update error propagates", func(t *testing.T) {
		api := &plugintest.API{}
		p := &Plugin{}
		p.SetAPI(api)

		user := &model.User{
			Id:       "user-1",
			Email:    "user@example.com",
			Position: "OldPos",
		}
		info := &OIDCUserInfo{
			Position: "NewPos",
		}

		api.On("UpdateUser", mock.Anything).Return(nil, model.NewAppError("UpdateUser", "test.error", nil, "failed to update", http.StatusInternalServerError))

		_, err := p.updateUserIfChanged(user, info)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "failed to update user") {
			t.Errorf("error = %q, want containing 'failed to update user'", err.Error())
		}
		api.AssertExpectations(t)
	})

	t.Run("email verified revoked by provider", func(t *testing.T) {
		api := &plugintest.API{}
		p := &Plugin{}
		p.SetAPI(api)

		user := &model.User{
			Id:            "user-1",
			Email:         "user@example.com",
			EmailVerified: true,
		}
		info := &OIDCUserInfo{
			Email:         "user@example.com",
			EmailVerified: model.NewPointer(false),
		}

		api.On("UpdateUser", mock.MatchedBy(func(u *model.User) bool {
			return u.Id == "user-1" && !u.EmailVerified
		})).Return(func(u *model.User) *model.User {
			return u
		}, nil)

		updated, err := p.updateUserIfChanged(user, info)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if updated.EmailVerified {
			t.Error("EmailVerified should be false after provider downgrade")
		}
		api.AssertExpectations(t)
	})

	t.Run("nil email verified claim leaves user untouched", func(t *testing.T) {
		p := &Plugin{}
		user := &model.User{
			Id:            "user-1",
			Email:         "user@example.com",
			EmailVerified: true,
		}
		info := &OIDCUserInfo{
			Email:         "user@example.com",
			EmailVerified: nil,
		}

		updated, err := p.updateUserIfChanged(user, info)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !updated.EmailVerified {
			t.Error("EmailVerified should remain true when claim is absent")
		}
	})
}

func TestNonceMatches(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		got      string
		want     bool
	}{
		{"equal", "abc123", "abc123", true},
		{"mismatch", "abc123", "other", false},
		{"empty got", "abc123", "", false},
		{"empty expected", "", "abc123", false},
		{"both empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nonceMatches(tt.expected, tt.got); got != tt.want {
				t.Errorf("nonceMatches(%q, %q) = %v, want %v", tt.expected, tt.got, got, tt.want)
			}
		})
	}
}

func TestOAuthStatePKCENonceRoundTrip(t *testing.T) {
	orig := OAuthState{
		Token:        "tok",
		CreateAt:     1,
		ReturnTo:     "/",
		CodeVerifier: oauth2.GenerateVerifier(),
		Nonce:        "deadbeef",
	}
	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got OAuthState
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.CodeVerifier != orig.CodeVerifier || got.Nonce != orig.Nonce {
		t.Errorf("round-trip = %+v, want verifier/nonce from %+v", got, orig)
	}
}

func TestSetSessionCookie(t *testing.T) {
	newPlugin := func(allowSubdomains bool) *Plugin {
		siteURL := "https://chat.example.com"
		api := &plugintest.API{}
		api.On("GetConfig").Return(&model.Config{ServiceSettings: model.ServiceSettings{
			SiteURL:                   &siteURL,
			AllowCookiesForSubdomains: &allowSubdomains,
		}})
		p := &Plugin{}
		p.SetAPI(api)
		return p
	}
	session := &model.Session{
		Token:     "new-token",
		UserId:    "user-1",
		ExpiresAt: model.GetMillis() + 720*60*60*1000,
		Props:     model.StringMap{"csrf": "csrf-1"},
	}
	// The browser may still hold a stale core cookie; the new one must replace it.
	req := httptest.NewRequest(http.MethodGet, "https://chat.example.com/plugins/mattermost-oidc/oauth2/callback", nil)

	t.Run("subdomain cookies: same Domain as core, host-only copies dropped", func(t *testing.T) {
		rec := httptest.NewRecorder()
		newPlugin(true).setSessionCookie(rec, req, session, "https://chat.example.com")

		set := map[string]*http.Cookie{}
		dropped := map[string]*http.Cookie{}
		for _, c := range rec.Result().Cookies() {
			if c.MaxAge < 0 {
				if c.Domain != "" {
					t.Errorf("%s: deletion must target the host-only cookie, got Domain=%q", c.Name, c.Domain)
				}
				if set[c.Name] != nil {
					t.Errorf("%s: deletion must precede setting the new cookie", c.Name)
				}
				dropped[c.Name] = c
				continue
			}
			set[c.Name] = c
		}
		want := map[string]string{
			model.SessionCookieToken: "new-token",
			model.SessionCookieUser:  "user-1",
			model.SessionCookieCsrf:  "csrf-1",
		}
		for name, value := range want {
			c := set[name]
			if c == nil {
				t.Fatalf("%s not set", name)
			}
			if c.Value != value {
				t.Errorf("%s = %q, want %q", name, c.Value, value)
			}
			if c.Domain != "chat.example.com" {
				t.Errorf("%s Domain = %q, want chat.example.com", name, c.Domain)
			}
			if c.Path != "/" {
				t.Errorf("%s Path = %q, want /", name, c.Path)
			}
			if c.MaxAge <= 0 {
				t.Errorf("%s MaxAge = %d, want a persistent cookie", name, c.MaxAge)
			}
			if !c.Secure {
				t.Errorf("%s should be Secure on https", name)
			}
			if dropped[name] == nil {
				t.Errorf("%s: host-only copy not dropped", name)
			}
		}
		if !set[model.SessionCookieToken].HttpOnly {
			t.Error("MMAUTHTOKEN must be HttpOnly")
		}
		if !dropped[model.SessionCookieToken].HttpOnly {
			t.Error("MMAUTHTOKEN deletion cookie must preserve HttpOnly")
		}
		if dropped[model.SessionCookieToken].SameSite != http.SameSiteLaxMode {
			t.Error("MMAUTHTOKEN deletion cookie must preserve SameSite")
		}
		if set[model.SessionCookieCsrf].HttpOnly {
			t.Error("MMCSRF must be readable by the webapp")
		}
	})

	t.Run("host-only cookies when subdomains are off", func(t *testing.T) {
		rec := httptest.NewRecorder()
		newPlugin(false).setSessionCookie(rec, req, session, "https://chat.example.com")

		cookies := rec.Result().Cookies()
		if len(cookies) != 3 {
			t.Fatalf("got %d cookies, want 3 (no deletions)", len(cookies))
		}
		for _, c := range cookies {
			if c.Domain != "" {
				t.Errorf("%s Domain = %q, want host-only", c.Name, c.Domain)
			}
			if c.Path != "/" {
				t.Errorf("%s Path = %q, want /", c.Name, c.Path)
			}
			if c.MaxAge <= 0 {
				t.Errorf("%s MaxAge = %d, want a persistent cookie", c.Name, c.MaxAge)
			}
		}
	})

	t.Run("subpath with subdomain cookies", func(t *testing.T) {
		rec := httptest.NewRecorder()
		newPlugin(true).setSessionCookie(rec, req, session, "https://chat.example.com/mattermost")

		set := map[string]*http.Cookie{}
		var dropped int
		for _, c := range rec.Result().Cookies() {
			if c.MaxAge < 0 {
				if c.Domain != "" {
					t.Errorf("%s: deletion must target host-only cookie, got Domain=%q", c.Name, c.Domain)
				}
				if c.Path == "/mattermost" {
					dropped++
				}
				continue
			}
			set[c.Name] = c
		}
		if dropped != 3 {
			t.Errorf("got %d deletions at /mattermost, want 3", dropped)
		}
		for _, name := range []string{model.SessionCookieToken, model.SessionCookieUser, model.SessionCookieCsrf} {
			c := set[name]
			if c == nil {
				t.Fatalf("%s not set", name)
			}
			if c.Path != "/mattermost" {
				t.Errorf("%s Path = %q, want /mattermost", name, c.Path)
			}
			if c.Domain != "chat.example.com" {
				t.Errorf("%s Domain = %q, want chat.example.com", name, c.Domain)
			}
		}
	})
}

func TestGetCookiePath(t *testing.T) {
	tests := []struct {
		siteURL string
		want    string
	}{
		{"", "/"},
		{"https://chat.example.com", "/"},
		{"https://chat.example.com/", "/"},
		{"https://chat.example.com/mattermost", "/mattermost"},
		{"https://chat.example.com/mattermost/", "/mattermost"},
		{"https://chat.example.com/sub/path", "/sub/path"},
		{"http://localhost:8065/mm", "/mm"},
	}
	for _, tc := range tests {
		got := getCookiePath(tc.siteURL)
		if got != tc.want {
			t.Errorf("getCookiePath(%q) = %q, want %q", tc.siteURL, got, tc.want)
		}
	}
}

// quietAPI drops log calls, which plugintest.API would reject as unexpected.
type quietAPI struct{ *plugintest.API }

func (quietAPI) LogInfo(string, ...any)  {}
func (quietAPI) LogWarn(string, ...any)  {}
func (quietAPI) LogError(string, ...any) {}

// newDiscoveryTestPlugin returns a plugin whose issuer answers discovery only while up is true; onRequest may be nil.
func newDiscoveryTestPlugin(t *testing.T, up *atomic.Bool, hits *atomic.Int32, onRequest func()) (*Plugin, string) {
	var issuer string

	t.Helper()

	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if onRequest != nil {
			onRequest()
		}
		if !up.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/certs",
		})
	}))
	t.Cleanup(idp.Close)
	issuer = idp.URL

	api := &plugintest.API{}
	api.On("GetConfig").Return(&model.Config{ServiceSettings: model.ServiceSettings{SiteURL: model.NewPointer("https://mm.example.com")}})
	api.On("KVSetWithExpiry", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	p := &Plugin{encryptionKey: "test-key", discoveryClient: idp.Client()}
	p.SetAPI(quietAPI{api})
	p.setConfiguration(&Configuration{Enable: true, IssuerURL: issuer, ClientID: "mattermost", ClientSecret: "secret", Scopes: "openid"})
	return p, issuer
}

func TestConnectRetriesFailedDiscovery(t *testing.T) {
	var up atomic.Bool
	var hits atomic.Int32
	p, issuer := newDiscoveryTestPlugin(t, &up, &hits, nil)
	if err := p.initOIDCProvider(); err == nil {
		t.Fatal("discovery succeeded while the issuer was down")
	}

	up.Store(true)
	rec := httptest.NewRecorder()
	p.handleOAuth2Connect(rec, httptest.NewRequest(http.MethodGet, "/oauth2/connect", nil))

	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), issuer+"/auth?") {
		t.Fatalf("got %d to %q, want a redirect to the issuer", rec.Code, rec.Header().Get("Location"))
	}
}

func TestConnectRetriesDiscoveryAtMostOncePerInterval(t *testing.T) {
	var up atomic.Bool
	var hits atomic.Int32
	p, _ := newDiscoveryTestPlugin(t, &up, &hits, nil)
	_ = p.initOIDCProvider()

	for range 3 {
		rec := httptest.NewRecorder()
		p.handleOAuth2Connect(rec, httptest.NewRequest(http.MethodGet, "/oauth2/connect", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("got %d while the issuer is down, want 500", rec.Code)
		}
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("issuer hit %d times, want 2: one failed discovery and one retry", got)
	}
}

func TestConnectDoesNotRetryInvalidConfiguration(t *testing.T) {
	var up atomic.Bool
	var hits atomic.Int32
	p, _ := newDiscoveryTestPlugin(t, &up, &hits, nil)
	up.Store(true)
	config := p.getConfiguration()
	config.ClientSecret = ""
	p.setConfiguration(config)

	rec := httptest.NewRecorder()
	p.handleOAuth2Connect(rec, httptest.NewRequest(http.MethodGet, "/oauth2/connect", nil))

	if rec.Code != http.StatusInternalServerError || hits.Load() != 0 {
		t.Fatalf("got %d after %d discovery calls, want 500 and none", rec.Code, hits.Load())
	}
}

func TestDiscoveryDiscardedWhenConfigurationChanges(t *testing.T) {
	var up atomic.Bool
	var hits atomic.Int32
	var p *Plugin
	p, _ = newDiscoveryTestPlugin(t, &up, &hits, func() {
		config := p.getConfiguration()
		config.ClientID = "rotated"
		p.setConfiguration(config)
	})
	up.Store(true)

	if err := p.initOIDCProvider(); err == nil || p.getOAuthConfig() != nil {
		t.Fatalf("got err=%v, provider set=%t; want the stale discovery discarded", err, p.getOAuthConfig() != nil)
	}
}

func TestOnConfigurationChangeDiscardsOldProviderOnInvalidConfig(t *testing.T) {
	var up atomic.Bool
	var hits atomic.Int32
	p, issuer := newDiscoveryTestPlugin(t, &up, &hits, nil)
	up.Store(true)

	// Successfully initialize provider with valid config.
	if err := p.initOIDCProvider(); err != nil {
		t.Fatalf("failed to initialize provider: %v", err)
	}
	if p.getOAuthConfig() == nil {
		t.Fatal("expected oauthConfig to be set")
	}

	// Mock LoadPluginConfiguration to return an invalid config (missing ClientSecret).
	invalidCfg := &Configuration{
		Enable:       true,
		IssuerURL:    issuer,
		ClientID:     "mattermost",
		ClientSecret: "", // invalid
		Scopes:       "openid",
	}
	rawAPI := p.API.(quietAPI).API
	rawAPI.On("LoadPluginConfiguration", mock.Anything).Run(func(args mock.Arguments) {
		dest := args.Get(0).(*Configuration)
		*dest = *invalidCfg
	}).Return(nil)

	if err := p.OnConfigurationChange(); err != nil {
		t.Fatalf("OnConfigurationChange returned unexpected error: %v", err)
	}

	// Provider state must be completely cleared.
	if p.getOAuthConfig() != nil || p.getOIDCProvider() != nil || p.getOIDCVerifier() != nil {
		t.Fatal("expected provider state to be discarded after invalid configuration change")
	}

	// Login attempt must fail fast with 500, not redirect to the old provider.
	rec := httptest.NewRecorder()
	p.handleOAuth2Connect(rec, httptest.NewRequest(http.MethodGet, "/oauth2/connect", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got status %d, want 500", rec.Code)
	}
}

func TestOnConfigurationChangeDiscardsOldProviderOnFailedDiscovery(t *testing.T) {
	var up atomic.Bool
	var hits atomic.Int32
	p, _ := newDiscoveryTestPlugin(t, &up, &hits, nil)
	up.Store(true)

	// Successfully initialize provider with initial config.
	if err := p.initOIDCProvider(); err != nil {
		t.Fatalf("failed to initialize provider: %v", err)
	}
	if p.getOAuthConfig() == nil {
		t.Fatal("expected oauthConfig to be set")
	}

	// Create a new IdP that is currently down.
	var newHits atomic.Int32
	var newUp atomic.Bool
	var newIssuer string
	newIdp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		newHits.Add(1)
		if !newUp.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 newIssuer,
			"authorization_endpoint": newIssuer + "/auth",
			"token_endpoint":         newIssuer + "/token",
			"jwks_uri":               newIssuer + "/certs",
		})
	}))
	t.Cleanup(newIdp.Close)
	newIssuer = newIdp.URL

	// Point discovery client to handle the new TLS server.
	p.discoveryClient = newIdp.Client()

	newCfg := &Configuration{
		Enable:       true,
		IssuerURL:    newIssuer,
		ClientID:     "mattermost",
		ClientSecret: "secret",
		Scopes:       "openid",
	}
	rawAPI := p.API.(quietAPI).API
	rawAPI.On("LoadPluginConfiguration", mock.Anything).Run(func(args mock.Arguments) {
		dest := args.Get(0).(*Configuration)
		*dest = *newCfg
	}).Return(nil)

	// Discovery should fail because newIdp is down.
	if err := p.OnConfigurationChange(); err != nil {
		t.Fatalf("OnConfigurationChange returned unexpected error: %v", err)
	}

	// Old provider must be discarded!
	if p.getOAuthConfig() != nil {
		t.Fatal("expected old oauthConfig to be discarded when new discovery fails")
	}

	// Now bring newIdp up and test that login retry discovers the NEW issuer, not the old one.
	newUp.Store(true)
	rec := httptest.NewRecorder()
	p.handleOAuth2Connect(rec, httptest.NewRequest(http.MethodGet, "/oauth2/connect", nil))
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), newIssuer+"/auth?") {
		t.Fatalf("got %d to %q, want redirect to new issuer %s", rec.Code, rec.Header().Get("Location"), newIssuer)
	}
}

func TestOnConfigurationChangeDiscardsOldProviderOnDisable(t *testing.T) {
	var up atomic.Bool
	var hits atomic.Int32
	p, issuer := newDiscoveryTestPlugin(t, &up, &hits, nil)
	up.Store(true)

	if err := p.initOIDCProvider(); err != nil {
		t.Fatalf("failed to initialize provider: %v", err)
	}
	if p.getOAuthConfig() == nil {
		t.Fatal("expected oauthConfig to be set")
	}

	disabledCfg := &Configuration{
		Enable:       false,
		IssuerURL:    issuer,
		ClientID:     "mattermost",
		ClientSecret: "secret",
		Scopes:       "openid",
	}
	rawAPI := p.API.(quietAPI).API
	rawAPI.On("LoadPluginConfiguration", mock.Anything).Run(func(args mock.Arguments) {
		dest := args.Get(0).(*Configuration)
		*dest = *disabledCfg
	}).Return(nil)

	if err := p.OnConfigurationChange(); err != nil {
		t.Fatalf("OnConfigurationChange returned unexpected error: %v", err)
	}

	if p.getOAuthConfig() != nil {
		t.Fatal("expected oauthConfig to be nil after disabling plugin")
	}

	rec := httptest.NewRecorder()
	p.handleOAuth2Connect(rec, httptest.NewRequest(http.MethodGet, "/oauth2/connect", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400 Bad Request", rec.Code)
	}
}

func TestOnDeactivateDiscardsProvider(t *testing.T) {
	var up atomic.Bool
	var hits atomic.Int32
	p, _ := newDiscoveryTestPlugin(t, &up, &hits, nil)
	up.Store(true)

	if err := p.initOIDCProvider(); err != nil {
		t.Fatalf("failed to initialize provider: %v", err)
	}
	if p.getOAuthConfig() == nil {
		t.Fatal("expected oauthConfig to be set")
	}

	if err := p.OnDeactivate(); err != nil {
		t.Fatalf("OnDeactivate returned unexpected error: %v", err)
	}

	if p.getOAuthConfig() != nil || p.getOIDCProvider() != nil || p.getOIDCVerifier() != nil {
		t.Fatal("expected provider state to be nil after deactivation")
	}
}

func TestPublicConfigEnableRequiresValidConfig(t *testing.T) {
	p := &Plugin{}

	// Case 1: Disabled
	p.setConfiguration(&Configuration{
		Enable: false,
	})
	rec := httptest.NewRecorder()
	p.handleGetPublicConfig(rec, httptest.NewRequest(http.MethodGet, "/api/v1/config", nil))
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp["enable"] != false {
		t.Fatalf("expected enable=false when disabled, got %v", resp["enable"])
	}

	// Case 2: Enabled but invalid (missing ClientSecret, IssuerURL not https)
	p.setConfiguration(&Configuration{
		Enable:    true,
		IssuerURL: "http://not-https.com",
		ClientID:  "client",
	})
	rec = httptest.NewRecorder()
	p.handleGetPublicConfig(rec, httptest.NewRequest(http.MethodGet, "/api/v1/config", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp["enable"] != false {
		t.Fatalf("expected enable=false when config is invalid, got %v", resp["enable"])
	}

	// Case 3: Enabled and valid
	p.setConfiguration(&Configuration{
		Enable:       true,
		IssuerURL:    "https://idp.example.com",
		ClientID:     "client",
		ClientSecret: "secret",
		Scopes:       "openid",
		ButtonText:   "SSO Login",
		ButtonColor:  "#123456",
	})
	rec = httptest.NewRecorder()
	p.handleGetPublicConfig(rec, httptest.NewRequest(http.MethodGet, "/api/v1/config", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp["enable"] != true {
		t.Fatalf("expected enable=true when config is valid, got %v", resp["enable"])
	}
	if resp["button_text"] != "SSO Login" || resp["button_color"] != "#123456" {
		t.Fatalf("unexpected button attributes in public config: %v", resp)
	}
}

func TestOnActivateAndConfigChangeDoNotRedundantlyInitProvider(t *testing.T) {
	var up atomic.Bool
	var hits atomic.Int32
	p, issuer := newDiscoveryTestPlugin(t, &up, &hits, nil)
	up.Store(true)

	validCfg := Configuration{
		Enable:       true,
		IssuerURL:    issuer,
		ClientID:     "mattermost",
		ClientSecret: "secret",
		Scopes:       "openid",
	}

	rawAPI := p.API.(quietAPI).API
	rawAPI.On("KVGet", kvEncryptionKey).Return([]byte("test-key"), nil)
	rawAPI.On("LoadPluginConfiguration", mock.Anything).Run(func(args mock.Arguments) {
		dest := args.Get(0).(*Configuration)
		*dest = validCfg
	}).Return(nil)

	// Step 1: Mattermost calls OnConfigurationChange before OnActivate on startup.
	if err := p.OnConfigurationChange(); err != nil {
		t.Fatalf("first OnConfigurationChange failed: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("discovery hits after first OnConfigurationChange = %d, want 1", got)
	}

	// Step 2: Mattermost calls OnActivate. Since provider is already initialized, hits should remain 1.
	if err := p.OnActivate(); err != nil {
		t.Fatalf("OnActivate failed: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("discovery hits after OnActivate = %d, want 1 (should not re-initialize)", got)
	}

	// Step 3: Mattermost broadcasts config change (e.g. saving server settings / PluginStates).
	// Configuration is unchanged, so hits should remain 1.
	if err := p.OnConfigurationChange(); err != nil {
		t.Fatalf("second OnConfigurationChange failed: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("discovery hits after unchanged OnConfigurationChange = %d, want 1 (should not re-initialize)", got)
	}

	// Step 4: If configuration actually changes (e.g. rotated client ID), discovery should run again.
	validCfg.ClientID = "mattermost-rotated"
	if err := p.OnConfigurationChange(); err != nil {
		t.Fatalf("third OnConfigurationChange failed: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("discovery hits after changed OnConfigurationChange = %d, want 2", got)
	}
}
