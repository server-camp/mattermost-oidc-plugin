package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	mobileUA = "Mattermost Mobile/2.42.0+1 (iOS; 17; iPhone)"
	webUA    = "Mozilla/5.0 Mattermost/5.7 Electron"
	cfgPath  = "/plugins/mattermost-oidc/api/v1/config"
)

func TestMatchesMobileUA(t *testing.T) {
	cases := []struct {
		ua, match string
		want      bool
	}{
		{mobileUA, "Mattermost Mobile/", true},
		{webUA, "Mattermost Mobile/", false},
		{mobileUA, "", false}, // empty match never matches
		{"", "Mattermost Mobile/", false},
	}
	for _, c := range cases {
		if got := matchesMobileUA(c.ua, c.match); got != c.want {
			t.Errorf("matchesMobileUA(%q, %q) = %v, want %v", c.ua, c.match, got, c.want)
		}
	}
}

func TestHandleMobileLogin(t *testing.T) {
	cfg := config{pluginConnectPath: "/plugins/mattermost-oidc/oauth2/connect"}

	t.Run("redirects with mobile_redirect", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth/openid/mobile_login?redirect_to=mmauth%3A%2F%2Fcallback", nil)
		rec := httptest.NewRecorder()
		handleMobileLogin(cfg, rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
		}
		loc := rec.Header().Get("Location")
		want := "/plugins/mattermost-oidc/oauth2/connect?mobile_redirect=mmauth%3A%2F%2Fcallback"
		if loc != want {
			t.Errorf("Location = %q, want %q", loc, want)
		}
	})

	t.Run("missing redirect_to is 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth/openid/mobile_login", nil)
		rec := httptest.NewRecorder()
		handleMobileLogin(cfg, rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
	})
}

// newTestUpstream returns a server that answers both the client-config route and
// the plugin public-config route (both live behind the same upstream host).
func newTestUpstream(enable bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v4/config/client":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"Version":"1","EnableSignUpWithOpenId":"false"}`)
		case cfgPath:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"enable":       enable,
				"button_text":  "SSO Login",
				"button_color": "#123456",
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

// getClientConfig runs a request through the shim (with a plugin reporting the
// given enable state) and returns the decoded /api/v4/config/client JSON object.
func getClientConfig(t *testing.T, cfg config, ua string, enable bool) map[string]string {
	t.Helper()
	upstream := newTestUpstream(enable)
	defer upstream.Close()
	cfg.upstream = upstream.URL

	shim := httptest.NewServer(newHandler(cfg, &http.Client{Timeout: 5 * time.Second}, &buttonCache{ttl: time.Minute}))
	defer shim.Close()

	req, _ := http.NewRequest(http.MethodGet, shim.URL+"/api/v4/config/client", nil)
	req.Header.Set("User-Agent", ua)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	var m map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return m
}

func baseConfig() config {
	return config{
		pluginConnectPath: "/plugins/mattermost-oidc/oauth2/connect",
		pluginConfigPath:  cfgPath,
		mobileUAMatch:     "Mattermost Mobile/",
	}
}

func TestRewriteClientConfig(t *testing.T) {
	t.Run("mobile + plugin enabled → button advertised", func(t *testing.T) {
		cfg := baseConfig()
		m := getClientConfig(t, cfg, mobileUA, true)
		if m["EnableSignUpWithOpenId"] != "true" {
			t.Errorf("EnableSignUpWithOpenId = %q, want true", m["EnableSignUpWithOpenId"])
		}
		if m["OpenIdButtonText"] != "SSO Login" {
			t.Errorf("OpenIdButtonText = %q, want %q", m["OpenIdButtonText"], "SSO Login")
		}
		if m["OpenIdButtonColor"] != "#123456" {
			t.Errorf("OpenIdButtonColor = %q, want %q", m["OpenIdButtonColor"], "#123456")
		}
	})

	t.Run("mobile + plugin disabled → untouched", func(t *testing.T) {
		cfg := baseConfig()
		m := getClientConfig(t, cfg, mobileUA, false)
		if m["EnableSignUpWithOpenId"] != "false" {
			t.Errorf("EnableSignUpWithOpenId = %q, want false (plugin disabled)", m["EnableSignUpWithOpenId"])
		}
		if _, ok := m["OpenIdButtonText"]; ok {
			t.Errorf("OpenIdButtonText should not be set when plugin disabled")
		}
	})

	t.Run("non-mobile → untouched even when enabled", func(t *testing.T) {
		cfg := baseConfig()
		m := getClientConfig(t, cfg, webUA, true)
		if m["EnableSignUpWithOpenId"] != "false" {
			t.Errorf("EnableSignUpWithOpenId = %q, want false (web client)", m["EnableSignUpWithOpenId"])
		}
	})

	t.Run("env vars override plugin button values", func(t *testing.T) {
		cfg := baseConfig()
		cfg.openIDButtonText = "Forced Text"
		cfg.openIDButtonColor = "#ABCDEF"
		m := getClientConfig(t, cfg, mobileUA, true)
		if m["OpenIdButtonText"] != "Forced Text" {
			t.Errorf("OpenIdButtonText = %q, want %q", m["OpenIdButtonText"], "Forced Text")
		}
		if m["OpenIdButtonColor"] != "#ABCDEF" {
			t.Errorf("OpenIdButtonColor = %q, want %q", m["OpenIdButtonColor"], "#ABCDEF")
		}
	})
}

func TestHealthz(t *testing.T) {
	cfg := baseConfig()
	cfg.upstream = "http://127.0.0.1:0"
	shim := httptest.NewServer(newHandler(cfg, &http.Client{Timeout: time.Second}, &buttonCache{ttl: time.Minute}))
	defer shim.Close()

	resp, err := http.Get(shim.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(body)) != "ok" {
		t.Errorf("healthz body = %q, want ok", body)
	}
}
