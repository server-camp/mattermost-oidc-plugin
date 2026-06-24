// Command mobile-bridge is a tiny front-of-Mattermost shim that makes the native
// mobile app perform OIDC login via the mattermost-oidc plugin.
//
// It intercepts exactly two routes; everything else must be routed straight to
// Mattermost by your ingress (nginx / Traefik / Caddy). See README.md.
//
//  1. GET /api/v4/config/client
//     For requests coming from the native app (User-Agent contains
//     "Mattermost Mobile/"), it rewrites the JSON config to advertise the
//     built-in OpenID provider so the app renders its native "Open ID" login
//     button. All other clients (web, desktop) get the upstream response
//     untouched, so they keep using the plugin's own login button.
//
//  2. GET /oauth/openid/mobile_login
//     The native SSO flow targets this hardcoded core endpoint. The shim
//     redirects it into the plugin's connect endpoint, carrying the app's
//     custom-scheme callback (redirect_to) as mobile_redirect. The plugin then
//     drives the OIDC flow and hands the session token back to the app via the
//     deep link.
//
// IMPORTANT: this deliberately spoofs the EnableSignUpWithOpenId flag that the
// Enterprise license normally gates. That is a licensing decision the operator
// owns; this tool does not modify Mattermost itself.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type config struct {
	listen            string
	upstream          string
	pluginConnectPath string
	pluginConfigPath  string
	mobileUAMatch     string
	openIDButtonText  string
	openIDButtonColor string
	debug             bool
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func loadConfig() config {
	return config{
		listen:            envOr("LISTEN", ":8066"),
		upstream:          strings.TrimRight(envOr("UPSTREAM", "http://127.0.0.1:8065"), "/"),
		pluginConnectPath: envOr("PLUGIN_CONNECT_PATH", "/plugins/mattermost-oidc/oauth2/connect"),
		pluginConfigPath:  envOr("PLUGIN_CONFIG_PATH", "/plugins/mattermost-oidc/api/v1/config"),
		mobileUAMatch:     envOr("MOBILE_UA_MATCH", "Mattermost Mobile/"),
		// Button text/color default to empty: when empty they are pulled from the
		// plugin's public config. Set the env vars only to force a fixed value.
		openIDButtonText:  os.Getenv("OPENID_BUTTON_TEXT"),
		openIDButtonColor: os.Getenv("OPENID_BUTTON_COLOR"),
		debug:             os.Getenv("DEBUG") != "",
	}
}

// hopByHop headers must not be forwarded between connections.
var hopByHop = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// pluginPublicConfig mirrors the plugin's GET /api/v1/config response.
type pluginPublicConfig struct {
	Enable      bool   `json:"enable"`
	ButtonText  string `json:"button_text"`
	ButtonColor string `json:"button_color"`
}

// buttonCache caches the plugin's button text/color so it is not refetched on
// every config request. Concurrency-safe; refreshes after ttl, and keeps the
// last good value if a refresh fails.
type buttonCache struct {
	mu        sync.Mutex
	ttl       time.Duration
	fetchedAt time.Time
	val       pluginPublicConfig
	ok        bool
}

func (c *buttonCache) get(cfg config, client *http.Client) (pluginPublicConfig, bool) {
	// Fast path: return a fresh cached value without doing any I/O under the lock.
	c.mu.Lock()
	if c.ok && time.Since(c.fetchedAt) < c.ttl {
		val := c.val
		c.mu.Unlock()
		return val, true
	}
	c.mu.Unlock()

	// Refresh OUTSIDE the lock so a slow/hung upstream never blocks other config
	// requests (the shim proxies /api/v4/config/client for all clients). Concurrent
	// callers during an expiry window may each refresh once — harmless and cheap.
	pc, err := fetchPluginConfig(cfg, client)

	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		if cfg.debug {
			log.Printf("plugin config fetch failed: %v", err)
		}
		return c.val, c.ok // fall back to last good value, if any
	}
	c.val, c.ok, c.fetchedAt = pc, true, time.Now()
	return pc, true
}

func fetchPluginConfig(cfg config, client *http.Client) (pluginPublicConfig, error) {
	var pc pluginPublicConfig
	// Short, dedicated timeout: this is a best-effort enrichment, never let it
	// stall a config response (the shared client timeout is much longer).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.upstream+cfg.pluginConfigPath, nil)
	if err != nil {
		return pc, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return pc, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return pc, fmt.Errorf("plugin config status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return pc, err
	}
	if err := json.Unmarshal(body, &pc); err != nil {
		return pc, err
	}
	return pc, nil
}

func main() {
	cfg := loadConfig()
	client := &http.Client{
		Timeout: 30 * time.Second,
		// Do not auto-follow redirects when proxying the config endpoint.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	cache := &buttonCache{ttl: 60 * time.Second}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("/api/v4/config/client", func(w http.ResponseWriter, r *http.Request) {
		handleClientConfig(cfg, client, cache, w, r)
	})
	mux.HandleFunc("/oauth/openid/mobile_login", func(w http.ResponseWriter, r *http.Request) {
		handleMobileLogin(cfg, w, r)
	})

	log.Printf("mobile-bridge listening on %s, upstream=%s, ua-match=%q", cfg.listen, cfg.upstream, cfg.mobileUAMatch)
	if err := http.ListenAndServe(cfg.listen, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// handleClientConfig proxies GET /api/v4/config/client to upstream and, for the
// native mobile app, flips on the OpenID login button in the returned JSON.
func handleClientConfig(cfg config, client *http.Client, cache *buttonCache, w http.ResponseWriter, r *http.Request) {
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, cfg.upstream+r.URL.RequestURI(), nil)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	upReq.Header = r.Header.Clone()
	// Force an uncompressed response so we can rewrite the JSON without juggling gzip.
	upReq.Header.Set("Accept-Encoding", "identity")

	resp, err := client.Do(upReq)
	if err != nil {
		log.Printf("upstream error: %v", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	ua := r.Header.Get("User-Agent")
	isMobile := cfg.mobileUAMatch != "" && strings.Contains(ua, cfg.mobileUAMatch)
	if cfg.debug {
		log.Printf("config/client ua=%q mobile=%v status=%d", ua, isMobile, resp.StatusCode)
	}

	if isMobile && resp.StatusCode == http.StatusOK {
		var m map[string]string
		if json.Unmarshal(body, &m) == nil {
			m["EnableSignUpWithOpenId"] = "true"

			// Button text/color: explicit env vars win; otherwise pull them from
			// the plugin's own public config so the mobile button matches web.
			text, color := cfg.openIDButtonText, cfg.openIDButtonColor
			if text == "" || color == "" {
				if pc, ok := cache.get(cfg, client); ok {
					if text == "" {
						text = pc.ButtonText
					}
					if color == "" {
						color = pc.ButtonColor
					}
				}
			}
			if text != "" {
				m["OpenIdButtonText"] = text
			}
			if color != "" {
				m["OpenIdButtonColor"] = color
			}
			if nb, e := json.Marshal(m); e == nil {
				body = nb
			}
		} else if cfg.debug {
			log.Printf("config/client: body was not a JSON object, passing through")
		}
	}

	copyHeaders(w.Header(), resp.Header)
	w.Header().Del("Content-Encoding") // body is identity
	w.Header().Del("Content-Length")   // length changed
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// handleMobileLogin turns the native app's /oauth/openid/mobile_login request
// into a redirect to the plugin connect endpoint, preserving the app's
// custom-scheme callback as mobile_redirect.
func handleMobileLogin(cfg config, w http.ResponseWriter, r *http.Request) {
	redirectTo := r.URL.Query().Get("redirect_to")
	if redirectTo == "" {
		http.Error(w, "missing redirect_to", http.StatusBadRequest)
		return
	}
	loc := cfg.pluginConnectPath + "?mobile_redirect=" + url.QueryEscape(redirectTo)
	if cfg.debug {
		log.Printf("mobile_login redirect_to=%q -> %s", redirectTo, loc)
	}
	http.Redirect(w, r, loc, http.StatusFound)
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		if hopByHop[k] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
