package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"github.com/mattermost/mattermost/server/public/plugin"
	"golang.org/x/oauth2"
)

const (
	// PluginID is the unique identifier for this plugin.
	PluginID = "mattermost-oidc"

	// AuthService is the service name stored in the user's AuthService field.
	AuthService = "oidc"

	// KVOAuthStatePrefix is the KV store key prefix for OAuth state tokens.
	KVOAuthStatePrefix = "oidc_state_"
)

// kvEncryptionKey is the KV store key under which the HMAC signing key is persisted.
const kvEncryptionKey = "_plugin_encryption_key"

// discoveryRetryInterval limits how often unauthenticated login requests can make the plugin contact the issuer.
const discoveryRetryInterval = 10 * time.Second

// Plugin implements the Mattermost plugin interface.
type Plugin struct {
	plugin.MattermostPlugin

	// configurationLock synchronizes access to the configuration.
	configurationLock sync.RWMutex

	// configuration is the active plugin configuration.
	configuration *Configuration

	// encryptionKey is the HMAC key used to sign OAuth state tokens.
	// Loaded from the KV store on activation; never exposed via config or UI.
	encryptionKey string

	// oidcProvider is the cached OIDC provider from discovery.
	oidcProvider *oidc.Provider

	// oauth2Config is the cached OAuth2 configuration.
	oauth2Config *oauth2.Config

	// oidcVerifier is the ID token verifier.
	oidcVerifier *oidc.IDTokenVerifier

	// retryLock allows one login-time discovery retry at a time.
	retryLock sync.Mutex

	// lastDiscoveryRetry is when a login request last retried discovery, guarded by retryLock.
	lastDiscoveryRetry time.Time

	// discoveryClient overrides the HTTP client used for OIDC discovery when set (currently only used by tests).
	discoveryClient *http.Client

	// router handles HTTP requests for this plugin.
	router *mux.Router
}

// OnActivate is called when the plugin is activated.
func (p *Plugin) OnActivate() error {
	// Load or generate the HMAC signing key from the KV store.
	// The key is kept out of plugin config and the System Console entirely.
	if keyBytes, err := p.API.KVGet(kvEncryptionKey); err != nil {
		return fmt.Errorf("failed to load encryption key from KV store: %w", err)
	} else if len(keyBytes) > 0 {
		p.encryptionKey = string(keyBytes)
	} else {
		key, err := generateRandomKey(32)
		if err != nil {
			return fmt.Errorf("failed to generate encryption key: %w", err)
		}
		if err := p.API.KVSet(kvEncryptionKey, []byte(key)); err != nil {
			return fmt.Errorf("failed to persist encryption key: %w", err)
		}
		p.encryptionKey = key
	}

	p.initRouter()

	cfg := p.getConfiguration()
	if cfg.Enable {
		if err := cfg.IsValid(); err != nil {
			p.API.LogWarn("OIDC plugin configuration is incomplete", "error", err.Error())
			return nil // Don't fail activation, just log the issue
		}
		if p.getOAuthConfig() == nil {
			if err := p.initOIDCProvider(); err != nil {
				p.API.LogWarn("Failed to initialize OIDC provider", "error", err.Error())
			}
		}
	}

	p.API.LogInfo("Mattermost / Mostlymatter OIDC plugin activated")
	return nil
}

// OnDeactivate is called when the plugin is deactivated.
func (p *Plugin) OnDeactivate() error {
	p.clearOIDCProvider()
	p.API.LogInfo("Mattermost / Mostlymatter OIDC plugin deactivated")
	return nil
}

// OnConfigurationChange is called when the configuration changes.
func (p *Plugin) OnConfigurationChange() error {
	var configuration Configuration
	if err := p.API.LoadPluginConfiguration(&configuration); err != nil {
		return fmt.Errorf("failed to load plugin configuration: %w", err)
	}

	p.configurationLock.RLock()
	var (
		unchanged   = p.configuration != nil && *p.configuration == configuration
		hasProvider = p.oauth2Config != nil
	)
	p.configurationLock.RUnlock()
	if unchanged && hasProvider {
		return nil // if settings did not change and the provider is already running, skip re-discovery.
	}

	p.setConfiguration(&configuration)
	p.clearOIDCProvider() // clear old config to prevent stale, outdated config in case the newly saved one is invalid

	if configuration.Enable {
		if err := configuration.IsValid(); err != nil {
			p.API.LogWarn("OIDC configuration invalid", "error", err.Error())
			return nil
		}
		if err := p.initOIDCProvider(); err != nil {
			p.API.LogError("Failed to re-initialize OIDC provider", "error", err.Error())
		}
	}

	return nil
}

// getConfiguration retrieves the active configuration.
func (p *Plugin) getConfiguration() *Configuration {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()

	if p.configuration == nil {
		return &Configuration{}
	}
	return p.configuration.Clone()
}

// setConfiguration replaces the active configuration.
func (p *Plugin) setConfiguration(configuration *Configuration) {
	p.configurationLock.Lock()
	defer p.configurationLock.Unlock()

	p.configuration = configuration
}

// clearOIDCProvider resets the cached provider, OAuth2 configuration, and verifier.
func (p *Plugin) clearOIDCProvider() {
	p.configurationLock.Lock()
	defer p.configurationLock.Unlock()

	p.oidcProvider = nil
	p.oauth2Config = nil
	p.oidcVerifier = nil
}

// initOIDCProvider discovers and initializes the OIDC provider, OAuth2 config, and verifier.
func (p *Plugin) initOIDCProvider() error {
	config := p.getConfiguration()
	if err := config.IsValid(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if p.discoveryClient != nil {
		ctx = oidc.ClientContext(ctx, p.discoveryClient)
	}

	// oidc.NewProvider expects the issuer URL and appends /.well-known/openid-configuration itself -> strip the suffix if the user accidentally included it.
	// Note that this will potentially result in a URL mismatch if the provider sends its URL with a trailing slash, see https://github.com/coreos/go-oidc/issues/442.
	issuer := strings.TrimSuffix(config.IssuerURL, "/.well-known/openid-configuration")

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return fmt.Errorf("failed to discover OIDC provider at %s: %w", issuer, err)
	}

	mmConfig := p.API.GetConfig()
	if mmConfig == nil {
		return fmt.Errorf("failed to get Mattermost config")
	}
	siteURL := mmConfig.ServiceSettings.SiteURL
	if siteURL == nil || *siteURL == "" {
		return fmt.Errorf("SiteURL is not configured in Mattermost")
	}

	redirectURL := fmt.Sprintf("%s/plugins/%s/oauth2/callback", *siteURL, PluginID)

	oauthConfig := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       config.GetScopes(),
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.ClientID,
	})

	p.configurationLock.Lock()
	// A configuration saved during discovery gets its own OnConfigurationChange, so this result is stale.
	stale := p.configuration == nil || *p.configuration != *config
	if !stale {
		p.oidcProvider = provider
		p.oauth2Config = oauthConfig
		p.oidcVerifier = verifier
	}
	p.configurationLock.Unlock()
	if stale {
		return fmt.Errorf("configuration changed during discovery")
	}

	p.API.LogInfo("OIDC provider initialized successfully",
		"issuer_url", config.IssuerURL,
		"redirect_url", redirectURL,
		"pkce", "S256",
	)
	return nil
}

// retryOIDCProvider re-runs failed discovery for a login request, at most once per discoveryRetryInterval.
func (p *Plugin) retryOIDCProvider() {
	if !p.retryLock.TryLock() {
		return
	}
	defer p.retryLock.Unlock()
	if p.getOAuthConfig() != nil || time.Since(p.lastDiscoveryRetry) < discoveryRetryInterval {
		return
	}
	if err := p.initOIDCProvider(); err != nil {
		p.API.LogWarn("Failed to initialize OIDC provider on login", "error", err.Error())
	}
	p.lastDiscoveryRetry = time.Now()
}

// ServeHTTP routes incoming HTTP requests to the plugin's router.
func (p *Plugin) ServeHTTP(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	p.router.ServeHTTP(w, r)
}

// initRouter sets up HTTP routes for the plugin.
func (p *Plugin) initRouter() {
	p.router = mux.NewRouter()

	// OAuth2 endpoints
	p.router.HandleFunc("/oauth2/connect", p.handleOAuth2Connect).Methods(http.MethodGet)
	p.router.HandleFunc("/oauth2/callback", p.handleOAuth2Callback).Methods(http.MethodGet)

	// API endpoints
	p.router.HandleFunc("/api/v1/config", p.handleGetPublicConfig).Methods(http.MethodGet)
}

// getEncryptionKey returns the HMAC signing key cached from the KV store.
func (p *Plugin) getEncryptionKey() string {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()
	return p.encryptionKey
}

// generateRandomKey generates a random hex-encoded key of the given byte length.
func generateRandomKey(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// getSiteURL returns the configured SiteURL or an empty string.
func (p *Plugin) getSiteURL() string {
	siteURL := p.API.GetConfig().ServiceSettings.SiteURL
	if siteURL == nil {
		return ""
	}
	return *siteURL
}

// getOAuthConfig safely retrieves the current OAuth2 config.
func (p *Plugin) getOAuthConfig() *oauth2.Config {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()
	return p.oauth2Config
}

// getOIDCVerifier safely retrieves the current OIDC ID token verifier.
func (p *Plugin) getOIDCVerifier() *oidc.IDTokenVerifier {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()
	return p.oidcVerifier
}

// getOIDCProvider safely retrieves the current OIDC provider.
func (p *Plugin) getOIDCProvider() *oidc.Provider {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()
	return p.oidcProvider
}
