package main

import (
	"fmt"
	"slices"
	"strings"
)

// Configuration holds the plugin's settings from the System Console.
type Configuration struct {
	Enable               bool   `json:"Enable"`
	IssuerURL            string `json:"IssuerURL"`
	ClientID             string `json:"ClientID"`
	ClientSecret         string `json:"ClientSecret"`
	Scopes               string `json:"Scopes"`
	ButtonText           string `json:"ButtonText"`
	ButtonColor          string `json:"ButtonColor"`
	UsernameClaim        string `json:"UsernameClaim"`
	EmailClaim           string `json:"EmailClaim"`
	FirstNameClaim       string `json:"FirstNameClaim"`
	LastNameClaim        string `json:"LastNameClaim"`
	PositionClaim        string `json:"PositionClaim"`
	EmailVerifiedClaim   string `json:"EmailVerifiedClaim"`
	RequireEmailVerified bool   `json:"RequireEmailVerified"`
	AutoCreateAccounts   bool   `json:"AutoCreateAccounts"`
	AutoLinkByEmail      bool   `json:"AutoLinkByEmail"`
	DefaultTeam          string `json:"DefaultTeam"`
}

// IsValid checks that all required configuration fields are present.
func (c *Configuration) IsValid() error {
	if !c.Enable {
		return nil
	}

	if c.IssuerURL == "" {
		return fmt.Errorf("issuer URL is required")
	}
	if !strings.HasPrefix(c.IssuerURL, "https://") {
		return fmt.Errorf("issuer URL must use HTTPS")
	}
	if c.ClientID == "" {
		return fmt.Errorf("client ID is required")
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("client secret is required")
	}

	scopes := c.GetScopes()
	hasOpenID := slices.Contains(scopes, "openid")
	if !hasOpenID {
		return fmt.Errorf("scopes must include 'openid'")
	}
	if c.RequireEmailVerified && strings.TrimSpace(c.EmailVerifiedClaim) == "" {
		return fmt.Errorf("email verified claim is required when require email verified is enabled")
	}

	return nil
}

// GetScopes parses the space-separated scopes string into a slice.
func (c *Configuration) GetScopes() []string {
	if strings.TrimSpace(c.Scopes) == "" {
		return []string{"openid", "profile", "email"}
	}
	parts := strings.Fields(c.Scopes)
	var scopes []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			scopes = append(scopes, p)
		}
	}
	return scopes
}

// Clone returns a shallow copy of the configuration.
func (c *Configuration) Clone() *Configuration {
	cc := *c
	return &cc
}
