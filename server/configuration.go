package main

import (
	"fmt"
	"strings"
)

// Configuration holds the plugin's settings from the System Console.
type Configuration struct {
	Enable             bool   `json:"Enable"`
	DiscoveryEndpoint  string `json:"DiscoveryEndpoint"`
	ClientID           string `json:"ClientID"`
	ClientSecret       string `json:"ClientSecret"`
	Scopes             string `json:"Scopes"`
	ButtonText         string `json:"ButtonText"`
	ButtonColor        string `json:"ButtonColor"`
	UsernameClaim      string `json:"UsernameClaim"`
	EmailClaim         string `json:"EmailClaim"`
	FirstNameClaim     string `json:"FirstNameClaim"`
	LastNameClaim      string `json:"LastNameClaim"`
	AutoCreateAccounts bool   `json:"AutoCreateAccounts"`
	AutoLinkByEmail    bool   `json:"AutoLinkByEmail"`
	DefaultTeam        string `json:"DefaultTeam"`
	EncryptionKey      string `json:"EncryptionKey"`
}

// IsValid checks that all required configuration fields are present.
func (c *Configuration) IsValid() error {
	if !c.Enable {
		return nil
	}

	if c.DiscoveryEndpoint == "" {
		return fmt.Errorf("discovery endpoint is required")
	}
	if !strings.HasPrefix(c.DiscoveryEndpoint, "https://") {
		return fmt.Errorf("discovery endpoint must use HTTPS")
	}
	if c.ClientID == "" {
		return fmt.Errorf("client ID is required")
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("client secret is required")
	}

	scopes := c.GetScopes()
	hasOpenID := false
	for _, s := range scopes {
		if s == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		return fmt.Errorf("scopes must include 'openid'")
	}

	return nil
}

// GetScopes parses the space-separated scopes string into a slice.
func (c *Configuration) GetScopes() []string {
	if c.Scopes == "" {
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
