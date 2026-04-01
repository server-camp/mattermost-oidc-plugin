package main

import (
	"testing"
)

func TestConfigurationIsValid(t *testing.T) {
	tests := []struct {
		name    string
		config  Configuration
		wantErr bool
	}{
		{
			name: "disabled plugin is always valid",
			config: Configuration{
				Enable: false,
			},
			wantErr: false,
		},
		{
			name: "valid full configuration",
			config: Configuration{
				Enable:            true,
				DiscoveryEndpoint: "https://idp.example.com/.well-known/openid-configuration",
				ClientID:          "my-client",
				ClientSecret:      "my-secret",
				Scopes:            "openid profile email",
			},
			wantErr: false,
		},
		{
			name: "missing discovery endpoint",
			config: Configuration{
				Enable:       true,
				ClientID:     "my-client",
				ClientSecret: "my-secret",
				Scopes:       "openid profile email",
			},
			wantErr: true,
		},
		{
			name: "missing client ID",
			config: Configuration{
				Enable:            true,
				DiscoveryEndpoint: "https://idp.example.com/.well-known/openid-configuration",
				ClientSecret:      "my-secret",
				Scopes:            "openid profile email",
			},
			wantErr: true,
		},
		{
			name: "missing client secret",
			config: Configuration{
				Enable:            true,
				DiscoveryEndpoint: "https://idp.example.com/.well-known/openid-configuration",
				ClientID:          "my-client",
				Scopes:            "openid profile email",
			},
			wantErr: true,
		},
		{
			name: "missing openid scope",
			config: Configuration{
				Enable:            true,
				DiscoveryEndpoint: "https://idp.example.com/.well-known/openid-configuration",
				ClientID:          "my-client",
				ClientSecret:      "my-secret",
				Scopes:            "profile email",
			},
			wantErr: true,
		},
		{
			name: "http discovery endpoint is rejected",
			config: Configuration{
				Enable:            true,
				DiscoveryEndpoint: "http://idp.example.com/.well-known/openid-configuration",
				ClientID:          "my-client",
				ClientSecret:      "my-secret",
				Scopes:            "openid profile email",
			},
			wantErr: true,
		},
		{
			name: "only openid scope is sufficient",
			config: Configuration{
				Enable:            true,
				DiscoveryEndpoint: "https://idp.example.com/.well-known/openid-configuration",
				ClientID:          "my-client",
				ClientSecret:      "my-secret",
				Scopes:            "openid",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.IsValid()
			if (err != nil) != tt.wantErr {
				t.Errorf("IsValid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetScopes(t *testing.T) {
	tests := []struct {
		name     string
		scopes   string
		expected []string
	}{
		{
			name:     "empty scopes returns defaults",
			scopes:   "",
			expected: []string{"openid", "profile", "email"},
		},
		{
			name:     "custom scopes are parsed",
			scopes:   "openid profile email groups",
			expected: []string{"openid", "profile", "email", "groups"},
		},
		{
			name:     "extra whitespace is handled",
			scopes:   "  openid   profile  ",
			expected: []string{"openid", "profile"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Configuration{Scopes: tt.scopes}
			result := config.GetScopes()

			if len(result) != len(tt.expected) {
				t.Errorf("GetScopes() returned %d scopes, want %d", len(result), len(tt.expected))
				return
			}
			for i, s := range result {
				if s != tt.expected[i] {
					t.Errorf("GetScopes()[%d] = %q, want %q", i, s, tt.expected[i])
				}
			}
		})
	}
}

func TestSanitizeUsername(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple username",
			input:    "john.doe",
			expected: "john.doe",
		},
		{
			name:     "uppercase is lowered",
			input:    "John.Doe",
			expected: "john.doe",
		},
		{
			name:     "special characters replaced",
			input:    "john@doe!#",
			expected: "john_doe__",
		},
		{
			name:     "starts with number gets prefix",
			input:    "123user",
			expected: "u123user",
		},
		{
			name:     "short username gets padded",
			input:    "ab",
			expected: "ab_",
		},
		{
			name:     "very long username gets truncated",
			input:    "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01234567890",
			expected: "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01",
		},
		{
			name:     "spaces are replaced",
			input:    "john doe",
			expected: "john_doe",
		},
		{
			name:     "hyphens and underscores preserved",
			input:    "john-doe_123",
			expected: "john-doe_123",
		},
		{
			name:     "unicode characters replaced",
			input:    "müller",
			expected: "m_ller",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeUsername(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeUsername(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestConfigurationClone(t *testing.T) {
	original := &Configuration{
		Enable:            true,
		DiscoveryEndpoint: "https://example.com",
		ClientID:          "test-id",
		ClientSecret:      "test-secret",
	}

	clone := original.Clone()

	// Modify clone
	clone.ClientID = "modified"

	// Original should be unchanged
	if original.ClientID != "test-id" {
		t.Error("Clone modified the original configuration")
	}
}
