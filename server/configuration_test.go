package main

import (
	"os"
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
				Enable:       true,
				IssuerURL:    "https://idp.example.com/.well-known/openid-configuration",
				ClientID:     "my-client",
				ClientSecret: "my-secret",
				Scopes:       "openid profile email",
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
				Enable:       true,
				IssuerURL:    "https://idp.example.com/.well-known/openid-configuration",
				ClientSecret: "my-secret",
				Scopes:       "openid profile email",
			},
			wantErr: true,
		},
		{
			name: "missing client secret",
			config: Configuration{
				Enable:    true,
				IssuerURL: "https://idp.example.com/.well-known/openid-configuration",
				ClientID:  "my-client",
				Scopes:    "openid profile email",
			},
			wantErr: true,
		},
		{
			name: "missing openid scope",
			config: Configuration{
				Enable:       true,
				IssuerURL:    "https://idp.example.com/.well-known/openid-configuration",
				ClientID:     "my-client",
				ClientSecret: "my-secret",
				Scopes:       "profile email",
			},
			wantErr: true,
		},
		{
			name: "http discovery endpoint is rejected",
			config: Configuration{
				Enable:       true,
				IssuerURL:    "http://idp.example.com/.well-known/openid-configuration",
				ClientID:     "my-client",
				ClientSecret: "my-secret",
				Scopes:       "openid profile email",
			},
			wantErr: true,
		},
		{
			name: "only openid scope is sufficient",
			config: Configuration{
				Enable:       true,
				IssuerURL:    "https://idp.example.com/.well-known/openid-configuration",
				ClientID:     "my-client",
				ClientSecret: "my-secret",
				Scopes:       "openid",
			},
			wantErr: false,
		},
		{
			name: "require email verified without claim is invalid",
			config: Configuration{
				Enable:               true,
				IssuerURL:            "https://idp.example.com/.well-known/openid-configuration",
				ClientID:             "my-client",
				ClientSecret:         "my-secret",
				Scopes:               "openid profile email",
				RequireEmailVerified: true,
			},
			wantErr: true,
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
		Enable:        true,
		IssuerURL:     "https://example.com",
		ClientID:      "test-id",
		ClientSecret:  "test-secret",
		PositionClaim: "position",
	}

	clone := original.Clone()

	// Modify clone
	clone.ClientID = "modified"
	clone.PositionClaim = "job_title"

	// Original should be unchanged
	if original.ClientID != "test-id" {
		t.Error("Clone modified the original configuration ClientID")
	}
	if original.PositionClaim != "position" {
		t.Error("Clone modified the original configuration PositionClaim")
	}
}

func TestClientSecretEnvironment(t *testing.T) {
	const envName = "OIDC_TEST_CLIENT_SECRET"
	for _, tc := range []struct {
		name, stored, envName, envValue, want string
		wantErr                               bool
	}{
		{name: "stored secret", stored: "stored", want: "stored"},
		{name: "environment only", envName: envName, envValue: "from-env", want: "from-env"},
		{name: "environment overrides stored", stored: "stored", envName: envName, envValue: "from-env", want: "from-env"},
		{name: "empty environment does not fall back", stored: "stored", envName: envName, wantErr: true},
		{name: "missing secret", wantErr: true},
		{name: "preserve secret whitespace", envName: envName, envValue: " secret\n", want: " secret\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envName, tc.envValue)
			cfg := Configuration{Enable: true, IssuerURL: "https://idp.example.com", ClientID: "client", ClientSecret: tc.stored, ClientSecretEnv: tc.envName}
			got, err := cfg.getClientSecret()
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("getClientSecret() = %q, %v, want %q, error %v", got, err, tc.want, tc.wantErr)
			}
			if err := cfg.IsValid(); (err != nil) != tc.wantErr {
				t.Fatalf("IsValid() = %v, want error %v", err, tc.wantErr)
			}
			if cfg.ClientSecret != tc.stored {
				t.Fatal("environment resolution changed the stored secret")
			}
		})
	}
	t.Setenv(envName, "")
	if err := os.Unsetenv(envName); err != nil {
		t.Fatal(err)
	}
	cfg := Configuration{Enable: true, IssuerURL: "https://idp.example.com", ClientID: "client", ClientSecret: "stored", ClientSecretEnv: envName}
	if _, err := cfg.getClientSecret(); err == nil {
		t.Fatal("unset environment variable must not fall back to stored secret")
	}
	cfg.Enable = false
	if err := cfg.IsValid(); err != nil {
		t.Fatalf("disabled plugin rejected missing environment: %v", err)
	}
}
