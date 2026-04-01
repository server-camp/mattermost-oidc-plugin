package main

import (
	"testing"
)

func TestGetStringClaim(t *testing.T) {
	claims := map[string]interface{}{
		"sub":                "user-123",
		"email":              "test@example.com",
		"preferred_username": "testuser",
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
	p.configuration = &Configuration{
		EncryptionKey: "test-encryption-key-1234567890abcdef",
	}

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
