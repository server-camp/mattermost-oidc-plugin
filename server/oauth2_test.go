package main

import (
	"net/http/httptest"
	"strings"
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
