package util

import "testing"

func TestMaskSensitiveHeaderValueFullyRedactsAuthorizationAndEdgeeHeaders(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "authorization", key: "Authorization", value: "Bearer route-secret-12345"},
		{name: "authorization case insensitive", key: "aUtHoRiZaTiOn", value: "xy"},
		{name: "proxy authorization", key: "Proxy-Authorization", value: "Basic proxy-secret-23456"},
		{name: "edgee API key", key: "X-Edgee-API-Key", value: "edgee-secret-34567"},
		{name: "edgee session ID", key: "x-edgee-session-id", value: "065e0091-7f30-4f0b-a0ed-3e45e2bb1124"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MaskSensitiveHeaderValue(tt.key, tt.value); got != "[REDACTED]" {
				t.Fatalf("MaskSensitiveHeaderValue(%q, secret) = %q, want fixed redaction", tt.key, got)
			}
		})
	}
}

func TestMaskSensitiveHeaderValueWithFullRedactionUsesCanonicalNames(t *testing.T) {
	const secret = "configured-header-secret-45678"
	redacted := map[string]struct{}{"X-Custom-Route-Header": {}}

	if got := MaskSensitiveHeaderValueWithFullRedaction("x-custom-route-header", secret, redacted); got != "[REDACTED]" {
		t.Fatalf("configured header = %q, want fixed redaction", got)
	}
}
