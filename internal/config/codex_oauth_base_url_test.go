package config

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestLoadConfigCodexOAuthBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "absent"},
		{name: "empty", value: `""`},
		{name: "http", value: "http://example.com/", want: "http://example.com"},
		{name: "uppercase scheme", value: "HTTPS://example.com/codex/", want: "HTTPS://example.com/codex"},
		{name: "https path", value: "https://example.com/backend/codex///", want: "https://example.com/backend/codex"},
		{name: "cloud endpoint", value: "https://api.edgee.ai/v1", want: "https://api.edgee.ai/v1"},
		{name: "relative", value: "/backend/codex", wantErr: true},
		{name: "unsupported scheme", value: "ftp://example.com/backend/codex", wantErr: true},
		{name: "empty host", value: "https:///backend/codex", wantErr: true},
		{name: "empty hostname", value: "http://:8080/backend/codex", wantErr: true},
		{name: "userinfo", value: "https://user:pass@example.com/backend/codex", wantErr: true},
		{name: "query", value: "https://example.com/backend/codex?mode=test", wantErr: true},
		{name: "empty query", value: "https://example.com/backend/codex?", wantErr: true},
		{name: "fragment", value: "https://example.com/backend/codex#section", wantErr: true},
		{name: "empty fragment", value: "https://example.com/backend/codex#", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			contents := "host: 127.0.0.1\n"
			if tt.value != "" {
				contents += "codex-oauth-base-url: " + tt.value + "\n"
			}
			if errWrite := os.WriteFile(configPath, []byte(contents), 0o600); errWrite != nil {
				t.Fatalf("write config: %v", errWrite)
			}

			cfg, errLoad := LoadConfig(configPath)
			if tt.wantErr {
				if errLoad == nil {
					t.Fatal("LoadConfig() error = nil, want validation error")
				}
				if !strings.Contains(errLoad.Error(), "codex-oauth-base-url") {
					t.Fatalf("LoadConfig() error = %q, want key name", errLoad)
				}
				return
			}
			if errLoad != nil {
				t.Fatalf("LoadConfig() error = %v", errLoad)
			}
			if cfg.CodexOAuthBaseURL != tt.want {
				t.Fatalf("CodexOAuthBaseURL = %q, want %q", cfg.CodexOAuthBaseURL, tt.want)
			}
			if len(cfg.CodexOAuthHeaders) != 0 {
				t.Fatalf("CodexOAuthHeaders = %#v, want empty", cfg.CodexOAuthHeaders)
			}
			if len(cfg.CodexOAuthRouteAPIKeys) != 0 {
				t.Fatalf("CodexOAuthRouteAPIKeys = %#v, want empty", cfg.CodexOAuthRouteAPIKeys)
			}
		})
	}
}

func TestLoadConfigCodexOAuthHeaders(t *testing.T) {
	tests := []struct {
		name          string
		header        string
		value         string
		wantCanonical string
		wantErr       bool
	}{
		{name: "valid and canonicalized", header: "x-edgee-api-key", value: "edge-key", wantCanonical: "X-Edgee-Api-Key"},
		{name: "all token punctuation", header: "!#$%&'*+-.^_`|~", value: "edge-key", wantCanonical: "!#$%&'*+-.^_`|~"},
		{name: "space", header: "x bad", wantErr: true},
		{name: "colon", header: "x:bad", wantErr: true},
		{name: "at sign", header: "x@bad", wantErr: true},
		{name: "empty", header: "", wantErr: true},
		{name: "authorization", header: "Authorization", wantErr: true},
		{name: "host", header: "HOST", wantErr: true},
		{name: "content length", header: "content-length", wantErr: true},
		{name: "connection", header: "Connection", wantErr: true},
		{name: "keep alive", header: "keep-alive", wantErr: true},
		{name: "te", header: "TE", wantErr: true},
		{name: "trailer", header: "Trailer", wantErr: true},
		{name: "transfer encoding", header: "Transfer-Encoding", wantErr: true},
		{name: "upgrade", header: "Upgrade", wantErr: true},
		{name: "proxy authorization", header: "Proxy-Authorization", wantErr: true},
		{name: "arbitrary proxy header", header: "Proxy-Whatever", wantErr: true},
		{name: "edgee session ID", header: "X-Edgee-Session-Id", wantErr: true},
		{name: "empty value", header: "X-Edgee-Api-Key", value: "", wantErr: true},
		{name: "whitespace value", header: "X-Edgee-Api-Key", value: " \t ", wantErr: true},
		{name: "line feed value", header: "X-Edgee-Api-Key", value: "edge\nkey", wantErr: true},
		{name: "carriage return value", header: "X-Edgee-Api-Key", value: "edge\rkey", wantErr: true},
		{name: "tab value", header: "X-Edgee-Api-Key", value: "edge\tkey", wantErr: true},
		{name: "delete value", header: "X-Edgee-Api-Key", value: "edge\x7fkey", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			contents := "codex-oauth-base-url: https://api.edgee.ai/v1\n" +
				"codex-oauth-headers:\n  " + strconv.Quote(tt.header) + ": " + strconv.Quote(tt.value) + "\n"
			if errWrite := os.WriteFile(configPath, []byte(contents), 0o600); errWrite != nil {
				t.Fatalf("write config: %v", errWrite)
			}

			cfg, errLoad := LoadConfig(configPath)
			if tt.wantErr {
				if errLoad == nil {
					t.Fatal("LoadConfig() error = nil, want validation error")
				}
				if !strings.Contains(errLoad.Error(), "codex-oauth-headers") || !strings.Contains(errLoad.Error(), strconv.Quote(tt.header)) {
					t.Fatalf("LoadConfig() error = %q, want key and offending header %q", errLoad, tt.header)
				}
				return
			}
			if errLoad != nil {
				t.Fatalf("LoadConfig() error = %v", errLoad)
			}
			if cfg.CodexOAuthHeaders[tt.wantCanonical] != tt.value {
				t.Fatalf("CodexOAuthHeaders[%q] = %q, want %q; all headers: %#v", tt.wantCanonical, cfg.CodexOAuthHeaders[tt.wantCanonical], tt.value, cfg.CodexOAuthHeaders)
			}
			if tt.header != tt.wantCanonical {
				if _, exists := cfg.CodexOAuthHeaders[tt.header]; exists {
					t.Fatalf("CodexOAuthHeaders retains non-canonical key %q: %#v", tt.header, cfg.CodexOAuthHeaders)
				}
			}
		})
	}
}

func TestValidateCodexOAuthHeadersRejectsInvalidUTF8Value(t *testing.T) {
	cfg := &Config{
		CodexOAuthBaseURL: "https://api.edgee.ai/v1",
		CodexOAuthHeaders: map[string]string{"X-Edgee-Api-Key": string([]byte{0xff})},
	}

	err := cfg.ValidateCodexOAuthHeaders()
	if err == nil || !strings.Contains(err.Error(), "control characters") {
		t.Fatalf("ValidateCodexOAuthHeaders() error = %v, want invalid value error", err)
	}
}

func TestLoadConfigCodexOAuthHeadersRejectsCaseInsensitiveDuplicatesDeterministically(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	contents := "codex-oauth-base-url: https://api.edgee.ai/v1\n" +
		"codex-oauth-headers:\n  X-Trace-Secret: first-secret\n  x-trace-secret: second-secret\n"
	if errWrite := os.WriteFile(configPath, []byte(contents), 0o600); errWrite != nil {
		t.Fatalf("write config: %v", errWrite)
	}

	const want = `codex-oauth-headers: duplicate header names "X-Trace-Secret" and "x-trace-secret"`
	for attempt := 0; attempt < 100; attempt++ {
		_, errLoad := LoadConfig(configPath)
		if errLoad == nil || errLoad.Error() != want {
			t.Fatalf("LoadConfig() attempt %d error = %v, want %q", attempt, errLoad, want)
		}
	}
}

func TestValidateCodexOAuthHeadersCanonicalizesNamesOnce(t *testing.T) {
	cfg := &Config{
		CodexOAuthBaseURL: "https://api.edgee.ai/v1",
		CodexOAuthHeaders: map[string]string{"x-custom-edgee-secret": "secret-value"},
	}

	if err := cfg.ValidateCodexOAuthHeaders(); err != nil {
		t.Fatalf("first validation error: %v", err)
	}
	wantName := http.CanonicalHeaderKey("x-custom-edgee-secret")
	if got := cfg.CodexOAuthHeaders[wantName]; got != "secret-value" {
		t.Fatalf("canonical header value = %q, want %q; headers: %#v", got, "secret-value", cfg.CodexOAuthHeaders)
	}
	if err := cfg.ValidateCodexOAuthHeaders(); err != nil {
		t.Fatalf("second validation error: %v", err)
	}
	if got := cfg.CodexOAuthHeaders[wantName]; got != "secret-value" {
		t.Fatalf("header changed after second validation: %q", got)
	}
}

func TestLoadConfigRejectsCodexOAuthHeadersWithoutBaseURL(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if errWrite := os.WriteFile(configPath, []byte("codex-oauth-headers:\n  x-edgee-api-key: edge-key\n"), 0o600); errWrite != nil {
		t.Fatalf("write config: %v", errWrite)
	}

	_, errLoad := LoadConfig(configPath)
	if errLoad == nil {
		t.Fatal("LoadConfig() error = nil, want headers-only validation error")
	}
	if !strings.Contains(errLoad.Error(), "codex-oauth-headers") || !strings.Contains(errLoad.Error(), "codex-oauth-base-url") {
		t.Fatalf("LoadConfig() error = %q, want both config keys", errLoad)
	}
}

func TestLoadConfigCodexOAuthRouteAPIKeys(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	contents := "api-keys:\n  - ordinary-key\n  - route-key\n" +
		"codex-oauth-base-url: https://api.edgee.ai/v1\n" +
		"codex-oauth-route-api-keys:\n  - ' route-key '\n  - route-key\n"
	if errWrite := os.WriteFile(configPath, []byte(contents), 0o600); errWrite != nil {
		t.Fatalf("write config: %v", errWrite)
	}

	cfg, errLoad := LoadConfig(configPath)
	if errLoad != nil {
		t.Fatalf("LoadConfig() error = %v", errLoad)
	}
	if len(cfg.CodexOAuthRouteAPIKeys) != 1 || cfg.CodexOAuthRouteAPIKeys[0] != "route-key" {
		t.Fatalf("CodexOAuthRouteAPIKeys = %#v, want normalized route key", cfg.CodexOAuthRouteAPIKeys)
	}
}

func TestLoadConfigRejectsInvalidCodexOAuthRouteAPIKeys(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		want     string
	}{
		{
			name:     "without base URL",
			contents: "api-keys: [ordinary-key, route-key]\ncodex-oauth-route-api-keys: [route-key]\n",
			want:     "codex-oauth-base-url",
		},
		{
			name:     "empty entry",
			contents: "api-keys: [ordinary-key, route-key]\ncodex-oauth-base-url: https://api.edgee.ai/v1\ncodex-oauth-route-api-keys: [' ']\n",
			want:     "entry 0 must not be empty",
		},
		{
			name:     "not an inbound API key",
			contents: "api-keys: [ordinary-key]\ncodex-oauth-base-url: https://api.edgee.ai/v1\ncodex-oauth-route-api-keys: [unknown-key]\n",
			want:     "must also be present in api-keys",
		},
		{
			name:     "all inbound API keys routed",
			contents: "api-keys: [route-key-1, route-key-2]\ncodex-oauth-base-url: https://api.edgee.ai/v1\ncodex-oauth-route-api-keys: [route-key-1, route-key-2]\n",
			want:     "at least one api-keys entry must remain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			if errWrite := os.WriteFile(configPath, []byte(tt.contents), 0o600); errWrite != nil {
				t.Fatalf("write config: %v", errWrite)
			}

			_, errLoad := LoadConfig(configPath)
			if errLoad == nil {
				t.Fatal("LoadConfig() error = nil, want route-key validation error")
			}
			if !strings.Contains(errLoad.Error(), "codex-oauth-route-api-keys") || !strings.Contains(errLoad.Error(), tt.want) {
				t.Fatalf("LoadConfig() error = %q, want key name and %q", errLoad, tt.want)
			}
		})
	}
}

func TestParseConfigBytesValidatesCodexOAuthConfig(t *testing.T) {
	cfg, errParse := ParseConfigBytes([]byte("codex-oauth-base-url: https://edge.example.com/codex/\ncodex-oauth-headers:\n  x-edgee-api-key: edge-key\n"))
	if errParse != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errParse)
	}
	if cfg.CodexOAuthBaseURL != "https://edge.example.com/codex" {
		t.Fatalf("CodexOAuthBaseURL = %q, want trimmed URL", cfg.CodexOAuthBaseURL)
	}
	if cfg.CodexOAuthHeaders["X-Edgee-Api-Key"] != "edge-key" {
		t.Fatalf("CodexOAuthHeaders = %#v, want configured header", cfg.CodexOAuthHeaders)
	}

	_, errParse = ParseConfigBytes([]byte("codex-oauth-base-url: relative/path\n"))
	if errParse == nil || !strings.Contains(errParse.Error(), "codex-oauth-base-url") {
		t.Fatalf("ParseConfigBytes() error = %v, want key-specific validation error", errParse)
	}

	_, errParse = ParseConfigBytes([]byte("codex-oauth-headers:\n  x-edgee-api-key: edge-key\n"))
	if errParse == nil || !strings.Contains(errParse.Error(), "codex-oauth-headers") {
		t.Fatalf("ParseConfigBytes() error = %v, want headers-only validation error", errParse)
	}

	_, errParse = ParseConfigBytes([]byte("api-keys: [route-key]\ncodex-oauth-base-url: https://edge.example.com/codex\ncodex-oauth-route-api-keys: [route-key]\n"))
	if errParse == nil || !strings.Contains(errParse.Error(), "codex-oauth-route-api-keys") {
		t.Fatalf("ParseConfigBytes() error = %v, want route-key validation error", errParse)
	}
}
