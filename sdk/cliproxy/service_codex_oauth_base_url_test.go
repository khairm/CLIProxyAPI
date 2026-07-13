package cliproxy

import (
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestValidateCodexOAuthBaseURLAuthConflicts(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *config.Config
		auth       *coreauth.Auth
		wantErr    bool
		wantDetail string
	}{
		{
			name: "unset preserves stock behavior",
			cfg:  &config.Config{},
			auth: &coreauth.Auth{Provider: "codex", Attributes: map[string]string{"base_url": "https://legacy.example.com"}},
		},
		{
			name:       "attribute base URL conflicts",
			cfg:        &config.Config{CodexOAuthBaseURL: "https://edge.example.com"},
			auth:       &coreauth.Auth{ID: "oauth-attr", Provider: "codex", Attributes: map[string]string{"base_url": "https://legacy.example.com"}},
			wantErr:    true,
			wantDetail: "oauth-attr",
		},
		{
			name:       "auth file metadata base URL conflicts",
			cfg:        &config.Config{CodexOAuthBaseURL: "https://edge.example.com"},
			auth:       &coreauth.Auth{ID: "oauth-file", FileName: "auths/codex.json", Provider: "codex", Metadata: map[string]any{"base_url": "https://legacy.example.com"}},
			wantErr:    true,
			wantDetail: "auths/codex.json",
		},
		{
			name: "matching codex API key entry is named",
			cfg: &config.Config{
				CodexOAuthBaseURL: "https://edge.example.com",
				CodexKey:          []config.CodexKey{{BaseURL: "https://legacy.example.com"}},
			},
			auth:       &coreauth.Auth{ID: "oauth-match", Provider: "codex", Metadata: map[string]any{"base_url": "https://legacy.example.com"}},
			wantErr:    true,
			wantDetail: "codex-api-key[0]",
		},
		{
			name: "API key auth keeps its own base URL",
			cfg:  &config.Config{CodexOAuthBaseURL: "https://edge.example.com"},
			auth: &coreauth.Auth{Provider: "codex", Attributes: map[string]string{"api_key": "sk-test", "base_url": "https://api-key.example.com"}},
		},
		{
			name: "other provider is ignored",
			cfg:  &config.Config{CodexOAuthBaseURL: "https://edge.example.com"},
			auth: &coreauth.Auth{Provider: "claude", Attributes: map[string]string{"base_url": "https://legacy.example.com"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errConflict := validateCodexOAuthBaseURLAuthConflicts(tt.cfg, []*coreauth.Auth{tt.auth})
			if !tt.wantErr {
				if errConflict != nil {
					t.Fatalf("validation error = %v, want nil", errConflict)
				}
				return
			}
			if errConflict == nil {
				t.Fatal("validation error = nil, want conflict")
			}
			if !strings.Contains(errConflict.Error(), "codex-oauth-base-url") || !strings.Contains(errConflict.Error(), tt.wantDetail) {
				t.Fatalf("validation error = %q, want key and %q", errConflict, tt.wantDetail)
			}
		})
	}
}

func TestValidateCodexOAuthRouteCredentialPool(t *testing.T) {
	routeConfig := &config.Config{CodexOAuthRouteAPIKeys: []string{"route-key"}}
	tests := []struct {
		name    string
		cfg     *config.Config
		auths   []*coreauth.Auth
		wantErr bool
	}{
		{
			name: "route keys unset",
			cfg:  &config.Config{},
		},
		{
			name:    "route keys with empty pool",
			cfg:     routeConfig,
			wantErr: true,
		},
		{
			name: "route keys with Codex API key only",
			cfg:  routeConfig,
			auths: []*coreauth.Auth{{
				Provider:   "codex",
				Attributes: map[string]string{coreauth.AttributeAPIKey: "upstream-key"},
			}},
			wantErr: true,
		},
		{
			name: "route keys with non-Codex OAuth only",
			cfg:  routeConfig,
			auths: []*coreauth.Auth{{
				Provider: "claude",
				Metadata: map[string]any{"access_token": "oauth-token"},
			}},
			wantErr: true,
		},
		{
			name: "route keys with Codex OAuth",
			cfg:  routeConfig,
			auths: []*coreauth.Auth{{
				Provider: "codex",
				Metadata: map[string]any{"access_token": "oauth-token"},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errValidate := validateCodexOAuthRouteCredentialPool(tt.cfg, tt.auths)
			if !tt.wantErr {
				if errValidate != nil {
					t.Fatalf("validation error = %v, want nil", errValidate)
				}
				return
			}
			if errValidate == nil {
				t.Fatal("validation error = nil, want missing Codex OAuth credential error")
			}
			if !strings.Contains(errValidate.Error(), "codex-oauth-route-api-keys") || !strings.Contains(errValidate.Error(), "Codex OAuth credential") {
				t.Fatalf("validation error = %q, want route key and Codex OAuth credential detail", errValidate)
			}
		})
	}
}

func TestApplyConfigUpdateKeepsStartupCodexOAuthConfig(t *testing.T) {
	startupURL := "https://startup.example.com/codex"
	startupHeaders := map[string]string{"x-edgee-api-key": "startup-key"}
	startupRouteAPIKeys := []string{"startup-route-key"}
	service := &Service{
		cfg: &config.Config{
			SDKConfig:              config.SDKConfig{APIKeys: []string{"ordinary-key", "startup-route-key"}},
			CodexOAuthBaseURL:      startupURL,
			CodexOAuthHeaders:      map[string]string{"x-edgee-api-key": "startup-key"},
			CodexOAuthRouteAPIKeys: []string{"startup-route-key"},
		},
		codexOAuthBaseURL:      startupURL,
		codexOAuthHeaders:      startupHeaders,
		codexOAuthRouteAPIKeys: startupRouteAPIKeys,
	}
	reloaded := &config.Config{
		SDKConfig:              config.SDKConfig{APIKeys: []string{"ordinary-key", "startup-route-key"}},
		CodexOAuthBaseURL:      "https://reload.example.com/codex",
		CodexOAuthHeaders:      map[string]string{"x-edgee-api-key": "reload-key"},
		CodexOAuthRouteAPIKeys: []string{"reload-route-key"},
	}

	service.applyConfigUpdateWithAuthSynthesis(reloaded, false)

	if reloaded.CodexOAuthBaseURL != startupURL {
		t.Fatalf("reloaded CodexOAuthBaseURL = %q, want startup %q", reloaded.CodexOAuthBaseURL, startupURL)
	}
	if service.cfg.CodexOAuthBaseURL != startupURL {
		t.Fatalf("service CodexOAuthBaseURL = %q, want startup %q", service.cfg.CodexOAuthBaseURL, startupURL)
	}
	if got := reloaded.CodexOAuthHeaders["X-Edgee-Api-Key"]; got != "startup-key" {
		t.Fatalf("reloaded CodexOAuthHeaders value = %q, want startup value", got)
	}
	if got := service.cfg.CodexOAuthHeaders["X-Edgee-Api-Key"]; got != "startup-key" {
		t.Fatalf("service CodexOAuthHeaders value = %q, want startup value", got)
	}
	if got := reloaded.CodexOAuthRouteAPIKeys; len(got) != 1 || got[0] != "startup-route-key" {
		t.Fatalf("reloaded CodexOAuthRouteAPIKeys = %#v, want startup route key", got)
	}
	if got := service.cfg.CodexOAuthRouteAPIKeys; len(got) != 1 || got[0] != "startup-route-key" {
		t.Fatalf("service CodexOAuthRouteAPIKeys = %#v, want startup route key", got)
	}
	startupHeaders["x-edgee-api-key"] = "mutated-after-reload"
	startupRouteAPIKeys[0] = "mutated-after-reload"
	if got := reloaded.CodexOAuthHeaders["X-Edgee-Api-Key"]; got != "startup-key" {
		t.Fatalf("reloaded CodexOAuthHeaders aliases startup snapshot: got %q", got)
	}
	if got := reloaded.CodexOAuthRouteAPIKeys[0]; got != "startup-route-key" {
		t.Fatalf("reloaded CodexOAuthRouteAPIKeys aliases startup snapshot: got %q", got)
	}
}

func TestApplyConfigUpdateRejectsStartupRouteWithoutOrdinaryBearer(t *testing.T) {
	startupURL := "https://startup.example.com/codex"
	original := &config.Config{
		SDKConfig:              config.SDKConfig{APIKeys: []string{"ordinary-key", "route-key"}},
		CodexOAuthBaseURL:      startupURL,
		CodexOAuthRouteAPIKeys: []string{"route-key"},
	}
	service := &Service{
		cfg:                    original,
		codexOAuthBaseURL:      startupURL,
		codexOAuthRouteAPIKeys: []string{"route-key"},
	}
	reloaded := &config.Config{
		SDKConfig: config.SDKConfig{APIKeys: []string{"route-key"}},
	}

	service.applyConfigUpdateWithAuthSynthesis(reloaded, false)

	if service.cfg != original {
		t.Fatal("invalid config update replaced the active service config")
	}
}

func TestApplyConfigUpdateRejectsMissingStartupRouteKey(t *testing.T) {
	startupURL := "https://startup.example.com/codex"
	original := &config.Config{
		SDKConfig:              config.SDKConfig{APIKeys: []string{"ordinary-key", "route-key"}},
		CodexOAuthBaseURL:      startupURL,
		CodexOAuthRouteAPIKeys: []string{"route-key"},
	}
	service := &Service{
		cfg:                    original,
		codexOAuthBaseURL:      startupURL,
		codexOAuthRouteAPIKeys: []string{"route-key"},
	}
	reloaded := &config.Config{
		SDKConfig: config.SDKConfig{APIKeys: []string{"ordinary-key"}},
	}

	service.applyConfigUpdateWithAuthSynthesis(reloaded, false)

	if service.cfg != original {
		t.Fatal("config missing the startup route key replaced the active service config")
	}
}

func TestBuilderRejectsInvalidCodexOAuthRoutingConfig(t *testing.T) {
	cfg := &config.Config{
		SDKConfig:              config.SDKConfig{APIKeys: []string{"route-key"}},
		CodexOAuthBaseURL:      "https://edge.example.com/codex/",
		CodexOAuthRouteAPIKeys: []string{"route-key"},
	}

	service, errBuild := NewBuilder().WithConfig(cfg).WithConfigPath(t.TempDir() + "/config.yaml").Build()
	if errBuild == nil {
		t.Fatal("Build() error = nil, want route validation error")
	}
	if service != nil {
		t.Fatal("Build() service is non-nil after validation failure")
	}
	if !strings.Contains(errBuild.Error(), "at least one api-keys entry must remain") {
		t.Fatalf("Build() error = %q, want ordinary bearer validation detail", errBuild)
	}
}
