// Package claude provides authentication functionality for Anthropic's Claude API.
package claude

import (
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

// NewAnthropicHttpClient creates an HTTP client that bypasses TLS fingerprinting
// for Anthropic domains by using the shared utls Chrome-fingerprint transport of authID
// ("" for flows without an account, such as login).
func NewAnthropicHttpClient(cfg *config.SDKConfig, authID string) *http.Client {
	var proxyURL string
	if cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}
	return &http.Client{Transport: helps.UtlsTransportForAuth(proxyURL, authID)}
}
