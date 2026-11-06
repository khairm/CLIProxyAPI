package helps

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
)

// NewProxyAwareHTTPClient creates an HTTP client with proper proxy configuration priority:
// 1. Use auth.ProxyURL if configured (highest priority)
// 2. Use cfg.ProxyURL if auth proxy is not configured
// 3. Use RoundTripper from context if neither are configured
//
// Parameters:
//   - ctx: The context containing optional RoundTripper
//   - cfg: The application configuration
//   - auth: The authentication information
//   - timeout: The client timeout (0 means no timeout)
//
// Returns:
//   - *http.Client: An HTTP client with configured proxy or transport
func NewProxyAwareHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) *http.Client {
	httpClient := &http.Client{}
	if timeout > 0 {
		httpClient.Timeout = timeout
	}

	// Priority 1: Use auth.ProxyURL if configured
	var proxyURL string
	if auth != nil {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
	}

	// Priority 2: Use cfg.ProxyURL if auth proxy is not configured
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}

	if proxyURL != "" {
		httpClient.Transport = proxyTransport(proxyURL)
		return httpClient
	}

	// Priority 3: Use RoundTripper from context (typically from RoundTripperFor)
	if rt, ok := ctx.Value("cliproxy.roundtripper").(http.RoundTripper); ok && rt != nil {
		httpClient.Transport = rt
	}

	return httpClient
}

// One transport per proxy URL for the whole process, so connections are pooled across clients.
// Proxy URLs come from config, so the map is not evicted.
var (
	sharedProxyMu         sync.Mutex
	sharedProxyTransports = map[string]*http.Transport{}
)

// proxyTransport returns the shared transport for proxyURL (SOCKS5, HTTP, HTTPS or "direct").
// An invalid proxy URL yields a transport that fails every request.
func proxyTransport(proxyURL string) http.RoundTripper {
	sharedProxyMu.Lock()
	defer sharedProxyMu.Unlock()
	if transport, ok := sharedProxyTransports[proxyURL]; ok {
		return transport
	}
	transport, _, errBuild := proxyutil.BuildHTTPTransport(proxyURL)
	if errBuild != nil {
		return proxyutil.FailingTransport(fmt.Errorf("invalid proxy %s: %w", proxyutil.Redact(proxyURL), errBuild))
	}
	sharedProxyTransports[proxyURL] = transport
	return transport
}
