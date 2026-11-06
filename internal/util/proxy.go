// Package util provides utility functions for the CLI Proxy API server.
// It includes helper functions for proxy configuration, HTTP client setup,
// log level management, and other common operations used across the application.
package util

import (
	"fmt"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
)

// SetProxy configures the provided HTTP client with proxy settings from the configuration.
// It supports SOCKS5, HTTP, and HTTPS proxies. An unusable proxy setting gives the client a
// transport that fails every request, so traffic never silently goes direct.
func SetProxy(cfg *config.SDKConfig, httpClient *http.Client) *http.Client {
	if cfg == nil || httpClient == nil {
		return httpClient
	}

	transport, _, errBuild := proxyutil.BuildHTTPTransport(cfg.ProxyURL)
	if errBuild != nil {
		err := fmt.Errorf("invalid proxy %s: %w", proxyutil.Redact(cfg.ProxyURL), errBuild)
		log.Error(err)
		httpClient.Transport = proxyutil.FailingTransport(err)
		return httpClient
	}
	if transport != nil {
		httpClient.Transport = transport
	}
	return httpClient
}
