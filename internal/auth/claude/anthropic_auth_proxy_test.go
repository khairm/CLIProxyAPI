package claude

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
)

func TestNewClaudeAuthWithProxyURL_OverrideDirectTakesPrecedence(t *testing.T) {
	cfg := &config.Config{SDKConfig: config.SDKConfig{ProxyURL: "socks5://proxy.example.com:1080"}}
	auth := NewClaudeAuthWithProxyURL(cfg, "direct")

	if auth.httpClient.Transport != helps.UtlsTransport("direct") {
		t.Fatalf("expected the direct utls transport, got %T", auth.httpClient.Transport)
	}
}

func TestNewClaudeAuthWithProxyURL_OverrideProxyAppliedWithoutConfig(t *testing.T) {
	auth := NewClaudeAuthWithProxyURL(nil, "socks5://proxy.example.com:1080")

	if auth.httpClient.Transport != helps.UtlsTransport("socks5://proxy.example.com:1080") {
		t.Fatalf("expected the socks5 utls transport, got %T", auth.httpClient.Transport)
	}
}

func TestNewClaudeAuthForAccount_UsesTheAccountsOwnTransport(t *testing.T) {
	const proxyURL = "http://proxy.example.com:8080"
	a := NewClaudeAuthForAccount(nil, proxyURL, "account-a").httpClient.Transport
	b := NewClaudeAuthForAccount(nil, proxyURL, "account-b").httpClient.Transport

	if a == b {
		t.Fatal("two accounts' token refreshes share one transport")
	}
	if a != helps.UtlsTransportForAuth(proxyURL, "account-a") {
		t.Fatal("refresh client is not the account's shared transport")
	}
	if a == helps.UtlsTransport(proxyURL) {
		t.Fatal("refresh client uses the account-less login transport")
	}
}
