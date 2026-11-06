package util

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestSetProxyWithInvalidProxyFailsInsteadOfGoingDirect(t *testing.T) {
	t.Parallel()
	var reached atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Store(true) }))
	defer server.Close()

	client := SetProxy(&config.SDKConfig{ProxyURL: "ftp://proxy.invalid:21"}, &http.Client{})
	if _, err := client.Get(server.URL); err == nil || !strings.Contains(err.Error(), "invalid proxy") {
		t.Fatalf("err = %v, want invalid proxy error", err)
	}
	if reached.Load() {
		t.Fatal("request went direct despite the invalid proxy")
	}
}
