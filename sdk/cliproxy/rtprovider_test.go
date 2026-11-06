package cliproxy

import (
	"net/http"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestRoundTripperForDirectBypassesProxy(t *testing.T) {
	t.Parallel()

	provider := newDefaultRoundTripperProvider()
	rt := provider.RoundTripperFor(&coreauth.Auth{ProxyURL: "direct"})
	transport, ok := rt.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", rt)
	}
	if transport.Proxy != nil {
		t.Fatal("expected direct transport to disable proxy function")
	}
}

func TestRoundTripperForInvalidProxyFailsRequests(t *testing.T) {
	t.Parallel()

	rt := newDefaultRoundTripperProvider().RoundTripperFor(&coreauth.Auth{ProxyURL: "ftp://proxy.example.com:21"})
	if rt == nil {
		t.Fatal("invalid proxy returned nil, which silently falls back to a direct connection")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("expected an invalid proxy error")
	}
}
