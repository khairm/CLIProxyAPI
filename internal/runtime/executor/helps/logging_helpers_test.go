package helps

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestRecordAPIResponseMetadataStoresHeadersWhenRequestLogDisabled(t *testing.T) {
	ctx := logging.WithResponseHeadersHolder(context.Background())
	headers := http.Header{}
	headers.Add("X-Upstream-Request-Id", "upstream-req-1")

	RecordAPIResponseMetadata(ctx, &config.Config{}, http.StatusOK, headers)
	headers.Set("X-Upstream-Request-Id", "mutated")

	got := logging.GetResponseHeaders(ctx)
	if got.Get("X-Upstream-Request-Id") != "upstream-req-1" {
		t.Fatalf("response header = %q, want %q", got.Get("X-Upstream-Request-Id"), "upstream-req-1")
	}
}

func TestRoutedCodexOAuthRequestLogsFullyRedactInjectedHeaders(t *testing.T) {
	const (
		authorizationSecret = "AZQJ-routed-oauth-token-WXVU"
		edgeeAPIKeySecret   = "BKVR-edgee-api-key-TSRP"
		sessionIDSecret     = "065e0091-7f30-4f0b-a0ed-3e45e2bb1124"
		configuredSecret    = "CMWX-configured-header-NLKJ"
	)

	info := UpstreamRequestLog{
		Headers: http.Header{
			"Authorization":         {"Bearer " + authorizationSecret},
			"X-Edgee-Api-Key":       {edgeeAPIKeySecret},
			"X-Edgee-Session-Id":    {sessionIDSecret},
			"X-Custom-Route-Header": {configuredSecret},
			"X-Ordinary-Header":     {"ordinary-visible-value"},
		},
	}
	cfg := &config.Config{
		SDKConfig:         config.SDKConfig{RequestLog: true},
		CodexOAuthHeaders: map[string]string{"X-Custom-Route-Header": configuredSecret},
	}

	tests := []struct {
		name   string
		record func(context.Context, *config.Config, UpstreamRequestLog)
		key    string
	}{
		{name: "HTTP", record: RecordAPIRequest, key: apiRequestKey},
		{name: "websocket", record: RecordAPIWebsocketRequest, key: apiWebsocketTimelineKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx := cliproxyexecutor.WithCodexOAuthRoute(context.Background(), sessionIDSecret)
			ctx = context.WithValue(ctx, "gin", ginCtx)

			tt.record(ctx, cfg, info)

			value, exists := ginCtx.Get(tt.key)
			if !exists {
				t.Fatalf("request log key %q was not recorded", tt.key)
			}
			logged, ok := value.([]byte)
			if !ok {
				t.Fatalf("request log type = %T, want []byte", value)
			}
			for _, secret := range []string{authorizationSecret, edgeeAPIKeySecret, sessionIDSecret, configuredSecret} {
				for _, fragment := range []string{secret, secret[:4], secret[len(secret)-4:]} {
					if strings.Contains(string(logged), fragment) {
						t.Fatalf("request log contains secret fragment %q from %q:\n%s", fragment, secret, logged)
					}
				}
			}
			if !strings.Contains(string(logged), "X-Ordinary-Header: ordinary-visible-value") {
				t.Fatalf("request log lost ordinary header:\n%s", logged)
			}
			for _, name := range []string{"Authorization", "X-Edgee-Api-Key", "X-Edgee-Session-Id", "X-Custom-Route-Header"} {
				if !strings.Contains(string(logged), name+": [REDACTED]") {
					t.Fatalf("request log does not fully redact %s:\n%s", name, logged)
				}
			}
		})
	}
}

func TestRoutedCodexOAuthResponseHeaderLogsDoNotEchoInjectedSecrets(t *testing.T) {
	const (
		authorizationSecret = "DZPT-routed-oauth-token-HGFC"
		edgeeAPIKeySecret   = "EQAS-edgee-api-key-JKLM"
		sessionIDSecret     = "165e0091-7f30-4f0b-a0ed-3e45e2bb9876"
		configuredSecret    = "FRBN-configured-header-UVWX"
	)
	headers := http.Header{
		"Authorization":         {"Bearer " + authorizationSecret},
		"X-Edgee-Api-Key":       {edgeeAPIKeySecret},
		"X-Edgee-Session-Id":    {sessionIDSecret},
		"X-Custom-Route-Header": {configuredSecret},
	}
	cfg := &config.Config{
		SDKConfig:         config.SDKConfig{RequestLog: true},
		CodexOAuthHeaders: map[string]string{"X-Custom-Route-Header": configuredSecret},
	}

	tests := []struct {
		name   string
		record func(context.Context, *config.Config, http.Header)
		key    string
	}{
		{
			name: "HTTP response",
			record: func(ctx context.Context, cfg *config.Config, headers http.Header) {
				RecordAPIRequest(ctx, cfg, UpstreamRequestLog{})
				RecordAPIResponseMetadata(ctx, cfg, http.StatusOK, headers)
			},
			key: apiResponseKey,
		},
		{
			name: "websocket handshake",
			record: func(ctx context.Context, cfg *config.Config, headers http.Header) {
				RecordAPIWebsocketHandshake(ctx, cfg, http.StatusSwitchingProtocols, headers)
			},
			key: apiWebsocketTimelineKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx := cliproxyexecutor.WithCodexOAuthRoute(context.Background(), sessionIDSecret)
			ctx = context.WithValue(ctx, "gin", ginCtx)

			tt.record(ctx, cfg, headers)

			value, exists := ginCtx.Get(tt.key)
			if !exists {
				t.Fatalf("response log key %q was not recorded", tt.key)
			}
			logged, ok := value.([]byte)
			if !ok {
				t.Fatalf("response log type = %T, want []byte", value)
			}
			for _, secret := range []string{authorizationSecret, edgeeAPIKeySecret, sessionIDSecret, configuredSecret} {
				for _, fragment := range []string{secret, secret[:4], secret[len(secret)-4:]} {
					if strings.Contains(string(logged), fragment) {
						t.Fatalf("response log contains secret fragment %q from %q:\n%s", fragment, secret, logged)
					}
				}
			}
		})
	}
}
