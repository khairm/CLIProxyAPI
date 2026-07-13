package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

type codexOAuthRoundTripFunc func(*http.Request) (*http.Response, error)

func (f codexOAuthRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func codexOAuthCompletedResponse(req *http.Request) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/event-stream"}},
		Body: io.NopCloser(strings.NewReader(
			"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":0,\"output_tokens\":0,\"total_tokens\":0}}}\n\n",
		)),
		Request: req,
	}
}

func codexOAuthExecutionContext(apiKey, requestID string, routed bool, sessionID string, rt http.RoundTripper) context.Context {
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ginCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	ginCtx.Request.Header.Set("Authorization", "Bearer "+apiKey)
	ginCtx.Request.Header.Set("User-Agent", "wire-identity-test/1.0")
	ginCtx.Request.Header.Set("X-Client-Request-Id", requestID)
	if sessionID != "" {
		ginCtx.Request.Header.Set("X-Edgee-Session-Id", sessionID)
	}
	ginCtx.Set("userApiKey", apiKey)

	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	if routed {
		ctx = cliproxyexecutor.WithCodexOAuthRoute(ctx, sessionID)
	}
	if rt != nil {
		ctx = context.WithValue(ctx, "cliproxy.roundtripper", rt)
	}
	return ctx
}

func executeCodexOAuthTestRequest(ctx context.Context, exec *CodexExecutor, auth *cliproxyauth.Auth) error {
	_, errExecute := exec.Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "gpt-5-codex",
		Payload: []byte(`{"model":"gpt-5-codex","input":"hello"}`),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response")})
	return errExecute
}

func TestCodexExecutorOAuthBaseURLDefaultsToStock(t *testing.T) {
	exec := NewCodexExecutor(&config.Config{})
	_, baseURL := exec.codexCreds(context.Background(), &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{"access_token": "oauth-token"},
	})
	if baseURL != codexDefaultBaseURL {
		t.Fatalf("baseURL = %q, want stock %q", baseURL, codexDefaultBaseURL)
	}
}

func TestCodexAutoExecutorConfiguredOAuthBaseUsesHTTPResponsesEndpoint(t *testing.T) {
	var gotPath string
	var gotUpgrade string
	var gotEdgeKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotUpgrade = r.Header.Get("Upgrade")
		gotEdgeKey = r.Header.Get("X-Edgee-Api-Key")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":0,\"output_tokens\":0,\"total_tokens\":0}}}\n\n"))
	}))
	defer server.Close()

	exec := NewCodexAutoExecutor(&config.Config{
		CodexOAuthBaseURL: server.URL,
		CodexOAuthHeaders: map[string]string{"x-edgee-api-key": "edge-key"},
		SDKConfig:         config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll},
	})
	auth := &cliproxyauth.Auth{
		Provider:   "codex",
		Attributes: map[string]string{"websockets": "true"},
		Metadata:   map[string]any{"access_token": "oauth-token"},
	}
	ctx := cliproxyexecutor.WithCodexOAuthRoute(context.Background(), "")
	ctx = cliproxyexecutor.WithDownstreamWebsocket(ctx)

	_, errExecute := exec.Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "gpt-5-codex",
		Payload: []byte(`{"model":"gpt-5-codex","input":"hello"}`),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response")})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if gotPath != "/responses" {
		t.Fatalf("request path = %q, want /responses", gotPath)
	}
	if gotUpgrade != "" {
		t.Fatalf("Upgrade = %q, want plain HTTP request", gotUpgrade)
	}
	if gotEdgeKey != "edge-key" {
		t.Fatalf("X-Edgee-Api-Key = %q, want configured header", gotEdgeKey)
	}
}

func TestCodexExecutorOAuthConfigIsStableAcrossTokenRefreshAndConfigMutation(t *testing.T) {
	cfg := &config.Config{
		CodexOAuthBaseURL: "https://edge.example.com/codex",
		CodexOAuthHeaders: map[string]string{"x-edgee-api-key": "startup-key"},
	}
	exec := NewCodexExecutor(cfg)
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{"access_token": "old-token"},
	}

	refreshedAuth, errRefresh := exec.Refresh(context.Background(), auth)
	if errRefresh != nil {
		t.Fatalf("Refresh() error = %v", errRefresh)
	}
	routeCtx := cliproxyexecutor.WithCodexOAuthRoute(context.Background(), "")
	oldToken, oldBaseURL := exec.codexCreds(routeCtx, refreshedAuth)
	auth.Metadata["access_token"] = "refreshed-token"
	cfg.CodexOAuthBaseURL = "https://reload.example.com/codex"
	cfg.CodexOAuthHeaders["x-edgee-api-key"] = "reload-key"
	newToken, newBaseURL := exec.codexCreds(routeCtx, auth)

	if oldToken != "old-token" || newToken != "refreshed-token" {
		t.Fatalf("tokens = %q, %q; want old and refreshed token", oldToken, newToken)
	}
	if oldBaseURL != "https://edge.example.com/codex" || newBaseURL != oldBaseURL {
		t.Fatalf("base URLs = %q, %q; want immutable startup route", oldBaseURL, newBaseURL)
	}
	httpReq, errRequest := http.NewRequestWithContext(routeCtx, http.MethodPost, newBaseURL+"/responses", nil)
	if errRequest != nil {
		t.Fatalf("NewRequest() error = %v", errRequest)
	}
	exec.applyCodexOAuthHeaders(httpReq, auth)
	if got := httpReq.Header.Get("X-Edgee-Api-Key"); got != "startup-key" {
		t.Fatalf("X-Edgee-Api-Key = %q, want immutable startup value", got)
	}
}

func TestCodexExecutorHttpRequestRewritesStockOAuthURLToConfiguredBase(t *testing.T) {
	var gotPath string
	var gotEdgeKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotEdgeKey = r.Header.Get("X-Edgee-Api-Key")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	exec := NewCodexExecutor(&config.Config{
		CodexOAuthBaseURL: server.URL + "/edge/codex",
		CodexOAuthHeaders: map[string]string{"x-edgee-api-key": "edge-key"},
	})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{"access_token": "oauth-token"},
	}
	req, errRequest := http.NewRequest(http.MethodPost, codexDefaultBaseURL+"/responses", nil)
	if errRequest != nil {
		t.Fatalf("NewRequest() error = %v", errRequest)
	}

	routeCtx := cliproxyexecutor.WithCodexOAuthRoute(context.Background(), "065e0091-7f30-4f0b-a0ed-3e45e2bb1124")
	resp, errHTTP := exec.HttpRequest(routeCtx, auth, req)
	if errHTTP != nil {
		t.Fatalf("HttpRequest() error = %v", errHTTP)
	}
	if _, errRead := io.Copy(io.Discard, resp.Body); errRead != nil {
		t.Fatalf("read response body: %v", errRead)
	}
	if errClose := resp.Body.Close(); errClose != nil {
		t.Fatalf("close response body: %v", errClose)
	}
	if gotPath != "/edge/codex/responses" {
		t.Fatalf("request path = %q, want /edge/codex/responses", gotPath)
	}
	if gotEdgeKey != "edge-key" {
		t.Fatalf("X-Edgee-Api-Key = %q, want configured header", gotEdgeKey)
	}
}

func TestCodexExecutorRoutedRequestOmitsAbsentSessionID(t *testing.T) {
	var gotSessionID string
	var gotEdgeKey string
	rt := codexOAuthRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotSessionID = req.Header.Get("X-Edgee-Session-Id")
		gotEdgeKey = req.Header.Get("X-Edgee-Api-Key")
		return codexOAuthCompletedResponse(req), nil
	})
	exec := NewCodexExecutor(&config.Config{
		CodexOAuthBaseURL: "https://edge.example.test/codex",
		CodexOAuthHeaders: map[string]string{
			"x-edgee-api-key":    "edge-key",
			"x-edgee-session-id": "must-not-be-synthesized",
		},
		SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll},
	})
	auth := &cliproxyauth.Auth{Provider: "codex", Metadata: map[string]any{"access_token": "oauth-token"}}
	ctx := codexOAuthExecutionContext("route-key", "routed-no-session", true, "", rt)

	if errExecute := executeCodexOAuthTestRequest(ctx, exec, auth); errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if gotSessionID != "" {
		t.Fatalf("X-Edgee-Session-Id = %q, want omitted", gotSessionID)
	}
	if gotEdgeKey != "edge-key" {
		t.Fatalf("X-Edgee-Api-Key = %q, want configured header", gotEdgeKey)
	}
}

func TestCodexExecutorOAuthHeadersAreNotAppliedWithoutBaseURL(t *testing.T) {
	exec := NewCodexExecutor(&config.Config{
		CodexOAuthHeaders: map[string]string{"x-edgee-api-key": "edge-key"},
	})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{"access_token": "oauth-token"},
	}
	req, errRequest := http.NewRequest(http.MethodPost, codexDefaultBaseURL+"/responses", nil)
	if errRequest != nil {
		t.Fatalf("NewRequest() error = %v", errRequest)
	}

	if errPrepare := exec.PrepareRequest(req, auth); errPrepare != nil {
		t.Fatalf("PrepareRequest() error = %v", errPrepare)
	}
	if got := req.Header.Get("X-Edgee-Api-Key"); got != "" {
		t.Fatalf("X-Edgee-Api-Key = %q, want empty without configured base URL", got)
	}
}

func TestCodexExecutorConfiguredOAuthBaseRejectsAPIKeyAuth(t *testing.T) {
	exec := NewCodexExecutor(&config.Config{
		CodexOAuthBaseURL: "https://edge.example.com/codex",
		CodexOAuthHeaders: map[string]string{"x-edgee-api-key": "edge-key"},
	})
	auth := &cliproxyauth.Auth{Provider: "codex", Attributes: map[string]string{
		"api_key":  "sk-test",
		"base_url": "https://api-key.example.com/v1",
	}}
	routeCtx := cliproxyexecutor.WithCodexOAuthRoute(context.Background(), "")
	req, errRequest := http.NewRequestWithContext(routeCtx, http.MethodPost, "https://api-key.example.com/v1/responses", nil)
	if errRequest != nil {
		t.Fatalf("NewRequest() error = %v", errRequest)
	}
	errPrepare := exec.PrepareRequest(req, auth)
	if errPrepare == nil {
		t.Fatal("PrepareRequest() error = nil, want route_unavailable")
	}
	statusErr, okStatus := errPrepare.(interface{ StatusCode() int })
	if !okStatus || statusErr.StatusCode() != http.StatusServiceUnavailable {
		t.Fatalf("PrepareRequest() error = %v, want HTTP %d", errPrepare, http.StatusServiceUnavailable)
	}
	if !strings.Contains(errPrepare.Error(), "route_unavailable") || !strings.Contains(errPrepare.Error(), "API-key") {
		t.Fatalf("PrepareRequest() error = %q, want route_unavailable API-key detail", errPrepare)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want no credential injection after rejection", got)
	}
}

func TestCodexExecutorConcurrentMixedRoutesAreRequestScoped(t *testing.T) {
	t.Parallel()

	const requestCount = 64
	type observation struct {
		requestID string
		url       string
		edgeKey   string
		sessionID string
	}

	observations := make(chan observation, requestCount)
	rt := codexOAuthRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		observations <- observation{
			requestID: req.Header.Get("X-Client-Request-Id"),
			url:       req.URL.String(),
			edgeKey:   req.Header.Get("X-Edgee-Api-Key"),
			sessionID: req.Header.Get("X-Edgee-Session-Id"),
		}
		return codexOAuthCompletedResponse(req), nil
	})
	exec := NewCodexExecutor(&config.Config{
		CodexOAuthBaseURL:      "https://edge.example.test/codex",
		CodexOAuthHeaders:      map[string]string{"x-edgee-api-key": "edge-key"},
		CodexOAuthRouteAPIKeys: []string{"route-key"},
		SDKConfig:              config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll},
	})
	auth := &cliproxyauth.Auth{Provider: "codex", Metadata: map[string]any{"access_token": "oauth-token"}}

	type expectation struct {
		routed    bool
		sessionID string
	}
	expected := make(map[string]expectation, requestCount)
	for index := 0; index < requestCount; index++ {
		requestID := fmt.Sprintf("mixed-%02d", index)
		routed := index%2 == 0
		sessionID := ""
		if routed {
			sessionID = fmt.Sprintf("00000000-0000-4000-8000-%012x", index)
		}
		expected[requestID] = expectation{routed: routed, sessionID: sessionID}
	}

	errCh := make(chan error, requestCount)
	var wg sync.WaitGroup
	for requestID, want := range expected {
		requestID, want := requestID, want
		wg.Add(1)
		go func() {
			defer wg.Done()
			apiKey := "ordinary-key"
			if want.routed {
				apiKey = "route-key"
			}
			ctx := codexOAuthExecutionContext(apiKey, requestID, want.routed, want.sessionID, rt)
			if errExecute := executeCodexOAuthTestRequest(ctx, exec, auth); errExecute != nil {
				errCh <- fmt.Errorf("%s: %w", requestID, errExecute)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for errExecute := range errCh {
		t.Errorf("Execute() error = %v", errExecute)
	}
	if t.Failed() {
		return
	}

	close(observations)
	seen := make(map[string]struct{}, requestCount)
	for got := range observations {
		want, ok := expected[got.requestID]
		if !ok {
			t.Errorf("unexpected request ID %q", got.requestID)
			continue
		}
		if _, duplicate := seen[got.requestID]; duplicate {
			t.Errorf("duplicate request ID %q", got.requestID)
			continue
		}
		seen[got.requestID] = struct{}{}
		if want.routed {
			if got.url != "https://edge.example.test/codex/responses" {
				t.Errorf("%s URL = %q, want override URL", got.requestID, got.url)
			}
			if got.edgeKey != "edge-key" {
				t.Errorf("%s X-Edgee-Api-Key = %q, want edge-key", got.requestID, got.edgeKey)
			}
			if got.sessionID != want.sessionID {
				t.Errorf("%s X-Edgee-Session-Id = %q, want %q", got.requestID, got.sessionID, want.sessionID)
			}
			continue
		}
		if got.url != codexDefaultBaseURL+"/responses" {
			t.Errorf("%s URL = %q, want stock URL", got.requestID, got.url)
		}
		if got.edgeKey != "" || got.sessionID != "" {
			t.Errorf("%s ordinary headers = edge %q session %q, want both omitted", got.requestID, got.edgeKey, got.sessionID)
		}
	}
	if len(seen) != requestCount {
		t.Errorf("captured %d requests, want %d", len(seen), requestCount)
	}
}
