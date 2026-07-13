package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type principalAuthProvider struct {
	provider string
}

func (p principalAuthProvider) Identifier() string {
	if p.provider != "" {
		return p.provider
	}
	return sdkaccess.DefaultAccessProviderName
}

func (p principalAuthProvider) Authenticate(_ context.Context, request *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	authorization := request.Header.Get("Authorization")
	principal := authorization
	metadata := map[string]string{"source": "authorization"}
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		principal = strings.TrimSpace(parts[1])
		metadata["credential-kind"] = "bearer"
	}
	return &sdkaccess.Result{Provider: p.Identifier(), Principal: principal, Metadata: metadata}, nil
}

func testCodexOAuthRouteMiddleware(t *testing.T, provider sdkaccess.Provider, routeKeys ...string) (*gin.Engine, *sdkaccess.Manager) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	manager := sdkaccess.NewManager()
	manager.SetProviders([]sdkaccess.Provider{provider})
	engine := gin.New()
	engine.Use(authMiddleware(manager, stringSet(routeKeys)))
	return engine, manager
}

func TestCodexOAuthRouteMiddlewareUsesAuthenticatedPrincipal(t *testing.T) {
	const sessionID = "123e4567-e89b-42d3-a456-426614174000"
	tests := []struct {
		name           string
		authorization  string
		provider       sdkaccess.Provider
		sessionHeaders []string
		routingHeader  string
		wantStatus     int
		wantRouted     bool
		wantSessionID  string
	}{
		{
			name:           "routed principal with valid lowercase UUIDv4",
			authorization:  "Bearer route-key",
			sessionHeaders: []string{sessionID},
			wantStatus:     http.StatusOK,
			wantRouted:     true,
			wantSessionID:  sessionID,
		},
		{
			name:          "routed principal without session ID",
			authorization: "Bearer route-key",
			wantStatus:    http.StatusOK,
			wantRouted:    true,
		},
		{
			name:           "ordinary principal ignores invalid session ID",
			authorization:  "Bearer ordinary-key",
			sessionHeaders: []string{"not-a-uuid"},
			wantStatus:     http.StatusOK,
		},
		{
			name:          "routing-like header cannot opt ordinary principal in",
			authorization: "Bearer ordinary-key",
			routingHeader: "true",
			wantStatus:    http.StatusOK,
		},
		{
			name:          "raw authorization route key is not a bearer",
			authorization: "route-key",
			wantStatus:    http.StatusOK,
		},
		{
			name:          "foreign provider principal collision does not route",
			authorization: "Bearer route-key",
			provider:      principalAuthProvider{provider: "foreign-provider"},
			wantStatus:    http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := tt.provider
			if provider == nil {
				provider = principalAuthProvider{}
			}
			engine, _ := testCodexOAuthRouteMiddleware(t, provider, "route-key")
			var gotRouted bool
			var gotSessionID string
			engine.GET("/test", func(c *gin.Context) {
				gotSessionID, gotRouted = cliproxyexecutor.CodexOAuthRoute(c.Request.Context())
				c.Status(http.StatusOK)
			})

			request := httptest.NewRequest(http.MethodGet, "/test", nil)
			request.Header.Set("Authorization", tt.authorization)
			for _, value := range tt.sessionHeaders {
				request.Header.Add("X-Edgee-Session-Id", value)
			}
			if tt.routingHeader != "" {
				request.Header.Set("X-Codex-OAuth-Route", tt.routingHeader)
			}
			response := httptest.NewRecorder()
			engine.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, tt.wantStatus, response.Body.String())
			}
			if gotRouted != tt.wantRouted || gotSessionID != tt.wantSessionID {
				t.Fatalf("CodexOAuthRoute() = (%q, %v), want (%q, %v)", gotSessionID, gotRouted, tt.wantSessionID, tt.wantRouted)
			}
		})
	}
}

func TestCodexOAuthRouteMiddlewareRejectsInvalidRoutedSessionID(t *testing.T) {
	const sessionID = "123e4567-e89b-42d3-a456-426614174000"
	tests := []struct {
		name   string
		values []string
	}{
		{name: "duplicate", values: []string{sessionID, sessionID}},
		{name: "uppercase", values: []string{strings.ToUpper(sessionID)}},
		{name: "non-v4", values: []string{"123e4567-e89b-12d3-a456-426614174000"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, _ := testCodexOAuthRouteMiddleware(t, principalAuthProvider{}, "route-key")
			handlerCalled := false
			engine.GET("/test", func(c *gin.Context) {
				handlerCalled = true
				c.Status(http.StatusOK)
			})

			request := httptest.NewRequest(http.MethodGet, "/test", nil)
			request.Header.Set("Authorization", "Bearer route-key")
			for _, value := range tt.values {
				request.Header.Add("X-Edgee-Session-Id", value)
			}
			response := httptest.NewRecorder()
			engine.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusBadRequest, response.Body.String())
			}
			if handlerCalled {
				t.Fatal("downstream handler called after invalid routed session ID")
			}
		})
	}
}
