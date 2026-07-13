package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestGetContextWithCancelPreservesCodexOAuthRoute(t *testing.T) {
	tests := []struct {
		name          string
		requestCtx    context.Context
		wantRouted    bool
		wantSessionID string
	}{
		{name: "ordinary", requestCtx: context.Background()},
		{name: "routed without session", requestCtx: coreexecutor.WithCodexOAuthRoute(context.Background(), ""), wantRouted: true},
		{name: "routed with session", requestCtx: coreexecutor.WithCodexOAuthRoute(context.Background(), "123e4567-e89b-42d3-a456-426614174000"), wantRouted: true, wantSessionID: "123e4567-e89b-42d3-a456-426614174000"},
	}

	gin.SetMode(gin.TestMode)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ginContext, _ := gin.CreateTestContext(httptest.NewRecorder())
			request := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
			ginContext.Request = request.WithContext(tt.requestCtx)
			handler := &BaseAPIHandler{Cfg: &config.SDKConfig{}}

			executionCtx, cancel := handler.GetContextWithCancel(nil, ginContext, context.Background())
			defer cancel()

			sessionID, routed := coreexecutor.CodexOAuthRoute(executionCtx)
			if routed != tt.wantRouted || sessionID != tt.wantSessionID {
				t.Fatalf("CodexOAuthRoute() = (%q, %v), want (%q, %v)", sessionID, routed, tt.wantSessionID, tt.wantRouted)
			}
		})
	}
}
