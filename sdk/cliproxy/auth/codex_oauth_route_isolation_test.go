package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type codexOAuthRouteSelectionExecutor struct {
	provider string
	calls    []string
}

func (e *codexOAuthRouteSelectionExecutor) Identifier() string { return e.provider }

func (e *codexOAuthRouteSelectionExecutor) Execute(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.calls = append(e.calls, auth.ID)
	return cliproxyexecutor.Response{Payload: []byte(auth.ID)}, nil
}

func (e *codexOAuthRouteSelectionExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (e *codexOAuthRouteSelectionExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (e *codexOAuthRouteSelectionExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *codexOAuthRouteSelectionExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestManagerExecuteCodexOAuthRouteUnauthorizedDoesNotRefreshSharedCredential(t *testing.T) {
	m, executor, primary, backup, model := newUnauthorizedRefreshFixture(t, false)
	m.SetConfig(&internalconfig.Config{CodexOAuthBaseURL: "https://edge.example.test/codex"})
	ctx := cliproxyexecutor.WithCodexOAuthRoute(context.Background(), "9ea20258-9c30-4e64-a68d-84e08bceb90c")

	resp, errExecute := m.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if errExecute != nil {
		t.Fatalf("Execute error = %v, want success via backup", errExecute)
	}
	if got := string(resp.Payload); got != backup.ID+":backup-access-token" {
		t.Fatalf("payload = %q, want backup response", got)
	}
	if got := executor.RefreshCalls(); got != 0 {
		t.Fatalf("Refresh calls = %d, want 0 for override-route 401", got)
	}
	if got := executor.ExecuteCalls(); len(got) != 2 || got[0] != primary.ID || got[1] != backup.ID {
		t.Fatalf("Execute calls = %v, want [primary, backup] without refresh retry", got)
	}

	updated, ok := m.GetByID(primary.ID)
	if !ok || updated == nil {
		t.Fatal("primary auth missing after override-route failure")
	}
	assertCodexOAuthRouteDidNotChangeAuthHealth(t, updated, model, primary.Status)
}

func TestManagerMarkResultCodexOAuthRouteFailuresDoNotChangeSharedCredentialHealth(t *testing.T) {
	statuses := []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
	}

	for _, status := range statuses {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			store := &errorStore{}
			m := NewManager(store, nil, nil)
			auth := &Auth{
				ID:        "codex-route-local-" + http.StatusText(status),
				Provider:  "codex",
				Status:    StatusActive,
				UpdatedAt: time.Unix(123, 0),
				Metadata: map[string]any{
					"access_token":  "shared-access-token",
					"refresh_token": "shared-refresh-token",
				},
			}
			if _, errRegister := m.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
				t.Fatalf("register auth: %v", errRegister)
			}

			model := "codex-route-local-model-" + http.StatusText(status)
			reg := registry.GetGlobalRegistry()
			reg.RegisterClient(auth.ID, "codex", []*registry.ModelInfo{{ID: model}})
			t.Cleanup(func() { reg.UnregisterClient(auth.ID) })

			ctx := cliproxyexecutor.WithCodexOAuthRoute(context.Background(), "")
			errMark := m.MarkResultWithError(ctx, Result{
				AuthID:   auth.ID,
				Provider: auth.Provider,
				Model:    model,
				Success:  false,
				Error:    &Error{HTTPStatus: status, Message: http.StatusText(status)},
			})
			if errMark != nil {
				t.Fatalf("MarkResult error = %v", errMark)
			}

			updated, ok := m.GetByID(auth.ID)
			if !ok || updated == nil {
				t.Fatal("auth missing after override-route failure")
			}
			assertCodexOAuthRouteDidNotChangeAuthHealth(t, updated, model, auth.Status)
			if !updated.UpdatedAt.Equal(auth.UpdatedAt) {
				t.Fatalf("UpdatedAt = %v, want unchanged %v", updated.UpdatedAt, auth.UpdatedAt)
			}
			if count := reg.GetModelCount(model); count != 1 {
				t.Fatalf("available model count = %d, want 1 after override-route failure", count)
			}
			if got := store.saveCount.Load(); got != 0 {
				t.Fatalf("persistence Save calls = %d, want 0 for override-route failure", got)
			}
		})
	}
}

func TestManagerMarkResultStockFailureStillMarksSharedCredentialHealth(t *testing.T) {
	m := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:       "codex-stock-health",
		Provider: "codex",
		Status:   StatusActive,
		Metadata: map[string]any{"access_token": "shared-access-token"},
	}
	if _, errRegister := m.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	model := "codex-stock-health-model"
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, "codex", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { reg.UnregisterClient(auth.ID) })

	errMark := m.MarkResultWithError(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: auth.Provider,
		Model:    model,
		Success:  false,
		Error:    &Error{HTTPStatus: http.StatusUnauthorized, Message: "unauthorized"},
	})
	if errMark != nil {
		t.Fatalf("MarkResult error = %v", errMark)
	}

	updated, ok := m.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatal("auth missing after stock-route failure")
	}
	state := updated.ModelStates[model]
	if state == nil || !state.Unavailable || state.NextRetryAfter.IsZero() {
		t.Fatalf("stock-route model state = %+v, want unavailable with cooldown", state)
	}
	if updated.Status != StatusError || updated.LastError == nil {
		t.Fatalf("stock-route auth health = status %q error %+v, want error health", updated.Status, updated.LastError)
	}
	if updated.Failed != 1 {
		t.Fatalf("stock-route failed count = %d, want 1", updated.Failed)
	}
	if count := reg.GetModelCount(model); count != 0 {
		t.Fatalf("available model count = %d, want 0 after stock-route 401", count)
	}
}

func TestManagerCodexOAuthRouteRejectsCodexAPIKeyCredential(t *testing.T) {
	m := NewManager(nil, nil, nil)
	m.SetConfig(&internalconfig.Config{CodexOAuthBaseURL: "https://edge.example.test/codex"})
	executor := &codexOAuthRouteSelectionExecutor{provider: "codex"}
	m.RegisterExecutor(executor)
	auth := &Auth{
		ID:         "codex-api-key-health",
		Provider:   "codex",
		Status:     StatusActive,
		Attributes: map[string]string{AttributeAPIKey: "upstream-api-key"},
	}
	if _, errRegister := m.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	ctx := cliproxyexecutor.WithCodexOAuthRoute(context.Background(), "")
	_, errExecute := m.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: "gpt-5"}, cliproxyexecutor.Options{})
	assertCodexOAuthRouteUnavailable(t, errExecute)
	if len(executor.calls) != 0 {
		t.Fatalf("Execute calls = %v, want no upstream execution", executor.calls)
	}

	updated, ok := m.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatal("Codex API-key auth missing after route rejection")
	}
	assertCodexOAuthRouteDidNotChangeAuthHealth(t, updated, "gpt-5", auth.Status)
}

func TestManagerCodexOAuthRouteRejectsNonCodexProvider(t *testing.T) {
	m := NewManager(nil, nil, nil)
	ctx := cliproxyexecutor.WithCodexOAuthRoute(context.Background(), "")

	_, errExecute := m.Execute(ctx, []string{"claude"}, cliproxyexecutor.Request{Model: "claude-sonnet-4"}, cliproxyexecutor.Options{})
	assertCodexOAuthRouteUnavailable(t, errExecute)
}

func TestManagerCodexOAuthRouteSelectsOAuthFromMixedCredentialPool(t *testing.T) {
	m := NewManager(nil, nil, nil)
	m.SetConfig(&internalconfig.Config{CodexOAuthBaseURL: "https://edge.example.test/codex"})
	executor := &codexOAuthRouteSelectionExecutor{provider: "codex"}
	m.RegisterExecutor(executor)
	auths := []*Auth{
		{
			ID:         "codex-api-key",
			Provider:   "codex",
			Status:     StatusActive,
			Attributes: map[string]string{AttributeAPIKey: "upstream-api-key"},
		},
		{
			ID:       "codex-oauth",
			Provider: "codex",
			Status:   StatusActive,
			Metadata: map[string]any{"access_token": "oauth-access-token"},
		},
	}
	for _, auth := range auths {
		if _, errRegister := m.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
			t.Fatalf("register auth %q: %v", auth.ID, errRegister)
		}
	}

	ctx := cliproxyexecutor.WithCodexOAuthRoute(context.Background(), "")
	resp, errExecute := m.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if got := string(resp.Payload); got != "codex-oauth" {
		t.Fatalf("Execute() payload = %q, want OAuth credential ID", got)
	}
	if len(executor.calls) != 1 || executor.calls[0] != "codex-oauth" {
		t.Fatalf("Execute calls = %v, want only Codex OAuth credential", executor.calls)
	}
}

func assertCodexOAuthRouteUnavailable(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("error = nil, want route_unavailable")
	}
	var authErr *Error
	if !errors.As(err, &authErr) || authErr == nil {
		t.Fatalf("error = %T %v, want *Error", err, err)
	}
	if authErr.Code != "route_unavailable" || authErr.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("error = %+v, want route_unavailable HTTP %d", authErr, http.StatusServiceUnavailable)
	}
}

func assertCodexOAuthRouteDidNotChangeAuthHealth(t *testing.T, auth *Auth, model string, wantStatus Status) {
	t.Helper()
	if auth.Status != wantStatus {
		t.Fatalf("auth status = %q, want unchanged %q", auth.Status, wantStatus)
	}
	if auth.Unavailable {
		t.Fatal("auth became unavailable after override-route failure")
	}
	if auth.LastError != nil || auth.StatusMessage != "" {
		t.Fatalf("auth error health changed: LastError=%+v StatusMessage=%q", auth.LastError, auth.StatusMessage)
	}
	if !auth.NextRetryAfter.IsZero() || !auth.NextRefreshAfter.IsZero() {
		t.Fatalf("auth cooldown changed: NextRetryAfter=%v NextRefreshAfter=%v", auth.NextRetryAfter, auth.NextRefreshAfter)
	}
	if auth.Quota.Exceeded || !auth.Quota.NextRecoverAt.IsZero() || auth.Quota.BackoffLevel != 0 {
		t.Fatalf("auth quota changed: %+v", auth.Quota)
	}
	if auth.Failed != 0 {
		t.Fatalf("auth failed count = %d, want 0", auth.Failed)
	}
	if state := auth.ModelStates[model]; state != nil {
		t.Fatalf("model health was created or changed after override-route failure: %+v", state)
	}
}
