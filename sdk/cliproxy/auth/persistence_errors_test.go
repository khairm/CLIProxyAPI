package auth

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type errorStore struct {
	err       error
	saveCount atomic.Int32
	mutate    func(*Auth)
}

type committedStoreError struct {
	err error
}

func (e *committedStoreError) Error() string              { return e.err.Error() }
func (e *committedStoreError) Unwrap() error              { return e.err }
func (e *committedStoreError) PersistenceCommitted() bool { return true }

func (s *errorStore) List(context.Context) ([]*Auth, error) { return nil, nil }

func (s *errorStore) Save(_ context.Context, auth *Auth) (string, error) {
	s.saveCount.Add(1)
	if s.mutate != nil {
		s.mutate(auth)
	}
	return "", s.err
}

func (s *errorStore) Delete(context.Context, string) error { return nil }

func TestManagerRegisterSurfacesPersistenceError(t *testing.T) {
	errStore := errors.New("store save failed")
	store := &errorStore{err: errStore}
	m := NewManager(store, nil, nil)

	_, errRegister := m.Register(context.Background(), &Auth{
		ID:       "register-persist-error",
		Provider: "codex",
		Metadata: map[string]any{"type": "codex"},
	})
	if !errors.Is(errRegister, errStore) {
		t.Fatalf("Register error = %v, want wrapped store error", errRegister)
	}
	if got := store.saveCount.Load(); got != 1 {
		t.Fatalf("Save calls = %d, want 1", got)
	}
	if _, exists := m.GetByID("register-persist-error"); exists {
		t.Fatal("auth was installed in memory after registration persistence failed")
	}
}

func TestManagerRegisterKeepsDatabaseCommittedStateWhileSurfacingMirrorError(t *testing.T) {
	errMirror := errors.New("local mirror replacement failed")
	store := &errorStore{
		err: &committedStoreError{err: errMirror},
		mutate: func(auth *Auth) {
			auth.Attributes = map[string]string{
				AttributePath:          "/spool/codex.json",
				AttributeSourceBackend: AuthSourcePostgres,
			}
			auth.FileName = "codex.json"
		},
	}
	m := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "register-committed-mirror-error",
		Provider: "codex",
		Metadata: map[string]any{"type": "codex"},
	}

	registered, errRegister := m.Register(context.Background(), auth)
	if !errors.Is(errRegister, errMirror) {
		t.Fatalf("Register error = %v, want wrapped mirror error", errRegister)
	}
	if registered == nil || registered.ID != auth.ID {
		t.Fatalf("Register auth = %+v, want database-committed auth", registered)
	}
	if registered.AuthSourceKind() != AuthSourcePostgres || registered.Attributes[AttributePath] != "/spool/codex.json" || registered.FileName != "codex.json" {
		t.Fatalf("Register auth source = %+v, want committed Postgres attributes", registered)
	}
	if stored, ok := m.GetByID(auth.ID); !ok || stored == nil {
		t.Fatalf("in-memory auth = %+v, %v; want database-committed auth", stored, ok)
	} else if stored.AuthSourceKind() != AuthSourcePostgres || stored.Attributes[AttributePath] != "/spool/codex.json" || stored.FileName != "codex.json" {
		t.Fatalf("in-memory auth source = %+v, want committed Postgres attributes", stored)
	}
}

func TestManagerUpdateSurfacesPersistenceError(t *testing.T) {
	errStore := errors.New("store save failed")
	store := &errorStore{err: errStore}
	m := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "update-persist-error",
		Provider: "codex",
		Metadata: map[string]any{"type": "codex"},
	}
	if _, errRegister := m.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	auth.Metadata["access_token"] = "replacement"

	_, errUpdate := m.Update(context.Background(), auth)
	if !errors.Is(errUpdate, errStore) {
		t.Fatalf("Update error = %v, want wrapped store error", errUpdate)
	}
	if got := store.saveCount.Load(); got != 1 {
		t.Fatalf("Save calls = %d, want 1", got)
	}
	stored, ok := m.GetByID(auth.ID)
	if !ok || stored.Metadata["access_token"] == "replacement" {
		t.Fatalf("in-memory auth changed after update persistence failed: %+v", stored)
	}
}

func TestManagerUpdateKeepsDatabaseCommittedStateWhileSurfacingMirrorError(t *testing.T) {
	errMirror := errors.New("local mirror replacement failed")
	store := &errorStore{err: &committedStoreError{err: errMirror}}
	m := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "update-committed-mirror-error",
		Provider: "codex",
		Metadata: map[string]any{"type": "codex", "access_token": "old"},
	}
	if _, errRegister := m.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	auth.Metadata["access_token"] = "new"

	updated, errUpdate := m.Update(context.Background(), auth)
	if !errors.Is(errUpdate, errMirror) {
		t.Fatalf("Update error = %v, want wrapped mirror error", errUpdate)
	}
	if updated == nil || updated.Metadata["access_token"] != "new" {
		t.Fatalf("Update auth = %+v, want database-committed state", updated)
	}
	stored, ok := m.GetByID(auth.ID)
	if !ok || stored.Metadata["access_token"] != "new" {
		t.Fatalf("in-memory auth = %+v, want database-committed state", stored)
	}
}

func TestManagerMarkResultSurfacesPersistenceError(t *testing.T) {
	errStore := errors.New("store save failed")
	store := &errorStore{err: errStore}
	m := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "mark-result-persist-error",
		Provider: "codex",
		Metadata: map[string]any{"type": "codex"},
	}
	if _, errRegister := m.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	errMark := m.MarkResult(context.Background(), Result{AuthID: auth.ID, Provider: auth.Provider, Success: true})
	if !errors.Is(errMark, errStore) {
		t.Fatalf("MarkResult error = %v, want wrapped store error", errMark)
	}
	if got := store.saveCount.Load(); got != 1 {
		t.Fatalf("Save calls = %d, want 1", got)
	}
	stored, ok := m.GetByID(auth.ID)
	if !ok || stored.Success != 0 || stored.Failed != 0 || stored.Status == StatusError {
		t.Fatalf("in-memory auth health changed after result persistence failed: %+v", stored)
	}
}

func TestManagerMarkResultKeepsDatabaseCommittedHealthWhileSurfacingMirrorError(t *testing.T) {
	errMirror := errors.New("local mirror replacement failed")
	store := &errorStore{err: &committedStoreError{err: errMirror}}
	m := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "mark-result-committed-mirror-error",
		Provider: "codex",
		Metadata: map[string]any{"type": "codex"},
	}
	if _, errRegister := m.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	errMark := m.MarkResult(context.Background(), Result{AuthID: auth.ID, Provider: auth.Provider, Success: true})
	if !errors.Is(errMark, errMirror) {
		t.Fatalf("MarkResult error = %v, want wrapped mirror error", errMark)
	}
	stored, ok := m.GetByID(auth.ID)
	if !ok || stored.Success != 1 || stored.Failed != 0 {
		t.Fatalf("in-memory auth health = %+v, want database-committed success", stored)
	}
}

type tokenStorageFileStore struct {
	path string
}

func (s *tokenStorageFileStore) List(context.Context) ([]*Auth, error) { return nil, nil }

func (s *tokenStorageFileStore) Save(_ context.Context, auth *Auth) (string, error) {
	if setter, ok := auth.Storage.(interface{ SetMetadata(map[string]any) }); ok {
		setter.SetMetadata(auth.Metadata)
	}
	if errSave := auth.Storage.SaveTokenToFile(s.path); errSave != nil {
		return "", errSave
	}
	return s.path, nil
}

func (s *tokenStorageFileStore) Delete(context.Context, string) error { return nil }

func TestCodexPersistenceCloneKeepsTokensAndDoesNotMutateLiveStorage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "codex.json")
	store := &tokenStorageFileStore{path: path}
	m := NewManager(store, nil, nil)
	storage := &codexauth.CodexTokenStorage{
		IDToken:      "id-token",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		AccountID:    "account-id",
		Email:        "user@example.com",
		Expire:       "2099-01-01T00:00:00Z",
	}
	auth := &Auth{
		ID:       "codex-storage-clone",
		Provider: "codex",
		Storage:  storage,
		Metadata: map[string]any{"email": storage.Email},
	}
	if _, errRegister := m.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}

	if errMark := m.MarkResultWithError(context.Background(), Result{AuthID: auth.ID, Provider: auth.Provider, Success: true}); errMark != nil {
		t.Fatalf("MarkResultWithError() error = %v", errMark)
	}
	updated, ok := m.GetByID(auth.ID)
	if !ok {
		t.Fatal("registered auth missing")
	}
	updated.Metadata["custom"] = "updated"
	if _, errUpdate := m.Update(context.Background(), updated); errUpdate != nil {
		t.Fatalf("Update() error = %v", errUpdate)
	}
	if _, mutated := storage.Metadata["custom"]; mutated {
		t.Fatalf("live token storage metadata was mutated: %#v", storage.Metadata)
	}

	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read auth file: %v", errRead)
	}
	var persisted map[string]any
	if errUnmarshal := json.Unmarshal(raw, &persisted); errUnmarshal != nil {
		t.Fatalf("unmarshal auth file: %v", errUnmarshal)
	}
	for key, want := range map[string]string{
		"id_token":      storage.IDToken,
		"access_token":  storage.AccessToken,
		"refresh_token": storage.RefreshToken,
		"account_id":    storage.AccountID,
		"expired":       storage.Expire,
		"type":          "codex",
	} {
		if got, _ := persisted[key].(string); got != want {
			t.Fatalf("persisted %s = %q, want %q; file=%s", key, got, want, raw)
		}
	}
}

func TestManagerRefreshAuthForRequestSurfacesUpdatePersistenceError(t *testing.T) {
	errStore := errors.New("store save failed")
	store := &errorStore{err: errStore}
	m := NewManager(store, nil, nil)
	executor := &unauthorizedRefreshExecutor{
		id:           "codex",
		tokenInvalid: map[string]struct{}{},
		refreshTokens: map[string]string{
			"refresh-persist-error": "fresh-access-token",
		},
	}
	m.RegisterExecutor(executor)
	auth := &Auth{
		ID:       "refresh-persist-error",
		Provider: "codex",
		Metadata: map[string]any{
			"access_token":  "stale-access-token",
			"refresh_token": "refresh-token",
		},
	}
	if _, errRegister := m.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	model := "refresh-persistence-model"
	m.mu.Lock()
	m.auths[auth.ID].ModelStates = map[string]*ModelState{
		model: {
			Unavailable: true,
			Status:      StatusError,
			LastError:   &Error{HTTPStatus: 401, Message: "unauthorized"},
		},
	}
	m.mu.Unlock()
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: model}})
	reg.SuspendClientModel(auth.ID, model, "unauthorized")
	t.Cleanup(func() { reg.UnregisterClient(auth.ID) })

	refreshed, errRefresh := m.refreshAuthForRequest(context.Background(), auth.ID, "stale-access-token")
	if !errors.Is(errRefresh, errStore) {
		t.Fatalf("refreshAuthForRequest error = %v, want wrapped store error", errRefresh)
	}
	if refreshed != nil {
		t.Fatalf("refreshAuthForRequest auth = %+v, want nil on persistence failure", refreshed)
	}
	if got := executor.RefreshCalls(); got != 1 {
		t.Fatalf("Refresh calls = %d, want 1", got)
	}
	if got := store.saveCount.Load(); got != 1 {
		t.Fatalf("Save calls = %d, want 1", got)
	}
	if count := reg.GetModelCount(model); count != 0 {
		t.Fatalf("available model count = %d, want suspended after persistence failure", count)
	}
}

func TestManagerExecuteSurfacesUnauthorizedRefreshPersistenceError(t *testing.T) {
	m, executor, primary, _, model := newUnauthorizedRefreshFixture(t, false)
	errStore := errors.New("store save failed")
	store := &errorStore{err: errStore}
	m.SetStore(store)

	_, errExecute := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if !errors.Is(errExecute, errStore) {
		t.Fatalf("Execute error = %v, want wrapped persistence error", errExecute)
	}
	if got := executor.RefreshCalls(); got != 1 {
		t.Fatalf("Refresh calls = %d, want 1", got)
	}
	if calls := executor.ExecuteCalls(); len(calls) != 1 || calls[0] != primary.ID {
		t.Fatalf("Execute calls = %v, want only primary before persistence failure", calls)
	}
}

func TestManagerExecuteKeepsDatabaseCommittedRefreshWhileSurfacingMirrorError(t *testing.T) {
	m, executor, primary, _, model := newUnauthorizedRefreshFixture(t, false)
	errMirror := errors.New("local mirror replacement failed")
	store := &errorStore{err: &committedStoreError{err: errMirror}}
	m.SetStore(store)

	_, errExecute := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if !errors.Is(errExecute, errMirror) {
		t.Fatalf("Execute error = %v, want wrapped mirror error", errExecute)
	}
	if got := executor.RefreshCalls(); got != 1 {
		t.Fatalf("Refresh calls = %d, want 1", got)
	}
	updated, ok := m.GetByID(primary.ID)
	if !ok || authAccessToken(updated) != "fresh-access-token" {
		t.Fatalf("in-memory auth = %+v, want database-committed refresh", updated)
	}
}

func TestManagerUpdatePersistenceFailurePreservesInheritedModelState(t *testing.T) {
	errStore := errors.New("store save failed")
	m := NewManager(&errorStore{err: errStore}, nil, nil)
	m.runtimeConfig.Store(&internalconfig.Config{DisableCooling: true})
	auth := &Auth{
		ID:       "update-model-state-persist-error",
		Provider: "codex",
		Metadata: map[string]any{"type": "codex"},
	}
	if _, errRegister := m.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	wantRetry := time.Now().Add(time.Hour)
	m.mu.Lock()
	m.auths[auth.ID].ModelStates = map[string]*ModelState{
		"gpt-5": {Unavailable: true, Status: StatusError, NextRetryAfter: wantRetry},
	}
	update := m.auths[auth.ID].Clone()
	update.ModelStates = nil
	m.mu.Unlock()

	if _, errUpdate := m.Update(context.Background(), update); !errors.Is(errUpdate, errStore) {
		t.Fatalf("Update error = %v, want wrapped persistence error", errUpdate)
	}
	stored, ok := m.GetByID(auth.ID)
	state := stored.ModelStates["gpt-5"]
	if !ok || state == nil || !state.Unavailable || !state.NextRetryAfter.Equal(wantRetry) {
		t.Fatalf("in-memory model state changed after persistence failure: %+v", state)
	}
}

var _ Store = (*errorStore)(nil)
