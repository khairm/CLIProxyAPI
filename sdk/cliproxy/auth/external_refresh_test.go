package auth

import (
	"context"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type pilotAuthShape struct {
	name     string
	marker   bool
	sentinel bool
}

var pilotManagedShapes = []pilotAuthShape{
	{name: "marker", marker: true},
	{name: "sentinel", sentinel: true},
}

func pilotCodexAuth(id string, expiry time.Time, shape pilotAuthShape) *Auth {
	refresh := "real-refresh-token"
	if shape.sentinel {
		refresh = pilotSentinelRefreshToken
	}
	meta := map[string]any{
		"type":          "codex",
		"access_token":  "stale-access-token",
		"refresh_token": refresh,
		"expired":       expiry.Format(time.RFC3339),
	}
	if shape.marker {
		meta["trayManagedAccount"] = "codex"
	}
	return &Auth{ID: id, Provider: "codex", Metadata: meta}
}

func TestPilotManagedAuthIsNeverScheduledForBackgroundRefresh(t *testing.T) {
	now := time.Date(2026, 11, 6, 17, 0, 0, 0, time.UTC)
	lead := 5 * 24 * time.Hour
	setRefreshLeadFactory(t, "codex", func() *time.Duration { return &lead })
	expiry := now.Add(4 * 24 * time.Hour)

	plain := pilotCodexAuth("plain", expiry, pilotAuthShape{})
	if _, ok := nextRefreshCheckAt(now, plain, 15*time.Minute); !ok {
		t.Fatalf("control: an unmanaged auth inside the refresh lead must be scheduled")
	}

	for _, shape := range pilotManagedShapes {
		managed := pilotCodexAuth("managed-"+shape.name, expiry, shape)
		if _, ok := nextRefreshCheckAt(now, managed, 15*time.Minute); ok {
			t.Fatalf("%s: nextRefreshCheckAt scheduled a pilot-managed auth", shape.name)
		}
	}
}

func TestPilotManagedAuthSurfacesUnauthorizedWithoutRefreshing(t *testing.T) {
	for _, shape := range pilotManagedShapes {
		t.Run(shape.name, func(t *testing.T) {
			model := "gpt-5.5"
			auth := pilotCodexAuth("aa-managed-"+shape.name, time.Now().Add(96*time.Hour), shape)
			executor := &unauthorizedRefreshExecutor{
				id:           "codex",
				tokenInvalid: map[string]struct{}{"stale-access-token": {}},
			}
			m := NewManager(nil, nil, nil)
			m.RegisterExecutor(executor)
			reg := registry.GetGlobalRegistry()
			reg.RegisterClient(auth.ID, "codex", []*registry.ModelInfo{{ID: model}})
			t.Cleanup(func() { reg.UnregisterClient(auth.ID) })
			if _, err := m.Register(context.Background(), auth); err != nil {
				t.Fatalf("register: %v", err)
			}

			_, err := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
			if err == nil || !isUnauthorizedError(err) {
				t.Fatalf("Execute error = %v, want the upstream 401", err)
			}
			if got := executor.RefreshCalls(); got != 0 {
				t.Fatalf("Refresh calls = %d, want 0 for a pilot-managed auth", got)
			}
			if got := executor.ExecuteCalls(); len(got) != 1 {
				t.Fatalf("Execute calls = %v, want exactly one attempt", got)
			}
		})
	}
}
