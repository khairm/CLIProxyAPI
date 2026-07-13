package executor

import "context"

type downstreamWebsocketContextKey struct{}
type codexOAuthRouteContextKey struct{}

// WithDownstreamWebsocket marks the current request as coming from a downstream websocket connection.
func WithDownstreamWebsocket(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, downstreamWebsocketContextKey{}, true)
}

// DownstreamWebsocket reports whether the current request originates from a downstream websocket connection.
func DownstreamWebsocket(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	raw := ctx.Value(downstreamWebsocketContextKey{})
	enabled, ok := raw.(bool)
	return ok && enabled
}

// WithCodexOAuthRoute marks a request for the configured Codex OAuth override.
// The session ID is already validated at the inbound API boundary and may be empty.
func WithCodexOAuthRoute(ctx context.Context, sessionID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, codexOAuthRouteContextKey{}, sessionID)
}

// CodexOAuthRoute returns the validated session ID and whether the override route is selected.
func CodexOAuthRoute(ctx context.Context) (sessionID string, enabled bool) {
	if ctx == nil {
		return "", false
	}
	sessionID, enabled = ctx.Value(codexOAuthRouteContextKey{}).(string)
	return sessionID, enabled
}
