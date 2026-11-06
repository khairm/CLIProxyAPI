package auth

import "sync"

var (
	authReleasedMu    sync.RWMutex
	authReleasedFuncs []func(authID string)
)

// OnAuthReleased registers fn to run after an auth is removed or its proxy URL changes, so
// resources kept per account, such as shared connections, can be released.
func OnAuthReleased(fn func(authID string)) {
	authReleasedMu.Lock()
	defer authReleasedMu.Unlock()
	authReleasedFuncs = append(authReleasedFuncs, fn)
}

func notifyAuthReleased(authID string) {
	authReleasedMu.RLock()
	defer authReleasedMu.RUnlock()
	for _, fn := range authReleasedFuncs {
		fn(authID)
	}
}

func proxyURLChanged(existing, next *Auth) bool {
	return existing != nil && next != nil && existing.ProxyURL != next.ProxyURL
}
