// Package codex provides authentication and token management functionality
// for OpenAI's Codex AI services. It handles OAuth2 token storage, serialization,
// and retrieval for maintaining authenticated sessions with the Codex API.
package codex

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/atomicfile"
	baseauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
)

// CodexTokenStorage stores OAuth2 token information for OpenAI Codex API authentication.
// It maintains compatibility with the existing auth system while adding Codex-specific fields
// for managing access tokens, refresh tokens, and user account information.
type CodexTokenStorage struct {
	// IDToken is the JWT ID token containing user claims and identity information.
	IDToken string `json:"id_token"`
	// AccessToken is the OAuth2 access token used for authenticating API requests.
	AccessToken string `json:"access_token"`
	// RefreshToken is used to obtain new access tokens when the current one expires.
	RefreshToken string `json:"refresh_token"`
	// AccountID is the OpenAI account identifier associated with this token.
	AccountID string `json:"account_id"`
	// LastRefresh is the timestamp of the last token refresh operation.
	LastRefresh string `json:"last_refresh"`
	// Email is the OpenAI account email address associated with this token.
	Email string `json:"email"`
	// Type indicates the authentication provider type, always "codex" for this storage.
	Type string `json:"type"`
	// Expire is the timestamp when the current access token expires.
	Expire string `json:"expired"`

	// Metadata holds arbitrary key-value pairs injected via hooks.
	// It is not exported to JSON directly to allow flattening during serialization.
	Metadata map[string]any `json:"-"`
}

// SetMetadata allows external callers to inject metadata into the storage before saving.
func (ts *CodexTokenStorage) SetMetadata(meta map[string]any) {
	ts.Metadata = meta
}

// CloneTokenStorage returns an independent copy suitable for staged persistence.
func (ts *CodexTokenStorage) CloneTokenStorage() baseauth.TokenStorage {
	if ts == nil {
		return (*CodexTokenStorage)(nil)
	}
	cloned := *ts
	if ts.Metadata != nil {
		cloned.Metadata = make(map[string]any, len(ts.Metadata))
		for key, value := range ts.Metadata {
			cloned.Metadata[key] = value
		}
	}
	return &cloned
}

// SaveTokenToFile serializes the Codex token storage to a JSON file.
// This method creates the necessary directory structure and writes the token
// data in JSON format to the specified file path for persistent storage.
// It merges any injected metadata into the top-level JSON object.
//
// Parameters:
//   - authFilePath: The full path where the token file should be saved
//
// Returns:
//   - error: An error if the operation fails, nil otherwise
func (ts *CodexTokenStorage) SaveTokenToFile(authFilePath string) (err error) {
	misc.LogSavingCredentials(authFilePath)
	ts.Type = "codex"

	// Build the complete payload before touching the existing credential file.
	data, errMerge := misc.MergeMetadata(ts, ts.Metadata)
	if errMerge != nil {
		return fmt.Errorf("failed to merge metadata: %w", errMerge)
	}
	payload, errMarshal := json.Marshal(data)
	if errMarshal != nil {
		return fmt.Errorf("failed to marshal token: %w", errMarshal)
	}
	payload = append(payload, '\n')

	dir := filepath.Dir(authFilePath)
	if errMkdir := os.MkdirAll(dir, 0700); errMkdir != nil {
		return fmt.Errorf("failed to create directory: %w", errMkdir)
	}

	if errWrite := atomicfile.WriteFile(authFilePath, payload, 0o600); errWrite != nil {
		return fmt.Errorf("failed to write token file atomically: %w", errWrite)
	}
	return nil

}
