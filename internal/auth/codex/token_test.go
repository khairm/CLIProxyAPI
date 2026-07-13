package codex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexTokenStorageSaveTokenToFileReplacesAtomically(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "codex.json")
	if errWrite := os.WriteFile(path, []byte(`{"old":true}`), 0o600); errWrite != nil {
		t.Fatalf("write existing auth file: %v", errWrite)
	}

	storage := &CodexTokenStorage{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		Metadata: map[string]any{
			"custom": "value",
		},
	}
	if errSave := storage.SaveTokenToFile(path); errSave != nil {
		t.Fatalf("SaveTokenToFile() error = %v", errSave)
	}

	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read saved auth file: %v", errRead)
	}
	var saved map[string]any
	if errUnmarshal := json.Unmarshal(raw, &saved); errUnmarshal != nil {
		t.Fatalf("unmarshal saved auth file: %v", errUnmarshal)
	}
	if got := saved["type"]; got != "codex" {
		t.Fatalf("type = %v, want codex", got)
	}
	if got := saved["access_token"]; got != "access-token" {
		t.Fatalf("access_token = %v, want access-token", got)
	}
	if got := saved["custom"]; got != "value" {
		t.Fatalf("custom = %v, want value", got)
	}
	if _, exists := saved["old"]; exists {
		t.Fatal("old auth file contents survived replacement")
	}
	assertNoCodexTokenTempFiles(t, dir)
}

func TestCodexTokenStorageSaveTokenToFilePreservesExistingFileOnMarshalError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "codex.json")
	want := []byte(`{"access_token":"still-valid"}`)
	if errWrite := os.WriteFile(path, want, 0o600); errWrite != nil {
		t.Fatalf("write existing auth file: %v", errWrite)
	}

	storage := &CodexTokenStorage{
		AccessToken: "replacement",
		Metadata: map[string]any{
			"invalid": func() {},
		},
	}
	if errSave := storage.SaveTokenToFile(path); errSave == nil {
		t.Fatal("SaveTokenToFile() error = nil, want marshal error")
	}

	got, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read existing auth file: %v", errRead)
	}
	if string(got) != string(want) {
		t.Fatalf("existing auth file = %q, want unchanged %q", got, want)
	}
	assertNoCodexTokenTempFiles(t, dir)
}

func TestCodexTokenStorageSaveTokenToFileSurfacesRenameErrorAndRemovesTempFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "codex.json")
	if errMkdir := os.Mkdir(path, 0o700); errMkdir != nil {
		t.Fatalf("create conflicting destination directory: %v", errMkdir)
	}

	errSave := (&CodexTokenStorage{AccessToken: "access-token"}).SaveTokenToFile(path)
	if errSave == nil {
		t.Fatal("SaveTokenToFile() error = nil, want rename error")
	}
	if !strings.Contains(errSave.Error(), "failed to write token file atomically") || !strings.Contains(errSave.Error(), "replace file") {
		t.Fatalf("SaveTokenToFile() error = %v, want replace failure", errSave)
	}
	assertNoCodexTokenTempFiles(t, dir)
}

func assertNoCodexTokenTempFiles(t *testing.T, dir string) {
	t.Helper()
	matches, errGlob := filepath.Glob(filepath.Join(dir, ".codex.json.tmp-*"))
	if errGlob != nil {
		t.Fatalf("glob temporary auth files: %v", errGlob)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary auth files remain: %v", matches)
	}
}
