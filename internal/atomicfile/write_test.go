package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileReplacesExistingAndCleansTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	if errWrite := os.WriteFile(path, []byte("old"), 0o600); errWrite != nil {
		t.Fatalf("write existing file: %v", errWrite)
	}
	if errWrite := WriteFile(path, []byte("new"), 0o600); errWrite != nil {
		t.Fatalf("WriteFile() error = %v", errWrite)
	}
	got, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read replacement: %v", errRead)
	}
	if string(got) != "new" {
		t.Fatalf("replacement = %q, want new", got)
	}
	assertNoTemporaryFiles(t, dir)
}

func TestWriteFileSurfacesReplaceFailureAndCleansTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	if errMkdir := os.Mkdir(path, 0o700); errMkdir != nil {
		t.Fatalf("create destination directory: %v", errMkdir)
	}
	if errWrite := WriteFile(path, []byte("new"), 0o600); errWrite == nil {
		t.Fatal("WriteFile() error = nil, want replacement failure")
	}
	assertNoTemporaryFiles(t, dir)
}

func assertNoTemporaryFiles(t *testing.T, dir string) {
	t.Helper()
	matches, errGlob := filepath.Glob(filepath.Join(dir, ".auth.json.tmp-*"))
	if errGlob != nil {
		t.Fatalf("glob temporary files: %v", errGlob)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain: %v", matches)
	}
}
