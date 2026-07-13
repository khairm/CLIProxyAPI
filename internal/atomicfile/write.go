package atomicfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile replaces path atomically using a temporary file in the same directory.
func WriteFile(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tempFile, errCreate := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if errCreate != nil {
		return fmt.Errorf("create temporary file: %w", errCreate)
	}
	tempPath := tempFile.Name()
	closed := false
	renamed := false
	defer func() {
		if !closed {
			if errClose := tempFile.Close(); errClose != nil {
				err = errors.Join(err, fmt.Errorf("close temporary file: %w", errClose))
			}
		}
		if !renamed {
			if errRemove := os.Remove(tempPath); errRemove != nil && !os.IsNotExist(errRemove) {
				err = errors.Join(err, fmt.Errorf("remove temporary file: %w", errRemove))
			}
		}
	}()

	if errChmod := tempFile.Chmod(perm); errChmod != nil {
		return fmt.Errorf("set temporary file permissions: %w", errChmod)
	}
	if _, errWrite := tempFile.Write(data); errWrite != nil {
		return fmt.Errorf("write temporary file: %w", errWrite)
	}
	if errSync := tempFile.Sync(); errSync != nil {
		return fmt.Errorf("sync temporary file: %w", errSync)
	}
	if errClose := tempFile.Close(); errClose != nil {
		closed = true
		return fmt.Errorf("close temporary file: %w", errClose)
	}
	closed = true

	if errReplace := replaceFile(tempPath, path); errReplace != nil {
		return fmt.Errorf("replace file: %w", errReplace)
	}
	renamed = true
	return nil
}
