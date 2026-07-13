//go:build !windows

package atomicfile

import "os"

func replaceFile(sourcePath, destinationPath string) error {
	return os.Rename(sourcePath, destinationPath)
}
