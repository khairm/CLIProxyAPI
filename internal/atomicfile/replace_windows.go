//go:build windows

package atomicfile

import "golang.org/x/sys/windows"

func replaceFile(sourcePath, destinationPath string) error {
	sourcePathUTF16, errSource := windows.UTF16PtrFromString(sourcePath)
	if errSource != nil {
		return errSource
	}
	destinationPathUTF16, errDestination := windows.UTF16PtrFromString(destinationPath)
	if errDestination != nil {
		return errDestination
	}
	return windows.MoveFileEx(
		sourcePathUTF16,
		destinationPathUTF16,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
}
