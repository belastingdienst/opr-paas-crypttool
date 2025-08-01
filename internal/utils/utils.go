/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package utils

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// PathToFileList returns a list of absolute paths to regular files within the given directories.
//
// It walks each directory, resolves symlinks and gets the absolute path for all files,
// then returns a list of unique file paths.
func PathToFileList(paths []string) ([]string, error) {
	files := make(map[string]bool)
	for _, path := range paths {
		//revive:disable-next-line
		err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return fmt.Errorf("error while walking the path: %w", err)
			} else if resolvedPath, err := filepath.EvalSymlinks(path); err != nil {
				return fmt.Errorf("failed to resolve symlink %s: %w", path, err)
			} else if absPath, err := filepath.Abs(resolvedPath); err != nil {
				return fmt.Errorf("failed to get absolute path for %s: %w", resolvedPath, err)
			} else if absMode, err := os.Stat(absPath); err != nil {
				return fmt.Errorf("failed to get filemode for %s: %w", absPath, err)
			} else if absMode.Mode().IsRegular() {
				files[absPath] = true
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	var fileList []string
	for key := range files {
		fileList = append(fileList, key)
	}
	return fileList, nil
}

// HashData hashes the given data using SHA-512.
func HashData(original []byte) string {
	sum := sha512.Sum512(original)
	return hex.EncodeToString(sum[:])
}
