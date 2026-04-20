package cacheutil

import (
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// AtomicWriteGob writes data to a file atomically using a temp file and rename.
// This prevents corruption if the process is interrupted during write.
func AtomicWriteGob(filename string, data interface{}) error {
	dir := filepath.Dir(filename)
	tempFile, err := os.CreateTemp(dir, ".tmp-*.gob")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tempName := tempFile.Name()

	success := false
	defer func() {
		if !success {
			tempFile.Close()
			os.Remove(tempName)
		}
	}()

	encoder := gob.NewEncoder(tempFile)
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode data: %w", err)
	}

	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tempName, filename); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	success = true
	return nil
}

// AtomicWriteFile writes data to a file atomically.
func AtomicWriteFile(filename string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(filename)
	tempFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tempName := tempFile.Name()

	success := false
	defer func() {
		if !success {
			tempFile.Close()
			os.Remove(tempName)
		}
	}()

	if _, err := io.WriteString(tempFile, string(data)); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	if err := tempFile.Chmod(perm); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close: %w", err)
	}

	if err := os.Rename(tempName, filename); err != nil {
		return fmt.Errorf("failed to rename: %w", err)
	}

	success = true
	return nil
}

// SanitizeForPath removes/replaces characters that are problematic in file paths.
func SanitizeForPath(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}
