package cacheutil

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// FileLock provides cross-process file locking using flock(2).
// Use this to protect read-modify-write cycles on shared cache files
// when multiple CloudFox processes may run concurrently.
type FileLock struct {
	file *os.File
}

// AcquireFileLock acquires an exclusive flock on a .lock file adjacent to the
// target path. Creates the lock file if it does not exist. The caller MUST
// call Release() when done (use defer).
func AcquireFileLock(targetPath string) (*FileLock, error) {
	lockPath := targetPath + ".lock"
	dir := filepath.Dir(lockPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create lock directory: %w", err)
	}

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file %s: %w", lockPath, err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to acquire lock on %s: %w", lockPath, err)
	}

	return &FileLock{file: f}, nil
}

// Release releases the file lock and closes the lock file.
func (fl *FileLock) Release() {
	if fl.file != nil {
		syscall.Flock(int(fl.file.Fd()), syscall.LOCK_UN)
		fl.file.Close()
	}
}
