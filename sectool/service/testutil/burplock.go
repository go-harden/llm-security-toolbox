package testutil

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// BurpLock provides a file-based lock to serialize access to Burp MCP
// across test packages. This prevents concurrent MCP connections which
// can cause SSE response mix-ups.
type BurpLock struct {
	file *os.File
}

// AcquireBurpLock acquires an exclusive lock on Burp MCP.
// The lock is automatically released when the test completes.
// If the lock cannot be acquired within 60 seconds, the test fails.
func AcquireBurpLock(t *testing.T) *BurpLock {
	t.Helper()

	lockPath := filepath.Join(os.TempDir(), "sectool-burp-test.lock")

	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("failed to open lock file: %v", err)
	}

	// Try to acquire lock with timeout
	deadline := time.Now().Add(60 * time.Second)
	for {
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}

		if time.Now().After(deadline) {
			_ = file.Close()
			t.Fatalf("timeout waiting for Burp MCP lock")
		}

		time.Sleep(100 * time.Millisecond)
	}

	lock := &BurpLock{file: file}
	t.Cleanup(func() {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	})

	return lock
}
