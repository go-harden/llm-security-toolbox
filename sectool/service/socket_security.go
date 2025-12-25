package service

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
)

// secureListener wraps a net.Listener and verifies peer credentials on Accept.
type secureListener struct {
	net.Listener
}

// wrapListenerWithCredentialCheck wraps a listener to verify peer credentials.
func wrapListenerWithCredentialCheck(l net.Listener) net.Listener {
	return &secureListener{Listener: l}
}

// Accept waits for and returns the next connection to the listener.
// It verifies peer credentials before returning the connection.
func (sl *secureListener) Accept() (net.Conn, error) {
	for {
		conn, err := sl.Listener.Accept()
		if err != nil {
			return nil, err
		}

		if err := verifyPeerCredentials(conn); err != nil {
			log.Printf("rejected connection: %v", err)
			_ = conn.Close()
			continue
		}

		return conn, nil
	}
}

// ValidateSocketPathSecurity verifies the socket's parent directory is secure.
// Checks that the directory is owned by the current user and not group/world-writable.
func ValidateSocketPathSecurity(socketPath string) error {
	dir := filepath.Dir(socketPath)

	// Use Lstat to detect symlinks (don't follow them)
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("failed to stat socket directory %s: %w", dir, err)
	}

	// Reject symlinks to prevent directory traversal attacks
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("socket directory %s is a symlink", dir)
	}

	if !info.IsDir() {
		return fmt.Errorf("socket parent path %s is not a directory", dir)
	}

	// Check ownership (platform-specific via getFileOwnerUID)
	uid, err := getFileOwnerUID(info)
	if err != nil {
		return fmt.Errorf("failed to get directory owner: %w", err)
	}

	currentUID := uint32(os.Getuid())
	if uid != currentUID {
		return fmt.Errorf("socket directory %s is owned by UID %d, expected %d", dir, uid, currentUID)
	}

	// Check that directory is not group or world-writable
	mode := info.Mode().Perm()
	if mode&0022 != 0 {
		return fmt.Errorf("socket directory %s has insecure permissions (mode %04o)", dir, mode)
	}

	return nil
}
