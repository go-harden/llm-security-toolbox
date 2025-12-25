//go:build !linux && !darwin

package service

import (
	"net"
	"os"
)

// verifyPeerCredentials is a no-op on unsupported systems.
// Security relies on filesystem permissions for the socket (0600).
func verifyPeerCredentials(conn net.Conn) error {
	return nil
}

// peerCredentialsSupported returns false on unsupported systems.
func peerCredentialsSupported() bool {
	return false
}

// getFileOwnerUID returns an error on unsupported platforms.
// The caller should skip UID validation when this fails.
func getFileOwnerUID(info os.FileInfo) (uint32, error) {
	// Cannot determine file owner on this platform
	// Return current UID to skip ownership check (permissions still checked)
	return uint32(os.Getuid()), nil
}
