//go:build linux

package service

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

// verifyPeerCredentials checks that the connecting peer has the same UID as the server.
// Returns nil if credentials match, error otherwise.
func verifyPeerCredentials(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("not a unix connection")
	}

	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get syscall conn: %w", err)
	}

	var cred *syscall.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return fmt.Errorf("failed to control socket: %w", err)
	}
	if credErr != nil {
		return fmt.Errorf("failed to get peer credentials: %w", credErr)
	}

	serverUID := uint32(os.Getuid())
	if cred.Uid != serverUID {
		return fmt.Errorf("peer UID %d does not match server UID %d", cred.Uid, serverUID)
	}

	return nil
}

// peerCredentialsSupported returns true on Linux where SO_PEERCRED is available.
func peerCredentialsSupported() bool {
	return true
}

// getFileOwnerUID returns the UID of the file owner.
func getFileOwnerUID(info os.FileInfo) (uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("failed to get underlying stat")
	}
	return stat.Uid, nil
}
