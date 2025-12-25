//go:build darwin

package service

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// verifyPeerCredentials checks that the connecting peer has the same UID as the server.
// Uses LOCAL_PEERCRED on macOS to get peer credentials.
func verifyPeerCredentials(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("not a unix connection")
	}

	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get syscall conn: %w", err)
	}

	var cred *unix.Xucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
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

// peerCredentialsSupported returns true on macOS where LOCAL_PEERCRED is available.
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
