//go:build windows

package endpoint

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

func listenUnix(path string) (net.Listener, error) {
	listener, err := net.Listen("unix", path)
	if err == nil {
		setUnixUnlinkOnClose(listener)
		return listener, nil
	}

	info, statErr := os.Lstat(path)
	if statErr != nil || info.Mode()&os.ModeSocket == 0 {
		return nil, err
	}
	probe, probeErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if probeErr == nil {
		_ = probe.Close()
		return nil, fmt.Errorf("socket path is already in use: %w", err)
	}
	if !isStaleUnixSocketProbeError(probeErr) {
		return nil, err
	}
	if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale socket path: %w", removeErr)
	}
	listener, err = net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	setUnixUnlinkOnClose(listener)
	return listener, nil
}

func isStaleUnixSocketProbeError(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ENOENT) ||
		errors.Is(err, os.ErrNotExist)
}

func setUnixUnlinkOnClose(listener net.Listener) {
	if unixListener, ok := listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(true)
	}
}
