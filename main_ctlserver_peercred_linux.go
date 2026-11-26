//go:build linux

package main

import (
	"net"
	"syscall"
)

// controlPeerIsRoot reports whether the connected peer runs as root, via
// SO_PEERCRED: the kernel records the peer's credentials at connect() time, so
// the answer cannot be raced or spoofed after the fact (vpn-ui
// web/service/control.go controlPeerIsRoot).
func controlPeerIsRoot(conn net.Conn) bool {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credErr != nil || cred == nil {
		return false
	}
	return cred.Uid == 0
}
