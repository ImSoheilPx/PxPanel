//go:build !linux

package main

import (
	"net"
	"os"
)

// controlPeerIsRoot is never meaningfully consulted outside Linux — the panel
// and its control socket are Linux-only — so the process's own euid is the
// only available answer, and os.Geteuid is a harmless stub where there is none.
func controlPeerIsRoot(conn net.Conn) bool {
	_ = conn
	return os.Geteuid() == 0
}
