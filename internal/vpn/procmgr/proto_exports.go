package procmgr

// Exported API surface for the per-protocol waves.
//
// procmgr.go keeps the vpn-ui file contents (package-private names, as they
// were inside vpn-ui's one giant `service` package). This file is the package
// boundary: the protocol services (openvpn, ocserv, l2tp, pptp, …) resolve
// daemon binaries, migrate legacy systemd units and enumerate managed child
// processes through these wrappers. Same re-export pattern as range/export.go.

// DaemonBin resolves a daemon binary the way the panel runs it: the bundled
// daemon if a bundle layer is installed, else a distro binary from PATH.
// (vpn-ui web/service daemonBin — openvpn.go/ocserv.go ovpnBinaryPath and
// ocservBinaryPath/occtlBinaryPath both go through it.)
func DaemonBin(name string) string { return daemonBin(name) }

// MigrateFromSystemd stops daemons an older (systemd-unit) layout ran as units
// and disables the units, now that the panel supervises them as children.
// Every protocol's RestartServices calls it first, exactly as in vpn-ui.
func MigrateFromSystemd() { migrateFromSystemd() }

// NamesWithPrefix returns the names of the managed child processes whose name
// carries the given prefix ("mtproto-server-", "openvpn-server-", …). The
// reconcile loops use it to stop processes that no longer correspond to an
// enabled inbound. (mtproto wave addition: RestartServices' stop-not-desired
// half. vpn-ui procMgr.namesWithPrefix.)
func (m *ProcManager) NamesWithPrefix(prefix string) []string {
	return m.namesWithPrefix(prefix)
}
