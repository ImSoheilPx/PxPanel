package vpnout

// Shared ppp-family client helpers. vpn-ui's vpnout_openconnect.go (and the
// pptp/l2tp outbound drivers, which land in this package from their own wave)
// read these off the one `service` package's vpnout_pptp.go; carried here
// verbatim so every ppp-device driver shares the one implementation. They are
// pure: name mangling, fingerprints, log slicing.

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"

	"github.com/vishvananda/netlink"
)

// procMgr is the process manager the ppp-family drivers supervise their clients
// through (vpn-ui's package-level procMgr).
var procMgr = procmgr.GetProcManager()

// migrateFromSystemd re-homes daemons a pre-procmgr install left under systemd
// (vpn-ui procmgr.go migrateFromSystemd; the target keeps the implementation in
// the procmgr package).
func migrateFromSystemd() { procmgr.MigrateFromSystemd() }

const (
	// pppOutIfMax bounds the generated ppp device name (vpn-ui vpnout_pptp.go):
	// the kernel refuses anything past IFNAMSIZ-1 and pppd then silently keeps
	// pppN.
	pppOutIfMax = 15

	// pppOutPoll is the poll interval while a ppp device comes up (vpn-ui
	// vpnout_pptp.go).
	pppOutPoll = 500 * time.Millisecond

	// pppOutFingerprintMark introduces the settings fingerprint in a generated pppd
	// options file. A `#` comment, so pppd's option parser skips it.
	// (vpn-ui read "# vpn-ui-settings = "; brand-adapted like the rest of the port.)
	pppOutFingerprintMark = "# pxpanel-settings = "
)

// pppOutRunDirs lists where a pppd might keep its pid files. The bundled pppd (2.5.x)
// uses /run/ppp, which is where these were verified; distro builds of 2.4.x use
// /var/run or /var/run/pppd. On most hosts /var/run is a symlink to /run, so the
// duplicates cost one failed stat each.
var pppOutRunDirs = []string{"/run/ppp", "/var/run/ppp", "/run/pppd", "/var/run/pppd", "/run", "/var/run"}

// pppOutLinkPid reads <rundir>/ppp-<linkname>.pid: pppd's pid, and the interface name
// once that pppd has created its unit.
func pppOutLinkPid(linkname string) (int, string) {
	for _, dir := range pppOutRunDirs {
		data, err := os.ReadFile(dir + "/ppp-" + linkname + ".pid")
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		pid, err := strconv.Atoi(strings.TrimSpace(lines[0]))
		if err != nil {
			continue
		}
		iface := ""
		if len(lines) > 1 {
			iface = strings.TrimSpace(lines[1])
		}
		return pid, iface
	}
	return 0, ""
}

// pppOutDevPid reads <rundir>/<iface>.pid: the pid of the pppd owning that device.
func pppOutDevPid(iface string) int {
	for _, dir := range pppOutRunDirs {
		data, err := os.ReadFile(dir + "/" + iface + ".pid")
		if err != nil {
			continue
		}
		if p, err := strconv.Atoi(strings.TrimSpace(strings.Split(string(data), "\n")[0])); err == nil {
			return p
		}
	}
	return 0
}

// pppOutIfaceOwnedBy finds the device whose pppd has the given pid.
//
// Every device on the box is a candidate and the answer comes only from pid files:
// nothing is inferred from a name. Filtering by name first was the obvious shortcut and
// is wrong twice over. It assumes the rename succeeded, which is the one case this
// function exists to cover (pppd logs "Couldn't rename interface" and carries on with
// pppN), and it would claim a device on the strength of its name, which is exactly what
// a leftover from a previous panel has. A device whose <rundir>/<dev>.pid holds a pid we
// have already proved to be our own pppd is ours whatever it happens to be called, and
// a device with no such file cannot be. The cost is one failed stat per unrelated
// interface, on a fallback path.
func pppOutIfaceOwnedBy(pid int) string {
	links, err := netlink.LinkList()
	if err != nil {
		return ""
	}
	for _, l := range links {
		if dev := l.Attrs().Name; pppOutDevPid(dev) == pid {
			return dev
		}
	}
	return ""
}

// pppOutProcessAlive reports whether the pid exists. EPERM counts as alive: the process
// is there and owned by somebody else, which is still "not free to be reused".
func pppOutProcessAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// pppOutIfaceReady reports whether the device exists and has finished IPCP.
func pppOutIfaceReady(iface string) bool { return pppOutIfaceAddr(iface) != "" }

// pppOutIfaceAddr returns the device's first IPv4 address, or "".
func pppOutIfaceAddr(iface string) string {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return ""
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if a.IP != nil {
			return a.IP.String()
		}
	}
	return ""
}

// pppOutResolveIface answers which netdev THIS tunnel's pppd is currently providing,
// preferring the live pid files over the name we asked for (vpn-ui vpnout_pptp.go).
func pppOutResolveIface(linkname, want, proc string) string {
	if pid, recorded := pppOutLinkPid(linkname); pid > 0 && pppOutProcessAlive(pid) {
		if recorded != "" && pppOutDevPid(recorded) == pid && pppOutIfaceReady(recorded) {
			return recorded
		}
		if owned := pppOutIfaceOwnedBy(pid); owned != "" && pppOutIfaceReady(owned) {
			return owned
		}
	}
	// No usable pid file, which is what a pppd with a runtime directory we do not know
	// about looks like. Fall back to the device we named ourselves, and only while our
	// own supervised pppd is alive: nothing else on this box creates that name, and
	// pppd deletes its device when it exits, so a device with our name under a running
	// instance of ours is ours.
	if want != "" && pppOutIfaceReady(want) && procMgr.IsRunning(proc) {
		return want
	}
	return ""
}

// pppOutResolveV4 turns a configured server into a single IPv4 address. `what` names
// the field in the error, because "cannot resolve" on its own does not tell an
// operator which of the addresses they typed is the broken one.
func pppOutResolveV4(server, what string) (net.IP, error) {
	if ip := net.ParseIP(server); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return nil, fmt.Errorf("the %s address %q is IPv6, and this client is IPv4 only", what, server)
	}
	ips, err := net.LookupIP(server)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve the %s %q: %w", what, server, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("the %s %q has no IPv4 address", what, server)
}

// pppOutSafeName reduces a tag to something usable as a filename, a procmgr key and
// part of a device name. Tags are operator input and only spaces are refused upstream.
func pppOutSafeName(tag string) string {
	var b strings.Builder
	for _, r := range tag {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unnamed"
	}
	return b.String()
}

func pppOutHash(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

// pppOutQuote renders a value for pppd's options parser, which understands
// double-quoted strings with backslash escapes.
func pppOutQuote(v string) string {
	esc := strings.ReplaceAll(v, `\`, `\\`)
	esc = strings.ReplaceAll(esc, `"`, `\"`)
	return `"` + esc + `"`
}

// pppOutShellQuote renders a value for /bin/sh, which is what parses pppd's `pty`
// argument and openconnect's `--script`.
func pppOutShellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// pppOutFingerprintOf hashes the operator's settings so a later Up can tell "already
// running" from "already running with something other than what was just typed".
func pppOutFingerprintOf(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%08x", pppOutHash(string(b)))
}

// pppOutStoredFingerprint reads back the fingerprint of a generated file, or "".
func pppOutStoredFingerprint(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(ln, pppOutFingerprintMark) {
			return strings.TrimSpace(strings.TrimPrefix(ln, pppOutFingerprintMark))
		}
	}
	return ""
}

// pppOutBytes renders a device counter.
func pppOutBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// pppOutLastLines returns the final n lines of a log.
func pppOutLastLines(log string, n int) string {
	if log == "" {
		return ""
	}
	lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func pppOutLogLines(log string) int {
	if log == "" {
		return 0
	}
	return len(strings.Split(strings.TrimRight(log, "\n"), "\n"))
}

// pppOutLogSince returns the log from the given line onwards, i.e. the current
// attempt's output only.
//
// The offset drifts if the ring buffer discarded lines in between (it holds 800), but
// it drifts in the safe direction: a discard makes this skip PAST some new lines, so at
// worst a tell is missed and the wait ends on its timeout, which still shows the tail.
// The opposite mistake, reading an older attempt's failure as this one's, is the one
// that matters and cannot happen.
func pppOutLogSince(log string, mark int) string {
	if log == "" {
		return ""
	}
	lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
	if mark >= len(lines) {
		return ""
	}
	if mark > 0 {
		lines = lines[mark:]
	}
	return strings.Join(lines, "\n")
}
