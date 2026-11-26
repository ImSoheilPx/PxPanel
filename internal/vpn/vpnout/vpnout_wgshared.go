package vpnout

// Shared WireGuard/AWG helpers the two client drivers carry locally. vpn-ui's
// vpnout_wireguard.go / vpnout_awg.go read these from the single `service`
// package (wgc.go / awg.go / core.go); the target keeps the inbound sides in
// their own packages with these unexported, so the client drivers carry the
// identical values here rather than reaching into another package's internals.

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/vpn/pkgmgr"

	"github.com/Jipok/wgctrl-go/wgtypes"
)

// wgDefaultMTU is the WireGuard standard tunnel MTU (vpn-ui wgc.go).
const (
	wgDefaultMTU = 1420

	// wgHandshakeStale is how long after its last handshake a peer is still considered
	// a live device. WireGuard rekeys roughly every 2 minutes under traffic, so a 3
	// minute window avoids flapping a briefly-idle device offline.
	wgHandshakeStale = 180 * time.Second
)

// awgObfs is the resolved (defaults applied) AWG 1.0 obfuscation parameter set.
// Verbatim from vpn-ui awg.go; the AWG outbound driver applies it to its peer
// config exactly as the inbound reconciler does.
type awgObfs struct {
	Jc, Jmin, Jmax, S1, S2 int
	H1, H2, H3, H4         string
}

func (b awgObfs) sig() string {
	return fmt.Sprintf("%d|%d|%d|%d|%d|%s|%s|%s|%s", b.Jc, b.Jmin, b.Jmax, b.S1, b.S2, b.H1, b.H2, b.H3, b.H4)
}

// apply writes the obfuscation params into a wgtypes.Config (only when H1-H4 are present).
func (b awgObfs) apply(cfg *wgtypes.Config) {
	jc, jmin, jmax, s1, s2 := b.Jc, b.Jmin, b.Jmax, b.S1, b.S2
	cfg.Jc, cfg.Jmin, cfg.Jmax = &jc, &jmin, &jmax
	cfg.S1, cfg.S2 = &s1, &s2
	if b.H1 != "" {
		h1, h2, h3, h4 := b.H1, b.H2, b.H3, b.H4
		cfg.H1, cfg.H2, cfg.H3, cfg.H4 = &h1, &h2, &h3, &h4
	}
}

// moduleAvailable reports whether a module can be used on the running kernel —
// already loaded, built into the kernel, or loadable on demand (vpn-ui core.go;
// the target keeps the implementation in pkgmgr).
func moduleAvailable(name string) bool { return pkgmgr.ModuleAvailable(name) }

const (
	// amneziawgModule is the out-of-tree AWG kernel module (vpn-ui awg.go).
	amneziawgModule = "amneziawg"
	// amneziawgLinkKind is the netlink link kind an AWG device reports.
	amneziawgLinkKind = "amneziawg"
)

// awgSupportedDistros names the hosts the DKMS build is attempted on (vpn-ui
// amneziawg_dkms.go).
const awgSupportedDistros = "Debian 12, Debian 13, Ubuntu 24.04 or Ubuntu 26.04"

// allowedIPsKey renders a peer's AllowedIPs as a stable, order-independent
// comparison key (vpn-ui wgc.go).
func allowedIPsKey(ips []net.IPNet) string {
	parts := make([]string, 0, len(ips))
	for _, n := range ips {
		parts = append(parts, n.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// awgKernelModuleSupported reports whether this host can build the AWG module
// at all (vpn-ui amneziawg_dkms.go awgKernelModuleSupported — the availability
// question BEFORE any DKMS attempt). Host/distro reads go through pkgmgr.
func awgKernelModuleSupported() (bool, string) {
	if maj, min, ok := runningKernelVersion(); ok && (maj > 7 || (maj == 7 && min >= 1)) {
		return false, fmt.Sprintf(
			"not supported on Linux %d.%d: the AmneziaWG module does not build on kernel 7.1 or newer "+
				"(the kernel removed ipv6_stub and upstream has not adapted yet). Every other protocol "+
				"is unaffected. For AmneziaWG use %s.", maj, min, awgSupportedDistros)
	}

	id := strings.ToLower(strings.TrimSpace(pkgmgr.OSReleaseField("ID")))
	like := strings.ToLower(pkgmgr.OSReleaseField("ID_LIKE"))
	switch {
	case id == "debian" || id == "ubuntu" ||
		strings.Contains(like, "debian") || strings.Contains(like, "ubuntu"):
		return true, ""
	case isEnterpriseLinux() || id == "fedora" || strings.Contains(like, "fedora"):
		return false, fmt.Sprintf(
			"not supported on %s: the AmneziaWG module fails to build against RHEL-family and Fedora "+
				"kernels (their backported kernels break the module's compatibility layer upstream). "+
				"Every other protocol is unaffected. For AmneziaWG use %s.",
			pkgmgr.DistroPretty(), awgSupportedDistros)
	default:
		return false, fmt.Sprintf(
			"%s is not a tested host for the AmneziaWG module, so setup did not attempt the build. "+
				"Every other protocol is unaffected. For AmneziaWG use %s.",
			pkgmgr.DistroPretty(), awgSupportedDistros)
	}
}

// runningKernelVersion is parseKernelVersion applied to the running kernel.
func runningKernelVersion() (int, int, bool) { return parseKernelVersion(pkgmgr.RunningKernel()) }

// parseKernelVersion pulls the major and minor out of a `uname -r` string. It has to cope
// with every shape the supported matrix produces: "6.8.0-136-generic", "7.1.3-arch2-2",
// "5.14.0-687.26.1.el9_8.x86_64" and Debian's "6.12.95+deb13-cloud-amd64".
func parseKernelVersion(r string) (int, int, bool) {
	if r == "" {
		return 0, 0, false
	}
	// cut at the first character that is not part of the dotted numeric prefix
	end := strings.IndexFunc(r, func(c rune) bool { return c != '.' && (c < '0' || c > '9') })
	if end > 0 {
		r = r[:end]
	}
	parts := strings.Split(r, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return maj, min, true
}

// isEnterpriseLinux reports a RHEL-family host (vpn-ui amneziawg_dkms.go).
func isEnterpriseLinux() bool {
	switch strings.ToLower(pkgmgr.OSReleaseField("ID")) {
	case "almalinux", "rocky", "centos", "rhel":
		return true
	}
	return strings.Contains(strings.ToLower(pkgmgr.OSReleaseField("ID_LIKE")), "rhel")
}
