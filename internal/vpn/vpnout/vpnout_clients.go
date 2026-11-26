package vpnout

// The bundled VPN CLIENT seam.
//
// vpn-ui's vpnout drivers read the client-side artifacts (openconnect + its
// vpnc-script, sstpc + its pppd plugin, the pppd bundle, openvpn) straight out
// of the `backend` package's //go:embed all:bin bundle. The target keeps that
// layer behind procmgr's BundleProvider, whose surface today covers only the
// SERVER-side daemons and the pppd/ipsec/strongswan pieces — it has no
// openconnect / sstpc / vpnc-script accessors yet, and this wave must not edit
// procmgr. So the reads go through the function vars below: verbatim driver
// logic on top, inert-but-honest defaults underneath.
//
// Default behaviour with no bundle provider wired (procmgr's noop): flat
// artifacts resolve through DaemonPath ("" until the bundle wave lands),
// sstpc/tree artifacts answer unavailable with a reason that names what is
// missing, and distro fallbacks that the drivers themselves implement (openvpn
// prefers a host binary) keep working. TODO(bundle wave): extend the
// BundleProvider with the client accessors (ClientPath/EnsureClients/
// ClientAvailable/ExtractOnly + the sstpc and vpnc-script roots) and re-point
// these vars at it, exactly as ipsec/bundle.go did for libreswan.

import (
	"fmt"
	"os"
	"path/filepath"

	vpnlog "github.com/ImSoheilPx/pxpanel/internal/vpn/log"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/pkgmgr"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"
)

// Client artifact names (vpn-ui backend/clients.go + pppd.go + sstpc.go).
const (
	// clientNameOpenconnect is the bundled openconnect binary.
	clientNameOpenconnect = "openconnect"
	// clientNameSstpc is the bundled sstpc launcher (a relocatable TREE, not a
	// flat binary: it needs OpenSSL's legacy provider via dlopen for MD4).
	clientNameSstpc = "sstpc"
	// clientNameVpncScript is openconnect's routing/DNS/MTU hook, a POSIX
	// script that drives iproute2 rather than an ELF.
	clientNameVpncScript = "vpnc-script"
	// clientNameSstpPppdPlugin passes pppd's MPPE keys to sstpc so it can
	// compute the SSTP crypto binding. pppd resolves a `plugin` argument
	// containing a slash by dlopen'ing it directly, so it is loaded by
	// absolute path.
	clientNameSstpPppdPlugin = "sstp-pppd-plugin.so"
)

// clientBundleCompanions maps a client binary to the artifacts it is useless
// without (vpn-ui backend/clients.go clientCompanions). Both entries are the
// same shape of bug: the binary is there, the run gets far enough to look like
// it is working, and then it fails somewhere that names nothing. So
// availability is answered for the whole set, never for the ELF alone.
var clientBundleCompanions = map[string][]string{
	clientNameOpenconnect: {clientNameVpncScript},
	clientNameSstpc:       {clientNameSstpPppdPlugin},
}

// clientBundleDaemonPath resolves a flat bundled binary by name (vpn-ui
// backend.DaemonPath), "" when absent.
var clientBundleDaemonPath = func(name string) string {
	return procmgr.Bundles().DaemonPath(name)
}

// clientBundleExtractOnly writes the named flat artifacts out of the embedded
// bundle (vpn-ui backend.ExtractOnly). Default: no client bundle layer is
// linked into this build, so nothing can be extracted — the error names it,
// and every caller already treats extraction failure as "keep looking for a
// host binary / refuse with a reason".
var clientBundleExtractOnly = func(names []string) ([]string, error) {
	return nil, fmt.Errorf("no client bundle is linked into this build (%s), so %v cannot be extracted",
		"the BundleProvider has no client accessors yet", names)
}

// clientBundleAnyAvailable reports whether ANY daemon bundle exists for this
// architecture (vpn-ui backend.Available). Default false: the case it actually
// separates is "no bundle for this arch", and the noop provider is exactly
// that.
var clientBundleAnyAvailable = func() bool { return false }

// clientBundlePath returns the extracted path of a bundled client artifact, or
// "" when it is absent (vpn-ui backend.ClientPath). sstpc is the one that is
// not a flat artifact: it unpacks as a tree, so its launcher is resolved from
// the bundle root instead — which the BundleProvider does not expose yet, and
// ClientPath therefore answers "" for until the bundle wave lands.
var clientBundlePath = func(name string) string {
	if name == clientNameSstpc {
		return "" // TODO(bundle wave): resolve inside the sstpc relocatable tree
	}
	return clientBundleDaemonPath(name)
}

// clientBundleAvailable answers whether an outbound of this kind can run on
// this host, and when it cannot, one line an operator can act on (vpn-ui
// backend.ClientAvailable). Asked at SAVE time about a config that may never
// be raised: it only looks, it never extracts.
//
// The companions are checked too, and the reason names whichever artifact is
// actually missing, so "openconnect works but its vpnc-script does not" reads
// as itself rather than as a generic openconnect failure.
var clientBundleAvailable = func(name string) (bool, string) {
	for _, n := range append([]string{name}, clientBundleCompanions[name]...) {
		if ok, reason := clientArtifactAvailable(n); !ok {
			return false, reason
		}
	}
	return true, ""
}

// clientArtifactAvailable is clientBundleAvailable for a single file (vpn-ui
// backend/artifactAvailable).
func clientArtifactAvailable(name string) (bool, string) {
	if name == clientNameSstpc {
		// The tree, not a flat artifact. Not resolvable through the
		// BundleProvider yet: honest refusal rather than a wrong yes.
		return false, "the sstpc client bundle was not included in this build, so SSTP dial-out cannot run here"
	}
	p := filepath.Join(clientBundleBinDir(), name)
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		// A present but non-executable artifact is its own failure, not a missing
		// one: it means an extraction was interrupted or something re-wrote the
		// file, and saying "not included in this build" there would send the
		// operator looking in the wrong place entirely.
		if st.Mode().Perm()&0o111 == 0 {
			return false, clientBundleLabel(name) + " at " + p + " is not executable, so the bundle extraction did not finish"
		}
		return true, ""
	}
	// Not on disk: absent until the bundle wave makes DaemonPath answer for it.
	return false, clientBundleLabel(name) + " was not included in this build: the client bundle was built without it, or not for this architecture"
}

// clientBundleBinDir is where flat client artifacts live once extracted
// (vpn-ui backend.BinDir). The BundleProvider does not expose a client bin dir
// yet, so availability probing uses the daemon path's own directory.
func clientBundleBinDir() string {
	if p := clientBundleDaemonPath("openvpn"); p != "" {
		return filepath.Dir(p)
	}
	return "/usr/local/bin"
}

// clientBundleLabel names an artifact the way an operator would recognise it
// (vpn-ui backend/clientLabel). The two companions are named through the
// client they serve, because on their own the file names mean nothing to
// whoever is reading the error.
func clientBundleLabel(name string) string {
	switch name {
	case clientNameVpncScript:
		return "openconnect's vpnc-script helper"
	case clientNameSstpPppdPlugin:
		return "sstpc's " + clientNameSstpPppdPlugin + " pppd plugin"
	default:
		return "the " + name + " client"
	}
}

// clientBundleEnsure lays the client artifacts down if they are not already
// there, and is the call an outbound driver makes before raising a tunnel
// (vpn-ui backend.EnsureClients). Safe to call on every raise.
//
// Default: with no bundle layer there is nothing to lay down, so this checks
// what the drivers are about to exec and fails with the artifact's name rather
// than letting a raise die somewhere that names nothing.
var clientBundleEnsure = func() error {
	for _, n := range []string{clientNameOpenconnect, clientNameVpncScript, clientNameSstpPppdPlugin} {
		if clientBundlePath(n) == "" {
			vpnlog.Warning("vpn outbound: client bundle artifact", n, "is not available on this host")
		}
	}
	return nil
}

// clientBundleVpncScriptPath is the extracted vpnc-script, to be passed to
// openconnect as --script (vpn-ui backend.VpncScriptPath).
var clientBundleVpncScriptPath = func() string { return clientBundlePath(clientNameVpncScript) }

// clientBundleSstpPluginPath is the extracted sstp-pppd-plugin.so, to be passed
// to pppd as `plugin <path>`. Empty when the bundle is absent, in which case
// SSTP dial-out must not be attempted: the handshake would fail at the crypto
// binding rather than at anything that names the missing plugin.
var clientBundleSstpPluginPath = func() string { return clientBundlePath(clientNameSstpPppdPlugin) }

// clientBundleHasPppd reports whether a relocatable pppd bundle is embedded
// (vpn-ui backend.HasPppdBundle). The BundleProvider's UsingBundledPppd covers
// the "in play" half of the question and answers false on the no-bundle
// default, which is the same answer for a build with no bundle at all.
var clientBundleHasPppd = func() bool { return procmgr.Bundles().UsingBundledPppd() }

// clientBundleExtractPppd unpacks the embedded pppd tree (vpn-ui
// backend.ExtractPppdBundle). Default: no bundle layer, nothing to unpack.
var clientBundleExtractPppd = func() error {
	return fmt.Errorf("no pppd bundle is linked into this build, so the bundled pppd cannot be extracted")
}

// clientBundleUsingPppd reports whether the bundled pppd is in play rather than
// the host's (vpn-ui backend.UsingBundledPppd). Present for the seam's
// completeness; the SSTP driver deliberately does not consult it (see its
// header comment: the bundled pppd is invoked by absolute path because the
// OpenSSL legacy provider it needs is a HOST-DEFAULT-ABSENT feature).
var clientBundleUsingPppd = func() bool { return procmgr.Bundles().UsingBundledPppd() }

// clientBundlePppdPath is the absolute path the SSTP driver execs for pppd
// (vpn-ui backend.PppdBundled, the fixed PppdBundleRoot + "/sbin/pppd"). The
// bundle wave owns the concrete root; the BundleProvider's PppdBundledPath is
// the same fact through the seam.
func clientBundlePppdPath() string {
	if p := procmgr.Bundles().PppdBundledPath(); p != "" {
		return p
	}
	return "/usr/libexec/pxpanel/pppd/sbin/pppd"
}

// commandExists reports whether name resolves on PATH (vpn-ui core.go).
func commandExists(name string) bool { return pkgmgr.CommandExists(name) }

// daemonBin resolves a host-installed daemon binary (vpn-ui procmgr.go daemonBin).
func daemonBin(name string) string { return procmgr.DaemonBin(name) }
