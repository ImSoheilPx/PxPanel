// Package ipsec is the shared IPsec layer the tunnel protocols drive: the ONE
// bundled strongSwan charon lifecycle (serving L2TP/IPsec IKEv1 transport today,
// IKEv2 and GRE-IPsec from their own waves) and the bundled libreswan (pluto)
// path that replaces the distro ipsec.service where its USE_DH2 build is
// embedded.
//
// Provenance: ported from vpn-ui web/service/charon.go + ipsec_bundle.go
// (Sir-MmD/vpn-ui, a 3x-ui v2.9.3 fork), verbatim where possible, with the
// following mechanical adaptations:
//
//   - vpn-ui's backend.* bundle reads go through procmgr.Bundles() (the
//     BundleProvider seam; the bundle/build wave implements it — no bundles
//     linked means the distro ipsec.service path everywhere, byte-for-byte the
//     vpn-ui non-bundle behaviour).
//   - ownPrepareHostFile → manifest.PrepareHostFile; applyCoreConfigOverride →
//     configedit.ApplyOverride; SettingService.GetRadiusSecret → vpn.RadiusSecret.
//   - The protocols charon also serves but whose waves have not landed
//     (ikev2/GRE inbounds beyond the plain DB counts, client-side vpnout
//     tunnels) register their "charon needed" clauses through
//     RegisterCharonNeeder instead of this package importing them.
//   - vpn-ui's fixed ikev2 config root /etc/vpn-ui-ikev2 is /etc/pxpanel-ikev2.
//
// TODO(ikev2 wave): port Ikev2Service against this package (constants below are
// its proc key + config root; charonDNS already reads ikev2 inbounds), move its
// swanctl cert dirs' ownership here if cleaner.
// TODO(gre wave): register a charon needer wrapping the GRE-IPsec settings
// check (vpn-ui greipsec.go greInboundHasIpsec).
// TODO(vpnout wave): register the outbound needer (vpn-ui charon.go
// vpnOutboundNeedsCharon — L2TP outbound with a PSK / IKEv2 outbound / GRE
// outbound with ipsecEnable).
// TODO(bundle wave): implement the BundleProvider IPsec/strongSwan methods over
// the extracted backend embeds (vpn-ui backend/libreswan.go +
// backend/strongswan.go); with the default no-bundle provider every helper here
// falls back to the host ipsec.service/charon exactly as vpn-ui does.
package ipsec

import "github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"

// Path + identity constants the two IPsec daemons are addressed by (vpn-ui
// ipsec_bundle.go consts + ikev2.go's swanctl block).
const (
	// ipsecConnName is the panel-wide connection the libreswan generator writes
	// (conn l2tp-psk), and the prefix of the per-inbound ones (conn
	// l2tp-psk-<id>).
	ipsecConnName = "l2tp-psk"
	// plutoCtl is the bundled pluto's control socket; DEFAULT_RUNDIR=/run/pluto
	// is compiled into pluto, and addconn/whack talk to this socket.
	plutoCtl = "/run/pluto/pluto.ctl"
	// ipsecProcName is the procMgr key for the pluto child. It matches the
	// "ipsec" core name so the ipsec card's Stop/Logs and the status probe line
	// up. (pkgmgr.ipsecProcName is the same string — pkgmgr keeps its own for
	// the seam's diagnostics.)
	ipsecProcName = "ipsec"

	// ikev2ProcName is the single shared charon process key in the process
	// manager. ikev2 and l2tp cooperate through it: whichever runs syncCharon
	// last leaves the one charon in the right state.
	ikev2ProcName = "ikev2"
	// ikev2ConfigRoot holds the generated strongswan.conf.
	ikev2ConfigRoot = "/etc/pxpanel-ikev2"
	// swanctlDir is charon's compiled-in swanctl config dir (Alpine layout). We
	// write per-inbound connection files under conf.d/ and the certs under the
	// standard subdirs.
	swanctlDir     = "/etc/swanctl"
	swanctlConfDir = swanctlDir + "/conf.d"
	swanctlX509    = swanctlDir + "/x509"
	swanctlX509CA  = swanctlDir + "/x509ca"
	swanctlPrivate = swanctlDir + "/private"
	// viciSocket is charon's control socket swanctl connects to.
	viciSocket = "/var/run/charon.vici"
)

// Bundled libreswan tree paths are derived from the BundleProvider's root
// (vpn-ui backend/libreswan.go: LibreswanBundleRoot + "/sbin/ipsec|pluto",
// NSS dir "/etc/ipsec.d") — the bundle wave owns the concrete root; "" (no
// bundle provider) means the bundled path is not in play at all.

// SwanctlConfDir is charon's connection drop-in dir (/etc/swanctl/conf.d) —
// where each protocol writes its conf.d file (l2tp.conf today; ikev2-<id>.conf /
// gre-*.conf from their waves). pkgmgr's IpsecHooks expose the same value so its
// StopIpsecService can remove the l2tp conn it does not own.
func SwanctlConfDir() string { return swanctlConfDir }

// HasStrongswanBundle reports whether the strongSwan relocatable tree ships with
// this build (vpn-ui backend.HasStrongswanBundle). When false, L2TP/IPsec falls
// back to host libreswan/pluto.
func HasStrongswanBundle() bool {
	return procmgr.Bundles().HasStrongswanBundle()
}

// charonBin / swanctlBin resolve the bundled launchers (or a host binary from
// PATH). (vpn-ui charon.go charonBin/swanctlBin via backend.StrongswanBinPath.)
func charonBin() string {
	if p := procmgr.Bundles().StrongswanBinPath("charon"); p != "" {
		return p
	}
	return "charon"
}

func swanctlBin() string {
	if p := procmgr.Bundles().StrongswanBinPath("swanctl"); p != "" {
		return p
	}
	return "swanctl"
}
