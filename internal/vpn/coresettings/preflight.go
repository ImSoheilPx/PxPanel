// Pre-flight detection: what is ALREADY on this host that installing a core will
// have to live beside. Ported from vpn-ui web/service/preflight.go.
//
// The ownership manifest makes install and uninstall non-destructive, but it does
// its work silently, and silence is the wrong answer when an operator is about to
// hand their machine's xl2tpd (or ocserv, or IPsec, or a GRE tunnel) over to the
// panel. This reports the collisions BEFORE they commit, so "the panel took over
// my VPN" is a decision they made rather than something they discover afterwards.
//
// Everything here is a stat, a unit query or a netlink list. No side effects, so
// it is safe to call from a GET that renders the setup dialog.
package coresettings

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/ImSoheilPx/pxpanel/internal/vpn/config"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/pkgmgr"
)

// Manifest artifact kinds, restated as literals (vpn-ui: ownFile/ownDir/
// ownUnit/ownIface package consts). The values must stay byte-identical to the
// manifest file's kinds; manifest.KindIface is the one the kinds.go file
// exports, the rest are mirrored here until the manifest wave exports them.
const (
	kindFile  = "file"
	kindDir   = "dir"
	kindUnit  = "unit"
	kindIface = manifest.KindIface // "iface"
)

// amneziawgLinkKind is the netlink link type of an AmneziaWG device — a mirror
// of manifest.go's unexported const of the same name.
const amneziawgLinkKind = "amneziawg"

// ownershipBackupDir is where the manifest keeps copies of shared host files it
// overwrites (manifest.go's unexported ownershipDir+"/backups"; config.VPNDir is
// manifest's ownershipDir, /etc/pxpanel).
const ownershipBackupDir = config.VPNDir + "/backups"

// CoreHostConflict is one thing already on the host that a core would share
// (vpn-ui: coreHostConflict).
type CoreHostConflict struct {
	// Kind is one of the manifest's artifact kinds, so the dialog can group them.
	Kind string `json:"kind"`
	// What names the artifact (a path, a unit, an interface).
	What string `json:"what"`
	// Detail says what installing this core will do about it, in the operator's
	// terms rather than the manifest's.
	Detail string `json:"detail"`
}

// preflightFile reports a config file the named core will overwrite.
func preflightFile(path string) *CoreHostConflict {
	if _, err := os.Lstat(path); err != nil {
		return nil
	}
	return &CoreHostConflict{Kind: kindFile, What: path,
		Detail: "already present; pxpanel will replace it and keep a copy in " + ownershipBackupDir}
}

// preflightDir reports a config directory the core will write into.
func preflightDir(path string) *CoreHostConflict {
	st, err := os.Lstat(path)
	if err != nil || !st.IsDir() {
		return nil
	}
	return &CoreHostConflict{Kind: kindDir, What: path,
		Detail: "already exists; pxpanel will add its own files inside it and never remove the directory"}
}

// unitEnabled / unitActive are mirrors of procmgr's unexported probes of the
// same names (vpn-ui kept them in web/service/procmgr.go).
func unitEnabled(unit string) bool {
	out, err := exec.Command("systemctl", "is-enabled", unit).Output()
	return err == nil && strings.TrimSpace(string(out)) == "enabled"
}

func unitActive(unit string) bool {
	return systemctlActive(unit)
}

// preflightUnit reports a distro service the panel will stop and disable so it
// can run that daemon itself.
func preflightUnit(unit string) *CoreHostConflict {
	if !pkgmgr.CommandExists("systemctl") {
		return nil
	}
	enabled, active := unitEnabled(unit), unitActive(unit)
	if !enabled && !active {
		return nil
	}
	state := "enabled"
	if active && enabled {
		state = "enabled and running"
	} else if active {
		state = "running"
	}
	return &CoreHostConflict{Kind: kindUnit, What: unit,
		Detail: state + "; pxpanel will stop and disable it so the panel can run this daemon, and re-enable it on uninstall"}
}

// preflightIfaces reports the operator's own netdevs that share a protocol's
// naming space. These are NOT touched (see the manifest wave's ifaceown), and
// saying so is the point: this is the exact case the user reported, where a
// hand-made GRE tunnel disappeared as soon as the GRE core was installed.
func preflightIfaces(core string) []CoreHostConflict {
	links, err := netlink.LinkList()
	if err != nil {
		return nil
	}
	var out []CoreHostConflict
	for _, l := range links {
		name := l.Attrs().Name
		var match bool
		switch core {
		case "gre":
			_, isGre := l.(*netlink.Gretun)
			match = isGre && !manifest.GreOwnedName(name)
		case "wgc":
			_, isWg := l.(*netlink.Wireguard)
			match = isWg && !manifest.WgcOwnedName(name)
		case "awg":
			match = l.Type() == amneziawgLinkKind && !manifest.AwgOwnedName(name)
		}
		if !match {
			continue
		}
		out = append(out, CoreHostConflict{Kind: kindIface, What: name,
			Detail: "your own interface; pxpanel will not touch it"})
	}
	return out
}

// coreConflictProbe is hostConflictsFor behind a seam, so a test can substitute a
// probe over paths it controls. The real probe reads absolute host paths
// (/etc/ipsec.conf and friends), which a test can neither create nor rely on, and
// the question worth pinning is WHICH CORES get probed under which recorded
// install state rather than what a stat returns.
var coreConflictProbe = hostConflictsFor

// hostConflictsFor lists everything already on this host that installing one core
// would share. Empty for a core with nothing in its way, which is the normal case
// on a clean box.
func hostConflictsFor(core string) []CoreHostConflict {
	var out []CoreHostConflict
	add := func(c *CoreHostConflict) {
		if c != nil {
			out = append(out, *c)
		}
	}

	switch core {
	case "l2tp":
		add(preflightFile("/etc/xl2tpd/xl2tpd.conf"))
		add(preflightFile("/etc/ppp/options.xl2tpd"))
		add(preflightFile("/etc/ipsec.conf"))
		add(preflightFile("/etc/ipsec.secrets"))
		add(preflightUnit("xl2tpd.service"))
		add(preflightUnit("ipsec.service"))
	case "pptp":
		add(preflightFile("/etc/pptpd.conf"))
		add(preflightFile("/etc/ppp/pptpd-options"))
		add(preflightUnit("pptpd.service"))
	case "openvpn":
		add(preflightDir("/etc/openvpn"))
		add(preflightDir("/etc/openvpn/server"))
		// openvpn-server@<name> is templated, so the instances are found rather
		// than named. An enabled instance is the operator's own server.
		if matches, _ := filepath.Glob("/etc/openvpn/server/*.conf"); len(matches) > 0 {
			out = append(out, CoreHostConflict{Kind: kindFile, What: "/etc/openvpn/server/*.conf",
				Detail: "the distro's own OpenVPN server configs; pxpanel neither reads nor removes them"})
		}
	case "openconnect":
		add(preflightDir("/etc/ocserv"))
		add(preflightFile("/etc/ocserv/ocserv.conf"))
		add(preflightUnit("ocserv.service"))
	case "sstp":
		add(preflightDir("/etc/accel-ppp"))
		add(preflightUnit("accel-ppp.service"))
	case "ikev2":
		add(preflightFile("/etc/strongswan.conf"))
		add(preflightFile("/etc/swanctl/swanctl.conf"))
		add(preflightDir("/etc/swanctl/conf.d"))
		add(preflightUnit("strongswan.service"))
		add(preflightUnit("ipsec.service"))
	case "gre", "wgc", "awg":
		out = append(out, preflightIfaces(core)...)
	}
	return out
}
