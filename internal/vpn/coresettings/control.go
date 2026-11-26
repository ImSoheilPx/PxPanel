// Core control: RestartCore / RestartAll / StopCore / CoreLogs. Ported from
// vpn-ui web/service/core.go (control half), with the ipsec half via pkgmgr's
// exported ipsec.service handlers, the radius half via the radius package, and
// the xray half via xrayplane's restart seam + the local Xray status seam.
package coresettings

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/logger"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ipsec"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/pkgmgr"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/radius"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/xrayplane"
)

// RestartCore restarts the daemon(s) for a given core.
func (s *CoreService) RestartCore(name string) error {
	switch name {
	case "xray":
		// The web layer's RestartXray(force) — unwired this is a logged no-op.
		return xrayplane.RequestRestart(true)
	case "l2tp":
		return s.l2tp.RestartServices()
	case "pptp":
		return s.pptp.RestartServices()
	case "openvpn":
		return s.openvpn.RestartServices()
	case "openconnect":
		return s.ocserv.RestartServices()
	case "sstp":
		return s.sstp.RestartServices()
	case "ikev2":
		return s.ikev2.RestartServices()
	case "wgc":
		return s.wgc.RestartServices()
	case "awg":
		return s.awg.RestartServices()
	case "gre":
		return s.gre.RestartServices()
	case "mtproto":
		return s.mtproto.RestartServices()
	case "ssh":
		return s.ssh.RestartServices()
	case "radius":
		return radius.RestartRadius()
	case "ipsec":
		_, err := pkgmgr.RestartIpsecService()
		return err
	default:
		return fmt.Errorf("unknown core: %s", name)
	}
}

// RestartAll restarts every core in a sensible order, aggregating any errors so
// one failing core doesn't abort the rest.
func (s *CoreService) RestartAll() error {
	var errs []string
	for _, name := range []string{"xray", "l2tp", "pptp", "openvpn", "openconnect", "sstp", "ikev2", "wgc", "awg", "gre", "mtproto", "ssh", "radius"} {
		if err := s.RestartCore(name); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// StopCore stops a core, where stopping is supported.
func (s *CoreService) StopCore(name string) error {
	switch name {
	case "xray":
		if XrayStop == nil {
			return fmt.Errorf("xray stop is not wired (web wave)")
		}
		return XrayStop()
	case "l2tp":
		s.l2tp.StopServices()
		return nil
	case "pptp":
		s.pptp.StopServices()
		return nil
	case "openvpn":
		s.openvpn.StopServices()
		return nil
	case "openconnect":
		s.ocserv.StopServices()
		return nil
	case "sstp":
		return s.sstp.StopServices()
	case "ikev2":
		return s.ikev2.StopServices()
	case "wgc":
		return s.wgc.StopServices()
	case "awg":
		return s.awg.StopServices()
	case "gre":
		return s.gre.StopServices()
	case "mtproto":
		return s.mtproto.StopServices()
	case "ssh":
		return s.ssh.StopServices()
	case "radius":
		return radius.StopRadius()
	case "ipsec":
		return pkgmgr.StopIpsecService()
	default:
		return fmt.Errorf("core %s does not support stop", name)
	}
}

// CoreLogs returns recent captured output for a core. VPN daemons return their
// supervised child-process output; xray/radius return the matching lines from
// the panel's in-memory log buffer (their output is routed there).
func (s *CoreService) CoreLogs(name string) string {
	switch name {
	case "l2tp":
		return procmgr.GetProcManager().Logs("xl2tpd")
	case "pptp":
		return procmgr.GetProcManager().Logs("pptpd")
	case "openvpn":
		return procmgr.GetProcManager().LogsByPrefix(ovpnProcPrefix)
	case "openconnect":
		return procmgr.GetProcManager().LogsByPrefix(ocservProcPrefix)
	case "sstp":
		return procmgr.GetProcManager().LogsByPrefix(sstpProcPrefix)
	case "ikev2":
		return procmgr.GetProcManager().Logs(ikev2ProcName)
	case "wgc":
		if !s.wgc.WireguardAvailable() {
			return "WireGuard (C): kernel module 'wireguard' not available on this host."
		}
		up := "no"
		if s.wgc.AnyInterfaceUp() {
			up = "yes"
		}
		return fmt.Sprintf("WireGuard (C) runs in-kernel via wgctrl (no daemon log).\nModule version: %s\nInterface(s) up: %s", wireguardModuleVersion(), up)
	case "awg":
		if !s.awg.AmneziawgAvailable() {
			return "AmneziaWG: kernel module 'amneziawg' not built on this host (run Core Settings setup)."
		}
		up := "no"
		if s.awg.AnyInterfaceUp() {
			up = "yes"
		}
		return fmt.Sprintf("AmneziaWG runs in-kernel via the wgctrl fork (no daemon log).\nModule version: %s\nInterface(s) up: %s", amneziawgModuleVersion(), up)
	case "gre":
		if !s.gre.GreAvailable() {
			return "GRE: kernel GRE (ip_gre) not available on this host."
		}
		up := "no"
		if s.gre.AnyInterfaceUp() {
			up = "yes"
		}
		fou := "no"
		if s.gre.FouAvailable() {
			fou = "yes"
		}
		return fmt.Sprintf("GRE runs in-kernel via netlink (no daemon log).\nTunnel(s) up: %s\nFOU (UDP encap) available: %s", up, fou)
	case "mtproto":
		return procmgr.GetProcManager().LogsByPrefix(mtprotoProcPrefix)
	case "ssh":
		running := "no"
		if s.ssh.AnyRunning() {
			running = "yes"
		}
		return fmt.Sprintf("SSH gateway runs in-binary (no daemon log).\nListener(s) bound: %s\n\n%s", running, filterLogs("SSH:"))
	case "xray":
		out := filterLogs("xray")
		if out == "" && XrayResult != nil {
			return XrayResult()
		}
		return out
	case "radius":
		return filterLogs("radius")
	case "ipsec":
		return ipsecFailureDiagnostics()
	}
	return ""
}

// filterLogs returns the most recent panel log lines (chronological) whose text
// mentions the given keyword (case-insensitive).
func filterLogs(keyword string) string {
	lines := logger.GetLogs(400, "debug")
	kw := strings.ToLower(keyword)
	var matched []string
	// GetLogs returns newest-first; walk backwards to emit chronological order.
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(strings.ToLower(lines[i]), kw) {
			matched = append(matched, lines[i])
		}
	}
	return strings.Join(matched, "\n")
}

// ipsecFailureDiagnostics captures why IPsec didn't come up (vpn-ui
// pkgmgr.go:325; pkgmgr keeps its copy unexported, scoped to its own steps).
func ipsecFailureDiagnostics() string {
	if ipsec.UsingBundledIpsec() {
		return procmgr.GetProcManager().Logs(ipsecBundledProcNm)
	}
	if !commandExists("systemctl") {
		return ""
	}
	var b strings.Builder
	out, _ := exec.Command("systemctl", "status", "ipsec", "--no-pager", "-l").CombinedOutput()
	b.WriteString("\n$ systemctl status ipsec\n" + string(out))
	if jout, _ := exec.Command("journalctl", "-u", "ipsec", "--no-pager", "-n", "30").CombinedOutput(); len(jout) > 0 {
		b.WriteString("\n$ journalctl -u ipsec -n 30\n" + string(jout))
	}
	return b.String()
}
