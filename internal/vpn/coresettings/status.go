// Per-core status + the recorded installed set. Ported from vpn-ui
// web/service/core.go (status half) and corecatalog.go's CoreCatalog /
// inboundCountsByCore.
package coresettings

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/ImSoheilPx/pxpanel/internal/config"
	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/logger"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ikev2"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ipsec"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/pkgmgr"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"

	awgsvc "github.com/ImSoheilPx/pxpanel/internal/vpn/awg"
	gresvc "github.com/ImSoheilPx/pxpanel/internal/vpn/gre"
	l2tpsvc "github.com/ImSoheilPx/pxpanel/internal/vpn/l2tp"
	mtpsvc "github.com/ImSoheilPx/pxpanel/internal/vpn/mtproto"
	ocsvc "github.com/ImSoheilPx/pxpanel/internal/vpn/ocserv"
	ovpnsvc "github.com/ImSoheilPx/pxpanel/internal/vpn/openvpn"
	pptpsvc "github.com/ImSoheilPx/pxpanel/internal/vpn/pptp"
	sshsvc "github.com/ImSoheilPx/pxpanel/internal/vpn/ssh"
	sstpsvc "github.com/ImSoheilPx/pxpanel/internal/vpn/sstp"
	wgcsvc "github.com/ImSoheilPx/pxpanel/internal/vpn/wgc"
)

// CoreState is the coarse health of a backend "core".
type CoreState string

const (
	CoreRunning      CoreState = "running"       // daemon is up
	CoreStopped      CoreState = "stopped"       // installed + has inbounds, but not running
	CoreIdle         CoreState = "idle"          // installed but no inbounds configured
	CoreNotInstalled CoreState = "not_installed" // binary missing (needs setup/bundle)
	CoreError        CoreState = "error"         // running attempt failed
)

// CoreStatus is the status of a single backend core shown in the Core Settings panel.
type CoreStatus struct {
	Name     string         `json:"name"`     // xray | l2tp | pptp | openvpn | openconnect | radius
	State    CoreState      `json:"state"`    //
	Detail   string         `json:"detail"`   // human-readable extra info / error
	Version  string         `json:"version"`  // where available (xray)
	Inbounds int            `json:"inbounds"` // number of inbounds of this type
	Extra    map[string]any `json:"extra,omitempty"`
}

// ModuleStatus reports whether a kernel module is loaded. Optional modules (e.g.
// af_key on kernels that dropped PF_KEY) don't count against readiness.
type ModuleStatus struct {
	Name     string `json:"name"`
	Loaded   bool   `json:"loaded"`
	Optional bool   `json:"optional,omitempty"`
}

// SystemStatus reports the host/kernel prerequisites that can't be baked into
// the binary — exactly the things the setup script used to worry about.
type SystemStatus struct {
	IpForward bool           `json:"ipForward"`
	Nftables  bool           `json:"nftables"`
	Iproute   bool           `json:"iproute"`
	Modules   []ModuleStatus `json:"modules"`
	ModulesOK bool           `json:"modulesOk"`
}

// Proc-name mirrors: the per-inbound procMgr child-name shapes the protocol
// packages keep unexported (openvpn.ovpnProcName / ocserv.ocservProcName /
// sstp.sstpProcName / mtproto.mtprotoProcName; ikev2ProcName is ipsec's and
// ikev2's shared const, value "ikev2"). Only the PREFIXES and the charon key
// are needed here — status and logs never address one inbound. Keep
// byte-identical to the protocol packages' shapes.
const (
	ovpnProcPrefix     = "openvpn-server-"
	ocservProcPrefix   = "ocserv-server-"
	sstpProcPrefix     = "sstp-server-"
	mtprotoProcPrefix  = "mtproto-server-"
	ikev2ProcName      = "ikev2"
	ipsecBundledProcNm = "ipsec" // pkgmgr.ipsecProcName: the bundled-pluto child
)

// Xray status seam. vpn-ui read its in-package xrayService directly; the
// target's Xray core control lives in internal/web (XrayService), which the
// vpn tree must not import (cycle). The web wave wires these four probes at
// start-up alongside xrayplane.SetRestartHook; unwired, the card reads
// "stopped" rather than inventing a lie. TODO(web wave): wire at server start.
var (
	// XrayRunning reports whether the Xray core process is up.
	XrayRunning func() bool
	// XrayVersion returns the running core's version string.
	XrayVersion func() string
	// XrayErr returns the last start error, when the core failed to come up.
	XrayErr func() error
	// XrayResult returns the core's own captured output, for CoreLogs.
	XrayResult func() string
	// XrayStop stops the core process (StopCore("xray")).
	XrayStop func() error
)

// CoreService aggregates status and provisioning across all backend cores.
// Like the other services it is a zero-value-usable value type; its methods are
// stateless (they read the DB and probe the host), so a fresh copy works.
type CoreService struct {
	l2tp    l2tpsvc.L2tpService
	pptp    pptpsvc.PptpService
	openvpn ovpnsvc.OpenVpnService
	ocserv  ocsvc.OcservService
	sstp    sstpsvc.SstpService
	ikev2   ikev2.Ikev2Service
	wgc     wgcsvc.WgcService
	awg     awgsvc.AwgService
	gre     gresvc.GreService
	mtproto mtpsvc.MtprotoService
	ssh     sshsvc.SshService
}

// --------------------------------------------------------------------------- //
//  Host probes
// --------------------------------------------------------------------------- //

func commandExists(name string) bool {
	return pkgmgr.CommandExists(name)
}

// daemonInstalled reports whether a daemon is available either from the host
// (in PATH) or from the bundle baked into the binary and extracted at setup —
// or from an ADOPTED previous-install daemon (legacybundle seam). The two
// relocatable-tree probes matter because accel-ppp and strongSwan are not flat
// BinDir binaries: their launcher wrappers resolve through AccelBinPath /
// StrongswanBinPath only. Same resolution order as daemonVersion below.
func daemonInstalled(name string) bool {
	b := procmgr.Bundles()
	return commandExists(name) ||
		b.DaemonPath(name) != "" ||
		b.AccelBinPath(name) != "" ||
		b.StrongswanBinPath(name) != ""
}

func systemctlActive(unit string) bool {
	if !commandExists("systemctl") {
		return false
	}
	out, _ := exec.Command("systemctl", "is-active", unit).Output()
	return strings.TrimSpace(string(out)) == "active"
}

func moduleLoaded(name string) bool {
	// A loaded module has /sys/module/<name>. A built-in module ALSO has that
	// entry — but ONLY if it exports at least one module parameter; a param-less built-in
	// (e.g. `tun`) has no /sys/module entry at all, so /sys alone false-negatives on
	// it and it would show "not loaded"/red even though it's compiled into the kernel
	// and always available. Fall back to the kernel's modules.builtin list for those.
	if _, err := os.Stat("/sys/module/" + name); err == nil {
		return true
	}
	return moduleBuiltin(name)
}

// moduleBuiltin reports whether the module is compiled into the running kernel,
// per /lib/modules/<ver>/modules.builtin (which lists built-in modules as
// "kernel/.../<name>.ko" paths). Built-ins are always available and need no load.
func moduleBuiltin(name string) bool {
	data, err := os.ReadFile("/lib/modules/" + pkgmgr.RunningKernel() + "/modules.builtin")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "/"+name+".ko")
}

// moduleAvailable reports whether a module can be used on the running kernel —
// already loaded, built into the kernel, or loadable on demand. It drives the
// "do we need to install a kernel package?" decision, so it must NOT false-
// negative on built-in modules (which have no /sys/module entry): `modprobe -nq`
// resolves both loadable .ko files and built-ins, returning success for either.
func moduleAvailable(name string) bool {
	return pkgmgr.ModuleAvailable(name)
}

var (
	daemonVersionRe    = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?`)
	daemonVersionCache = map[string]string{}
	daemonVersionMu    sync.Mutex
)

// daemonVersion returns a short version string (e.g. "2.6.12") for a bundled or
// host daemon by running `<bin> --version` and grabbing the first version-shaped
// token. Output is read regardless of exit code (some daemons exit non-zero on
// --version). Successful lookups are cached; "" is returned (and not cached) when
// the daemon isn't available, so it retries once it's installed.
func daemonVersion(name string) string {
	daemonVersionMu.Lock()
	if v, ok := daemonVersionCache[name]; ok {
		daemonVersionMu.Unlock()
		return v
	}
	daemonVersionMu.Unlock()

	b := procmgr.Bundles()
	bin := ""
	if p := b.DaemonPath(name); p != "" {
		bin = p
	} else if p := b.AccelBinPath(name); p != "" {
		// accel-ppp (SSTP) ships as a relocatable tree bundle, not a flat BinDir
		// binary, so its launchers resolve here — mirrors daemonBin().
		bin = p
	} else if p := b.StrongswanBinPath(name); p != "" {
		// strongSwan (IKEv2) also ships as a relocatable tree bundle, so the bundled
		// charon launcher resolves here — otherwise `charon --version` (a "strongSwan
		// 5.9.14" line) is never run and the IKEv2 core version shows as "—".
		bin = p
	} else if p, err := exec.LookPath(name); err == nil {
		bin = p
	} else {
		return ""
	}
	out, _ := exec.Command(bin, "--version").CombinedOutput()
	v := daemonVersionRe.FindString(string(out))
	if v != "" {
		daemonVersionMu.Lock()
		daemonVersionCache[name] = v
		daemonVersionMu.Unlock()
	}
	return v
}

func procFileIsOne(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}

// --------------------------------------------------------------------------- //
//  Per-core status
// --------------------------------------------------------------------------- //

// dokodemoPortBound reports whether something is already listening on the given
// TCP port — i.e. Xray bound its dokodemo-door for a VPN inbound. Probes by
// trying to bind: bind fails (address in use) → taken; bind succeeds → the port
// is free, meaning Xray failed to bind it.
func dokodemoPortBound(port int) bool {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}

// MissingDokodemoPorts returns the TPROXY/dokodemo ports that SHOULD be bound —
// one per enabled dial-in inbound, since that's how their traffic reaches Xray —
// but currently are not. A non-empty result means Xray silently failed to bind
// them on a restart, so those VPNs have no internet until it rebinds. Consumed
// by the dokodemo self-heal job.
func (s *CoreService) MissingDokodemoPorts() []int {
	var missing []int
	if ins, err := s.l2tp.GetL2tpInbounds(); err == nil {
		for _, in := range ins {
			if port := s.l2tp.GetTproxyPort(in); in.Enable && !dokodemoPortBound(port) {
				missing = append(missing, port)
			}
		}
	}
	if ins, err := s.pptp.GetPptpInbounds(); err == nil {
		for _, in := range ins {
			if port := s.pptp.GetTproxyPort(in); in.Enable && !dokodemoPortBound(port) {
				missing = append(missing, port)
			}
		}
	}
	if ins, err := s.openvpn.GetOpenVpnInbounds(); err == nil {
		for _, in := range ins {
			// One shared dokodemo per OpenVPN inbound (both transports use it).
			if port := s.openvpn.GetTproxyPort(in); in.Enable && !dokodemoPortBound(port) {
				missing = append(missing, port)
			}
		}
	}
	if ins, err := s.ocserv.GetOcservInbounds(); err == nil {
		for _, in := range ins {
			if port := s.ocserv.GetTproxyPort(in); in.Enable && !dokodemoPortBound(port) {
				missing = append(missing, port)
			}
		}
	}
	if ins, err := s.sstp.GetSstpInbounds(); err == nil {
		for _, in := range ins {
			if port := s.sstp.GetTproxyPort(in); in.Enable && !dokodemoPortBound(port) {
				missing = append(missing, port)
			}
		}
	}
	if ins, err := s.ikev2.GetIkev2Inbounds(); err == nil {
		for _, in := range ins {
			if port := s.ikev2.GetTproxyPort(in); in.Enable && !dokodemoPortBound(port) {
				missing = append(missing, port)
			}
		}
	}
	return missing
}

// GetCoresStatus returns the status of every backend core, in display order.
func (s *CoreService) GetCoresStatus() []CoreStatus {
	all := []CoreStatus{
		s.xrayStatus(),
		s.l2tpStatus(),
		s.ipsecStatus(),
		s.pptpStatus(),
		s.openvpnStatus(),
		s.ocservStatus(),
		s.sstpStatus(),
		s.ikev2Status(),
		s.wgcStatus(),
		s.awgStatus(),
		s.greStatus(),
		s.mtprotoStatus(),
		s.sshStatus(),
		s.radiusStatus(),
	}

	// A core the operator never installed reads as "not installed", whatever the
	// host probes say. Several cores would otherwise report themselves ready off
	// an embedded bundle (strongSwan, accel-ppp) or a stock kernel module
	// (WireGuard) that setup has not actually wired up on this host.
	installed := s.provisionedProtocolSet()
	installedNames := coreNamesFromSet(installed)
	for i := range all {
		if coreInstalled(all[i].Name, installed, installedNames) {
			continue
		}
		all[i].State = CoreNotInstalled
		all[i].Version = ""
		if all[i].Detail == "" {
			all[i].Detail = "not installed on this host"
		}
	}
	return all
}

// coreInstalled answers "has this host been set up for this core" for each of the
// three shapes of core the status cards show.
//
//   - A catalog core the operator picks: the recorded set is the only answer.
//   - A DERIVED core (ipsec, radius): nobody installs it directly, it exists only
//     to serve other cores, so it is installed exactly when an installed core
//     needs it. That is reference counting against what IS installed, the same
//     arithmetic uninstall runs against what REMAINS.
//   - A built-in core nothing else depends on (xray, ssh): part of the panel, so
//     it is always installed and its card reports plain liveness.
//
// ipsec and radius used to skip this check and fall through to their own probes,
// and on a host that has installed nothing both probes lie. The strongSwan bundle
// is embedded in the binary whether or not setup ever extracted it, so ipsec read
// "stopped"; the in-binary RADIUS server binds :1812 from panel start, so radius
// read "running" with nothing on the host for it to authenticate.
func coreInstalled(name string, installed map[string]bool, installedNames []string) bool {
	switch name {
	case "ipsec":
		// The shared IPsec layer: one charon serving L2TP/IPsec and IKEv2, or host
		// libreswan on an arch with no bundle. Only those two claim featStrongswan,
		// so a host with neither has no IPsec to report on.
		return needsFeature(installedNames, featStrongswan)
	case "radius":
		return anyCoreUsesRadius(installedNames)
	}
	spec := coreSpecFor(name)
	if spec == nil {
		return false
	}
	return spec.builtin || installed[name]
}

// xrayServedProtocols are the protocols the Overview lists as services of their
// own even though no daemon of theirs exists: one Xray process serves all of
// them, so their health IS Xray's health, qualified by whether an inbound of that
// protocol has been configured at all.
//
// They are deliberately NOT cores. A core is something the operator installs,
// starts and stops (see catalog.go), and none of that is true here - a card on
// the Core Settings page offering to stop AnyTLS would be offering to stop
// something that does not exist as a process.
var xrayServedProtocols = []string{"anytls", "tuic", "naive"}

// xrayProtocolInbounds counts the inbounds of each Xray-served protocol, so the
// Overview can tell "serving accounts" from "available but unused" without
// fetching the whole inbound list into a page that lists no inbounds.
func xrayProtocolInbounds() map[string]any {
	out := make(map[string]any, len(xrayServedProtocols))
	for _, p := range xrayServedProtocols {
		out[p] = 0
	}
	db := vpn.DB()
	if db == nil {
		return out
	}
	var rows []struct {
		Protocol string
		N        int
	}
	if err := db.Model(model.Inbound{}).
		Select("protocol, count(*) as n").
		Where("protocol IN (?) AND enable = ?", xrayServedProtocols, true).
		Group("protocol").Scan(&rows).Error; err != nil {
		logger.Warning("counting Xray-served protocol inbounds: ", err)
		return out
	}
	for _, r := range rows {
		out[r.Protocol] = r.N
	}
	return out
}

func (s *CoreService) xrayStatus() CoreStatus {
	cs := CoreStatus{Name: "xray"}
	// Carried on the Xray status rather than as statuses of their own: these
	// protocols have no separate process to report on, and inventing a core for
	// each would put a start/stop card on the Core Settings page for something
	// with nothing to start.
	cs.Extra = map[string]any{"protocolInbounds": xrayProtocolInbounds()}
	if XrayRunning != nil && XrayRunning() {
		cs.State = CoreRunning
		if XrayVersion != nil {
			cs.Version = XrayVersion()
		}
		return cs
	}
	if XrayErr != nil {
		if err := XrayErr(); err != nil {
			cs.State = CoreError
			cs.Detail = err.Error()
			return cs
		}
	}
	cs.State = CoreStopped
	return cs
}

func (s *CoreService) l2tpStatus() CoreStatus {
	cs := CoreStatus{Name: "l2tp"}
	inbounds, _ := s.l2tp.GetL2tpInbounds()
	cs.Inbounds = len(inbounds)
	if !daemonInstalled("xl2tpd") {
		cs.State = CoreNotInstalled
		cs.Detail = "xl2tpd not installed"
		return cs
	}
	cs.Version = daemonVersion("xl2tpd")
	switch {
	case procmgr.GetProcManager().IsRunning("xl2tpd"):
		cs.State = CoreRunning
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	default:
		cs.State = CoreStopped
	}
	return cs
}

// ipsecStatus reports libreswan (IPsec) as its own core. It runs either as our
// bundled USE_DH2 pluto (a supervised procMgr child, when a bundle is embedded)
// or as the host's ipsec.service — either way it underpins L2TP/IPsec but
// installs, versions and runs independently of xl2tpd, so it gets its own card.
func (s *CoreService) ipsecStatus() CoreStatus {
	cs := CoreStatus{Name: "ipsec"}
	// Bundled-strongSwan path (amd64): L2TP/IPsec is served by the SAME charon as IKEv2
	// (one daemon on UDP 500/4500). Report the charon process + strongSwan version so this
	// core reflects reality instead of the retired libreswan/pluto. Note for the UI: ipsec
	// and ikev2 now share one daemon, so stopping one stops both.
	if ipsec.HasStrongswanBundle() {
		if v := daemonVersion("charon"); v != "" {
			cs.Version = v
		}
		switch {
		case procmgr.GetProcManager().IsRunning(ikev2ProcName):
			cs.State = CoreRunning
		case !ikev2.CharonNeeded():
			// No enabled inbound wants IPsec (no IKEv2, and no L2TP or GRE with
			// ipsecEnable), so charon is MEANT to be down. "Idle" says that; amber
			// "Stopped" reads as a fault the operator is supposed to go and fix.
			// PORT NOTE: vpn-ui asked its in-package charonNeeded; the target's
			// aggregated form is ikev2's exported re-export (ipsec keeps its
			// register-needers variant unexported).
			cs.State = CoreIdle
		default:
			cs.State = CoreStopped
		}
		return cs
	}
	// Host libreswan path (arches without the strongSwan bundle).
	if !ipsecAvailable() {
		cs.State = CoreNotInstalled
		cs.Detail = "libreswan (ipsec) not installed"
		return cs
	}
	if maj, min, ok := pkgmgr.LibreswanVersion(); ok {
		cs.Version = fmt.Sprintf("%d.%d", maj, min)
	}
	running := systemctlActive("ipsec")
	if ipsec.UsingBundledIpsec() {
		running = ipsec.BundledPlutoRunning()
	}
	if running {
		cs.State = CoreRunning
	} else {
		cs.State = CoreStopped
	}
	return cs
}

// ipsecAvailable reports whether an `ipsec`/libreswan is usable at all — the
// bundled pluto, or a host install (vpn-ui ipsec_bundle.go:ipsecAvailable).
func ipsecAvailable() bool {
	return ipsec.UsingBundledIpsec() || commandExists("ipsec")
}

func (s *CoreService) pptpStatus() CoreStatus {
	cs := CoreStatus{Name: "pptp"}
	inbounds, _ := s.pptp.GetPptpInbounds()
	cs.Inbounds = len(inbounds)
	if !daemonInstalled("pptpd") {
		cs.State = CoreNotInstalled
		cs.Detail = "pptpd not installed"
		return cs
	}
	cs.Version = daemonVersion("pptpd")
	switch {
	case procmgr.GetProcManager().IsRunning("pptpd"):
		cs.State = CoreRunning
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	default:
		cs.State = CoreStopped
	}
	return cs
}

func (s *CoreService) openvpnStatus() CoreStatus {
	cs := CoreStatus{Name: "openvpn"}
	inbounds, _ := s.openvpn.GetOpenVpnInbounds()
	cs.Inbounds = len(inbounds)
	if !daemonInstalled("openvpn") {
		cs.State = CoreNotInstalled
		cs.Detail = "openvpn not installed"
		return cs
	}
	cs.Version = daemonVersion("openvpn")
	switch {
	case procmgr.GetProcManager().AnyRunningWithPrefix(ovpnProcPrefix):
		cs.State = CoreRunning
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	default:
		cs.State = CoreStopped
	}
	return cs
}

func (s *CoreService) ocservStatus() CoreStatus {
	cs := CoreStatus{Name: "openconnect"}
	inbounds, _ := s.ocserv.GetOcservInbounds()
	cs.Inbounds = len(inbounds)
	if !daemonInstalled("ocserv") {
		cs.State = CoreNotInstalled
		cs.Detail = "ocserv not installed"
		return cs
	}
	cs.Version = daemonVersion("ocserv")
	switch {
	case procmgr.GetProcManager().AnyRunningWithPrefix(ocservProcPrefix):
		cs.State = CoreRunning
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	default:
		cs.State = CoreStopped
	}
	return cs
}

func (s *CoreService) sstpStatus() CoreStatus {
	cs := CoreStatus{Name: "sstp"}
	inbounds, _ := s.sstp.GetSstpInbounds()
	cs.Inbounds = len(inbounds)
	// accel-pppd ships as a relocatable TREE bundle (not a flat BinDir daemon), so
	// daemonInstalled — which only consults PATH + the bundle's DaemonPath — misses it;
	// StrongswanBundleReady-style bundle probes cover the baked-in-binary case once the
	// bundle/build wave lands. Either presence = installed.
	if !daemonInstalled("accel-pppd") && !sstpBundlePresent() {
		cs.State = CoreNotInstalled
		cs.Detail = "accel-ppp (accel-pppd) not installed"
		return cs
	}
	cs.Version = daemonVersion("accel-pppd")
	switch {
	case procmgr.GetProcManager().AnyRunningWithPrefix(sstpProcPrefix):
		cs.State = CoreRunning
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	default:
		cs.State = CoreStopped
	}
	return cs
}

// sstpBundlePresent mirrors vpn-ui's backend.HasAccelBundle: is the accel-ppp
// tree bundle on disk? The BundleProvider has no accel probe yet, so this is
// the on-disk layout check the bundle wave's extractor produces. It answers
// false on the no-bundle default, which is the honest answer.
func sstpBundlePresent() bool {
	if len(daemonsFor([]string{"sstp"})) == 0 {
		return false
	}
	// The relocatable accel-ppp tree lives under the bundle root; nothing in the
	// current seam names it, so probe the conventional path.
	if _, err := os.Stat("/usr/libexec/pxpanel/accel-ppp"); err == nil {
		return true
	}
	return false
}

func (s *CoreService) ikev2Status() CoreStatus {
	cs := CoreStatus{Name: "ikev2"}
	inbounds, _ := s.ikev2.GetIkev2Inbounds()
	cs.Inbounds = len(inbounds)
	// charon ships as a relocatable TREE bundle (not a flat BinDir daemon), so
	// daemonInstalled (PATH + DaemonPath only) misses it; HasStrongswanBundle
	// covers the baked-in-binary case. Either presence = installed.
	if !daemonInstalled("charon") && !ipsec.HasStrongswanBundle() {
		cs.State = CoreNotInstalled
		cs.Detail = "strongSwan (charon) not installed"
		return cs
	}
	cs.Version = daemonVersion("charon")
	switch {
	case procmgr.GetProcManager().IsRunning(ikev2ProcName):
		cs.State = CoreRunning
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	default:
		cs.State = CoreStopped
	}
	return cs
}

// wgcStatus reports the WireGuard (C) core. Unlike the daemon-backed protocols there
// is no process to check: the data plane is the in-kernel wireguard module + the panel's
// wgctrl-managed interfaces. State is module-availability + interface presence based.
func (s *CoreService) wgcStatus() CoreStatus {
	cs := CoreStatus{Name: "wgc"}
	inbounds, _ := s.wgc.GetWgcInbounds()
	cs.Inbounds = len(inbounds)
	if !s.wgc.WireguardAvailable() {
		cs.State = CoreNotInstalled
		cs.Detail = "wireguard kernel module not available"
		return cs
	}
	cs.Version = wireguardModuleVersion()
	switch {
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	case s.wgc.AnyInterfaceUp():
		cs.State = CoreRunning
	default:
		cs.State = CoreStopped
	}
	return cs
}

// greStatus reports the GRE core. Like wg-c and awg it has no daemon: the data plane is the
// in-tree ip_gre module plus the netdevs GreService reconciles over netlink. ip_gre is
// frequently compiled into the kernel rather than built as a module, so availability is
// probed via the fallback device the driver registers, not only via /sys/module.
func (s *CoreService) greStatus() CoreStatus {
	cs := CoreStatus{Name: "gre"}
	inbounds, _ := s.gre.GetGreInbounds()
	cs.Inbounds = len(inbounds)
	if !s.gre.GreAvailable() {
		cs.State = CoreNotInstalled
		cs.Detail = "kernel GRE (ip_gre) not available (run Core Settings setup)"
		return cs
	}
	cs.Version = "kernel"
	switch {
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	case s.gre.AnyInterfaceUp():
		cs.State = CoreRunning
	default:
		cs.State = CoreStopped
	}
	return cs
}

// awgStatus reports the AmneziaWG core. Like wg-c it has no daemon: the data plane is the
// out-of-tree amneziawg kernel module (DKMS-built) + the panel's wgctrl-managed interfaces.
func (s *CoreService) awgStatus() CoreStatus {
	cs := CoreStatus{Name: "awg"}
	inbounds, _ := s.awg.GetAwgInbounds()
	cs.Inbounds = len(inbounds)
	if !s.awg.AmneziawgAvailable() {
		cs.State = CoreNotInstalled
		// Distinguish "setup has not run yet" from "this host cannot build it at all".
		// Telling an operator on Fedora/Arch/RHEL to re-run setup would send them round a
		// loop that can never succeed, so say what is actually wrong.
		if ok, why := awgKernelModuleSupported(); !ok {
			cs.Detail = why
		} else {
			cs.Detail = "amneziawg kernel module not built (run Core Settings setup)"
		}
		return cs
	}
	cs.Version = amneziawgModuleVersion()
	switch {
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	case s.awg.AnyInterfaceUp():
		cs.State = CoreRunning
	default:
		cs.State = CoreStopped
	}
	return cs
}

// mtprotoStatus reports the MTProto Proxy core. Unlike the tunnel protocols there
// is no kernel module or interface to probe: telemt is a plain userspace relay, so
// availability is just "is the bundled binary present" and liveness is "is any
// per-inbound child running".
func (s *CoreService) mtprotoStatus() CoreStatus {
	cs := CoreStatus{Name: "mtproto"}
	inbounds, _ := s.mtproto.GetMtprotoInbounds()
	cs.Inbounds = len(inbounds)
	if !s.mtproto.Available() {
		cs.State = CoreNotInstalled
		cs.Detail = "telemt binary not bundled for this architecture"
		return cs
	}
	cs.Version = daemonVersion("telemt")
	switch {
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	case procmgr.GetProcManager().AnyRunningWithPrefix(mtprotoProcPrefix):
		cs.State = CoreRunning
	default:
		cs.State = CoreStopped
	}
	return cs
}

func (s *CoreService) radiusStatus() CoreStatus {
	cs := CoreStatus{Name: "radius"}
	// RADIUS is embedded in the panel binary, so its version is the panel's.
	cs.Version = config.GetPanelVersion()
	// The embedded RADIUS server binds 127.0.0.1:1812 (auth). If the port can't
	// be bound, the server is already listening — which is what we want.
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:1812")
	if err != nil {
		cs.State = CoreRunning
		return cs
	}
	_ = pc.Close()
	cs.State = CoreStopped
	return cs
}

// sshStatus reports the SSH core. Like radius/wgc it is an in-binary Go server, so it
// is always "installed" (no bundled binary, no host dependency); "running" means at
// least one SSH listener is bound.
func (s *CoreService) sshStatus() CoreStatus {
	cs := CoreStatus{Name: "ssh"}
	cs.Version = config.GetPanelVersion()
	inbounds, _ := s.ssh.GetSshInbounds()
	cs.Inbounds = len(inbounds)
	switch {
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	case s.ssh.AnyRunning():
		cs.State = CoreRunning
	default:
		cs.State = CoreStopped
	}
	return cs
}

// --------------------------------------------------------------------------- //
//  Module version readers — mirrors of the protocol packages' unexported
//  probes (wgc.wireguardModuleVersion / awg.amneziawgModuleVersion).
// --------------------------------------------------------------------------- //

func wireguardModuleVersion() string {
	b, err := os.ReadFile("/sys/module/wireguard/version")
	if err != nil {
		return "kernel"
	}
	if v := strings.TrimSpace(string(b)); v != "" {
		return v
	}
	return "kernel"
}

func amneziawgModuleVersion() string {
	b, err := os.ReadFile("/sys/module/amneziawg/version")
	if err != nil {
		return "kernel"
	}
	if v := strings.TrimSpace(string(b)); v != "" {
		return v
	}
	return "kernel"
}

// --------------------------------------------------------------------------- //
//  AmneziaWG host-support probe (vpn-ui amneziawg_dkms.go:355-445)
// --------------------------------------------------------------------------- //

const awgSupportedDistros = "Debian 12, Debian 13, Ubuntu 24.04 or Ubuntu 26.04"

// awgKernelModuleSupported reports whether the AmneziaWG kernel module can build on
// this host (vpn-ui amneziawg_dkms.go, verbatim; pkgmgr.OSReleaseField/DistroPretty/
// RunningKernel replace the in-package os-release helpers).
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

// isEnterpriseLinux reports whether /etc/os-release names a RHEL clone.
func isEnterpriseLinux() bool {
	switch strings.ToLower(pkgmgr.OSReleaseField("ID")) {
	case "almalinux", "rocky", "centos", "rhel":
		return true
	}
	return strings.Contains(strings.ToLower(pkgmgr.OSReleaseField("ID_LIKE")), "rhel")
}

// --------------------------------------------------------------------------- //
//  System / kernel status
// --------------------------------------------------------------------------- //

// GetSystemStatus reports the host prerequisites (kernel modules, ip_forward,
// nftables) that cannot be baked into the binary.
func (s *CoreService) GetSystemStatus() SystemStatus {
	st := SystemStatus{
		IpForward: procFileIsOne("/proc/sys/net/ipv4/ip_forward"),
		Nftables:  commandExists("nft"),
		Iproute:   commandExists("ip"),
		ModulesOK: true,
	}
	// Scoped to the installed cores: a module belonging to a core this host never
	// installed is not missing, it is irrelevant, and reporting it red would ask
	// the operator to fix something they deliberately did not ask for.
	installed := s.installedCoreNames()
	for _, m := range requiredModulesFor(installed) {
		loaded := moduleLoaded(m)
		if !loaded {
			st.ModulesOK = false
		}
		st.Modules = append(st.Modules, ModuleStatus{Name: m, Loaded: loaded})
	}
	// Optional modules are shown only when the running kernel actually ships them,
	// so a module the kernel dropped (af_key on RHEL 10+) doesn't surface as a red
	// "not loaded" row or drag ModulesOK down.
	for _, m := range optionalModulesFor(installed) {
		if moduleAvailable(m) {
			st.Modules = append(st.Modules, ModuleStatus{Name: m, Loaded: moduleLoaded(m), Optional: true})
		}
	}
	return st
}

// IsProvisioned reports whether the VPN backend setup ("Initialize Setup") has
// been completed. It is true when the persisted flag is set, or — for installs
// provisioned before that flag existed — when the host already looks prepared:
// IP forwarding is enabled and a bundled daemon is available (daemons are only
// extracted by Provision). This fallback keeps already-set-up upgrades from
// regressing to the setup call-to-action.
func (s *CoreService) IsProvisioned() bool {
	// Before judging the host, give the one-time legacy scan its chance to
	// record an upgraded install's adopted cores: on a legacy host neither the
	// flag nor the daemon probe below can speak for the previous install.
	ensureLegacyAdoption()
	if GetVpnProvisioned() {
		return true
	}
	return procFileIsOne("/proc/sys/net/ipv4/ip_forward") && daemonInstalled("openvpn")
}

// provisionBaseline is FROZEN: the protocol set as of when per-protocol setup
// tracking was introduced. Do NOT add to it. It credits pre-tracking installs
// (vpnProvisioned=true, no recorded list) with the protocols that already
// existed, so an upgrade is not wrongly told every protocol is new.
var provisionBaseline = []string{"l2tp", "pptp", "openvpn", "openconnect"}

// provisionedProtocolSet returns the cores the host has been set up for. Setup
// is per-core now, so this is the authoritative "is it installed" answer for
// everything downstream: the status cards, the inbound-creation gate, and the
// shared-requirement arithmetic that decides what an uninstall may remove.
//
// The one-time legacy adoption scan is hooked here (rather than only at boot)
// because EVERY installed-set consumer flows through this one read: the boot
// ownership survey, the status cards, the catalog and the hooks. On an
// upgraded host the first read after the DB is wired records the previous
// install's daemons, so the very first status render already sees them.
func (s *CoreService) provisionedProtocolSet() map[string]bool {
	ensureLegacyAdoption()
	set := map[string]bool{}
	if list := GetProvisionedProtocols(); len(list) > 0 {
		for _, p := range list {
			set[p] = true
		}
		return set
	}
	// An install that has recorded its core set and recorded it as EMPTY is
	// authoritative: the operator uninstalled everything. Falling through to the
	// baseline here would resurrect the original four cores as "installed" the
	// moment the last one was removed.
	if HasRecordedProvisionedProtocols() {
		return set
	}
	// No recorded list but the host looks provisioned: a pre-tracking install.
	// Credit the frozen baseline, which is what its setup run actually covered.
	if s.IsProvisioned() {
		for _, p := range provisionBaseline {
			set[p] = true
		}
	}
	return set
}

// ProvisionedProtocolSet is the hook-facing view of provisionedProtocolSet —
// the seam value wired into procmgr.InstalledCoresFunc /
// manifest.InstalledCoresFunc (wire.go) and callable by later waves.
func ProvisionedProtocolSet() map[string]bool {
	var s CoreService
	return s.provisionedProtocolSet()
}

// coreInstallStateIsRecorded reports whether provisionedProtocolSet's answer came
// from something the panel actually WROTE DOWN, or from the baseline guess.
//
// The distinction exists because IsProvisioned() is not only a stored flag. With
// vpnProvisioned unset it falls back to a HEURISTIC:
//
//	procFileIsOne("/proc/sys/net/ipv4/ip_forward") && daemonInstalled("openvpn")
//
// and daemonInstalled is `commandExists(name) || bundle.DaemonPath(name) != ""`,
// i.e. a plain PATH lookup. So a box with a DISTRO openvpn and ip_forward=1 (any
// host that has ever run Docker, libvirt or a container runtime, and every
// router) reads as provisioned on a completely fresh panel database, and
// provisionedProtocolSet then credits it with the whole frozen baseline: l2tp,
// pptp, openvpn, openconnect.
//
// That is charitable and right for a pre-tracking upgrade, and exactly backwards
// for the pre-flight conflict probe, which is suppressed for a core the panel
// believes it installed. The presence of the very distro OpenVPN we would
// collide with was what silenced the warning about colliding with it, and the
// four cores it silenced are precisely the four whose shared config files needed
// backup-before-overwrite. Callers that ask "should I warn the operator about
// what is already on this host" must consult THIS, not IsProvisioned.
//
// Do not fold this back into provisionedProtocolSet as an "optimisation": the
// baseline fallback is correct for that function's other consumers (status
// cards, the inbound gate, uninstall's shared-requirement arithmetic), which
// need the charitable answer.
func (s *CoreService) coreInstallStateIsRecorded() bool {
	return HasRecordedProvisionedProtocols() || GetVpnProvisioned()
}

// MissingProtocols returns installable cores this host is NOT set up for. Since
// setup became per-core these are cores the operator has not installed (or has
// uninstalled), not a defect: the Core Settings page offers them under "Add
// core" rather than nagging about them.
func (s *CoreService) MissingProtocols() []string {
	if !s.IsProvisioned() {
		return nil
	}
	provisioned := s.provisionedProtocolSet()
	var missing []string
	for _, p := range installableCores() {
		if !provisioned[p] {
			missing = append(missing, p)
		}
	}
	return missing
}

// ProtocolNeedsSetup reports whether an inbound protocol's core still has to be
// installed before it can serve anything. Xray-native protocols map to no core
// and are never gated.
func (s *CoreService) ProtocolNeedsSetup(protocol string) bool {
	core := protocolCoreName(protocol)
	if core == "" {
		return false
	}
	return !s.provisionedProtocolSet()[core]
}

// --------------------------------------------------------------------------- //
//  Catalog read model (vpn-ui corecatalog.go:427-490)
// --------------------------------------------------------------------------- //

// CoreCatalog returns every core with its current install state, for the setup
// and uninstall dialogs.
func (s *CoreService) CoreCatalog() []CoreOption {
	installed := s.provisionedProtocolSet()
	counts := s.inboundCountsByCore()
	// Whether those "installed" answers are RECORDED or GUESSED. Read once: it is
	// two setting lookups and the loop below asks it per core.
	recorded := s.coreInstallStateIsRecorded()

	out := make([]CoreOption, 0, len(coreCatalog))
	for _, c := range coreCatalog {
		opt := CoreOption{
			Name:      c.name,
			Title:     c.title,
			Backend:   c.backend,
			Desc:      c.desc,
			Installed: c.builtin || installed[c.name],
			Inbounds:  counts[c.name],
			Shares:    sharersOf(c.name),
			Builtin:   c.builtin,
		}
		// Probed for a core the operator can still choose to install: once it really
		// is installed the artifacts are ours and the manifest is the record that
		// matters. "Really" is the load-bearing word; see coreShouldProbeConflicts.
		if coreShouldProbeConflicts(c.builtin, installed[c.name], recorded) {
			opt.Conflicts = coreConflictProbe(c.name)
		}
		out = append(out, opt)
	}
	return out
}

// inboundCountsByCore counts the inbounds each core currently serves. It reuses
// the same per-service getters the status cards use, so the two can never
// disagree about whether a core is in use.
func (s *CoreService) inboundCountsByCore() map[string]int {
	counts := map[string]int{}
	add := func(name string, n int, err error) {
		if err == nil {
			counts[name] = n
		}
	}
	l2tp, err := s.l2tp.GetL2tpInbounds()
	add("l2tp", len(l2tp), err)
	pptp, err := s.pptp.GetPptpInbounds()
	add("pptp", len(pptp), err)
	ovpn, err := s.openvpn.GetOpenVpnInbounds()
	add("openvpn", len(ovpn), err)
	oc, err := s.ocserv.GetOcservInbounds()
	add("openconnect", len(oc), err)
	sstp, err := s.sstp.GetSstpInbounds()
	add("sstp", len(sstp), err)
	ike, err := s.ikev2.GetIkev2Inbounds()
	add("ikev2", len(ike), err)
	wgc, err := s.wgc.GetWgcInbounds()
	add("wgc", len(wgc), err)
	awg, err := s.awg.GetAwgInbounds()
	add("awg", len(awg), err)
	gre, err := s.gre.GetGreInbounds()
	add("gre", len(gre), err)
	mt, err := s.mtproto.GetMtprotoInbounds()
	add("mtproto", len(mt), err)
	ssh, err := s.ssh.GetSshInbounds()
	add("ssh", len(ssh), err)
	return counts
}

// installedCoreNames is the set of cores this host is provisioned for, in
// catalog order.
func (s *CoreService) installedCoreNames() []string {
	return coreNamesFromSet(s.provisionedProtocolSet())
}

// coreNamesFromSet is installedCoreNames over an already-read set, so a caller
// that needs both the set and the list does not re-read the setting twice.
func coreNamesFromSet(set map[string]bool) []string {
	var out []string
	for _, c := range coreCatalog {
		if !c.builtin && set[c.name] {
			out = append(out, c.name)
		}
	}
	return out
}
