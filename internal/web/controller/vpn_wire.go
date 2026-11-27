package controller

// The VPN stack's wire-up: everything web.go needs to call, in one place.
//
// vpn-ui spread this across Server.startTask (web/web.go: OwnSynthesize → RADIUS
// start + SetRadius injection into 6 services → all 11 Init* → carriers → ssh
// outbound → vpnoutbound → RestartXray) plus seams into its in-package
// xrayService. The target keeps the same ORDER — the comments below are the
// source's reasoning, and reordering them is how a tunnel's first packet leaves in
// the clear — while the seams become explicit registrations filled from web.go
// (see WireVpnStack / WireVpnRuntimeSeams there).

import (
	"encoding/json"
	"net"

	"github.com/ImSoheilPx/pxpanel/internal/database"
	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/logger"
	"github.com/ImSoheilPx/pxpanel/internal/util/random"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/awg"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/coresettings"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/gre"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ikev2"
	vpncharon "github.com/ImSoheilPx/pxpanel/internal/vpn/ipsec"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/l2tp"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/mtproto"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ocserv"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/openvpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/pptp"
	vpnprocmgr "github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/radius"
	vpnrange "github.com/ImSoheilPx/pxpanel/internal/vpn/range"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/rbridge"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ssh"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/sstp"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/vpnout"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/wgc"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/xrayplane"
	"github.com/ImSoheilPx/pxpanel/internal/web/service"
)

// vpnRuntime bundles the stateful pieces the wire-up creates and the jobs need:
// the RADIUS server, the rbridge sweeper and the protocol services.
type vpnRuntime struct {
	radius  radius.RadiusService
	sweeper *rbridge.Sweeper
	sink    *radiusBridgeSink

	l2tp    l2tp.L2tpService
	pptp    pptp.PptpService
	openvpn openvpn.OpenVpnService
	ocserv  ocserv.OcservService
	sstp    sstp.SstpService
	ikev2   ikev2.Ikev2Service
	wgc     wgc.WgcService
	awg     awg.AwgService
	gre     gre.GreService
	mtproto mtproto.MtprotoService
	ssh     ssh.SshService

	sshOutbound ssh.SshOutboundService
	vpnOutbound vpnout.VpnOutboundService
}

// vpnRuntimeState guards the single vpnRuntime; the server may be constructed
// twice in tests (routes_contract_test's newTestEngine), and every Init* below is
// idempotent but the RADIUS listener is not.
var vpnRuntimeState *vpnRuntime

// VpnRuntime returns the wire-up state for the jobs; nil before WireVpnStack.
func VpnRuntime() *vpnRuntime { return vpnRuntimeState }

// VpnSweepHandles returns the RADIUS service and rbridge sweeper the traffic job
// needs (a zero-value service copy without the shared RADIUS instance silently
// no-ops every session kill — vpn-ui wired exactly this in NewXrayTrafficJob).
// Nil handles before WireVpnStack.
func VpnSweepHandles() (*radius.RadiusService, *rbridge.Sweeper) {
	if vpnRuntimeState == nil {
		return nil, nil
	}
	return &vpnRuntimeState.radius, vpnRuntimeState.sweeper
}

// VpnStopServices shuts the VPN stack down (vpn-ui Server.Stop → StopServices):
// the client-tunnel managers stop carried tunnels first (StopAll does that
// internally), the in-binary SSH gateway closes its listeners, charon goes down
// after ikev2/gre because their conns ride it, and the RADIUS listener closes
// last. Called from web.go's stop path; safe when nothing was wired.
func VpnStopServices() {
	if vpnRuntimeState == nil {
		return
	}
	rt := vpnRuntimeState
	rt.vpnOutbound.StopAll()
	rt.sshOutbound.StopAll()
	_ = rt.ssh.StopServices()
	_ = rt.ikev2.StopServices()
	_ = rt.gre.StopServices()
	if err := vpncharon.StopCharon(); err != nil {
		logger.Debug("vpn: stop charon on shutdown:", err)
	}
	rt.radius.Stop()
	vpnprocmgr.GetProcManager().StopAll()
}

// RegisterVpnProtocols attaches the per-protocol readers the shared registries ask
// each protocol wave to fill. Call once at server wire-up (after the DB handle is
// set); safe to call again.
//
// The explicit Register() seams live in openvpn/ikev2/ocserv/sstp; every other
// protocol registers from init(), which runs because this package (and therefore
// the binary) imports them via the vpnHooks/vpnRuntime field types.
func RegisterVpnProtocols() {
	openvpn.Register()
	ikev2.Register()
	ocserv.Register()
	sstp.Register()

	// The transport-aware OpenVPN reader for the email→IP map (vpn-ui radius.go
	// reached OpenVpnService's settings math directly; xrayplane keeps a registry
	// because routing.go must not import the openvpn internals).
	xrayplane.RegisterOpenVPNAddressMap(openvpnEmailIPMap)
}

// WireVpnStack runs the vpn-ui boot sequence in its original order. restartXray
// mirrors startTask's flag (false for panel-only starts). Returns the runtime the
// jobs need; a second call is a no-op.
func WireVpnStack(restartXray bool) *vpnRuntime {
	if vpnRuntimeState != nil {
		return vpnRuntimeState
	}
	rt := &vpnRuntime{}
	vpnRuntimeState = rt

	// Before ANY Init* below touches the host: work out what on this box was
	// already here and what the panel put here, and write it down. The Init*
	// calls create netdevs and rewrite shared config files, and the reconcilers
	// that follow delete whatever they believe is theirs, so the ownership record
	// has to exist first. See service/ownership.go (→ internal/vpn/manifest).
	manifest.OwnSynthesize()

	// Generate or load RADIUS shared secret and start the embedded RADIUS server.
	radiusSecret := getOrCreateRadiusSecret()
	if radiusSecret != "" {
		if err := rt.radius.Start(radiusSecret); err != nil {
			logger.Warning("RADIUS: failed to start:", err)
		}
		// Pass the RADIUS service (by pointer, so all of them share the one
		// instance whose mutex/session map the running RADIUS servers use) and
		// secret to the RADIUS-backed protocol services.
		rt.l2tp.SetRadius(&rt.radius, radiusSecret)
		rt.pptp.SetRadius(&rt.radius, radiusSecret)
		rt.openvpn.SetRadius(&rt.radius, radiusSecret)
		rt.ocserv.SetRadius(&rt.radius, radiusSecret)
		rt.sstp.SetRadius(&rt.radius, radiusSecret)
		rt.ikev2.SetRadius(&rt.radius, radiusSecret)
	}

	// Initialize L2TP/PPTP/OpenVPN/OpenConnect/SSTP services before Xray so
	// TPROXY/NAT rules are in place.
	rt.l2tp.InitL2tp()
	rt.pptp.InitPptp()
	rt.openvpn.InitOpenVpn()
	rt.ocserv.InitOcserv()
	rt.sstp.InitSstp()
	rt.ikev2.InitIkev2()
	rt.wgc.InitWgc()
	rt.awg.InitAwg()
	rt.gre.InitGre()
	rt.mtproto.InitMtproto()
	rt.ssh.InitSsh()

	// BEFORE anything dials, which is why it is here and not beside InitVpnOutbound
	// below. A carrier is a device plus a routing table, and whatever rides on it
	// sends its first packet the moment it starts: the SSH manager dials as soon
	// as its listener binds, and a WireGuard client hands its handshake to the
	// kernel the instant its peer is configured. A carrier made afterwards would
	// arrive after the packet it was meant to carry had already left in the clear.
	vpnout.InitVpnOutCarriers()
	rt.sshOutbound.InitSshOutbound()
	// Before RestartXray below, like every Init above it: the synthesized freedom
	// outbound binds to the netdev the client tunnel brings up, so the tunnel has
	// to exist by the time the core reads the config.
	rt.vpnOutbound.InitVpnOutbound()

	// The rbridge sweeper brings the non-RADIUS protocols (wg-c, awg, ikev2
	// psk/eap-tls, gre) into the same session/quota/evict/accounting model the
	// RADIUS protocols get. One sweeper, one Tick per traffic-collection cycle.
	rt.sink = newRadiusBridgeSink(&rt.radius)
	rt.sweeper = rbridge.New(rt.sink)
	rt.sweeper.Register(&rt.wgc)
	rt.sweeper.Register(&rt.awg)
	rt.sweeper.Register(&rt.ikev2)
	rt.sweeper.Register(&rt.gre)

	if restartXray {
		if err := restartXrayNow(true); err != nil {
			logger.Warning("start xray failed:", err)
		}
	}
	return rt
}

// WireVpnRuntimeSeams fills the seams the vpn packages reserved for the web layer.
// xrayService is the panel's XrayService; call before any VPN write path can run.
func WireVpnRuntimeSeams(xrayService *service.XrayService) {
	vpnXrayService = xrayService

	// xrayplane restart seams: RequestRestart(force) → a real restart NOW (vpn-ui's
	// in-package xrayService.RestartXray(force)); SetNeedRestartHook → the
	// scheduler's debounced restart (vpn-ui's SetToNeedRestart).
	xrayplane.SetRestartHook(restartXrayNow)
	xrayplane.SetNeedRestartHook(func() {
		if vpnRequestRestartHook != nil {
			vpnRequestRestartHook()
			return
		}
		if vpnXrayService != nil {
			vpnXrayService.SetToNeedRestart()
		}
	})

	// Online identities: the running core's session list feeds the accounts layer's
	// online sort through the accounts adapter (xrayplane.SetOnlineClientsSource
	// forwards to accounts.RegisterOnlineClientEmails — one registration covers
	// both consumers). Unwired, every account reads as offline.
	vpnOnlineClientsSource = func() []string {
		var inboundService service.InboundService
		return inboundService.GetOnlineClients()
	}
	xrayplane.SetOnlineClientsSource(vpnOnlineClientsSource)

	// Core Settings' Xray card seams (coresettings.XrayRunning/Version/Err/Result/
	// Stop): vpn-ui read its in-package xrayService directly; unwired, the card
	// reads "stopped" rather than inventing a lie.
	coresettings.XrayRunning = func() bool { return xrayService.IsXrayRunning() }
	coresettings.XrayVersion = func() string { return xrayService.GetXrayVersion() }
	coresettings.XrayErr = xrayService.GetXrayErr
	coresettings.XrayResult = xrayService.GetXrayResult
	coresettings.XrayStop = xrayService.StopXray

	// The controller-side restart hook shares the scheduler path: a vpn edit asks
	// for exactly what the SPA's own edits ask for.
	vpnRequestRestartHook = func() {
		if vpnXrayService != nil {
			vpnXrayService.SetToNeedRestart()
		}
	}
}

// restartXrayNow restarts the core through the web service. force mirrors
// XrayService.RestartXray's flag.
func restartXrayNow(force bool) error {
	if vpnXrayService == nil {
		return nil
	}
	return vpnXrayService.RestartXray(force)
}

// radiusSecretKey is the settings-KV row the embedded RADIUS server's shared
// secret lives under (vpn-ui SettingService key of the same name).
const radiusSecretKey = "radiusSecret"

// getOrCreateRadiusSecret returns the shared RADIUS secret, minting one on first
// use (vpn-ui getOrCreateRadiusSecret). The settings KV is the same model.Setting
// table the panel already uses, reached directly because SettingService keeps its
// generic getter/setter unexported.
func getOrCreateRadiusSecret() string {
	db := database.GetDB()
	if db == nil {
		return ""
	}
	setting := &model.Setting{}
	if err := db.Model(model.Setting{}).Where("`key` = ?", radiusSecretKey).First(setting).Error; err == nil && setting.Value != "" {
		return setting.Value
	}
	// 24 bytes is 192 bits of secret; base64 makes it a printable settings value.
	generated := random.Base64Bytes(24)
	if generated == "" {
		logger.Warning("RADIUS: could not generate a shared secret")
		return ""
	}
	row := &model.Setting{Key: radiusSecretKey, Value: generated}
	if err := db.Create(row).Error; err != nil {
		logger.Warning("RADIUS: could not store the generated shared secret:", err)
		return ""
	}
	return generated
}

// radiusBridgeSink adapts the RADIUS service to rbridge.Sink: the sweeper folds
// the non-RADIUS protocols' sessions into the SAME reconciled model the RADIUS
// protocols get (session registry + nft accounting via ReconcileLocalSessions;
// quota/disable enforcement through DisabledEmails).
type radiusBridgeSink struct {
	radius *radius.RadiusService
}

func newRadiusBridgeSink(rs *radius.RadiusService) *radiusBridgeSink {
	return &radiusBridgeSink{radius: rs}
}

func (s *radiusBridgeSink) ReconcileLocalSessions(protocol string, desired map[string]rbridge.Reconciled) {
	s.radius.ReconcileLocalSessions(protocol, desired)
}

func (s *radiusBridgeSink) DisabledEmails() map[string]bool {
	return s.radius.DisabledEmails()
}

// openvpnSettingsJSON is the slice of OpenVPN's settings shape the email→IP map
// needs. Mirrors the openvpn package's internal openvpnSettings fields (the map
// cannot call the unexported parse, so the shape is restated here — vpn-ui
// restated it in radius.go for the same reason).
type openvpnSettingsJSON struct {
	IpRanges  []string `json:"ipRanges"`  // UDP-side /24 ranges; TCP mirrors into 10.3.x
	IpRange   string   `json:"ipRange"`   // legacy single-range spelling
	UdpEnable *bool    `json:"udpEnable"` // nil = enabled
	TcpEnable *bool    `json:"tcpEnable"` // nil = enabled
	UserLimit *int     `json:"userLimit"` // nil = absent (legacy => 1); 0 = no limit
	Clients   []struct {
		Email string `json:"email"`
		Slot  *int   `json:"slot"`
	} `json:"clients"`
}

func (s *openvpnSettingsJSON) effectiveRanges() []string {
	if len(s.IpRanges) > 0 {
		return s.IpRanges
	}
	if s.IpRange != "" {
		return []string{s.IpRange}
	}
	return nil
}

func (s *openvpnSettingsJSON) udpEnabled() bool { return s.UdpEnable == nil || *s.UdpEnable }
func (s *openvpnSettingsJSON) tcpEnabled() bool { return s.TcpEnable == nil || *s.TcpEnable }

// openvpnEmailIPMap produces the OpenVPN part of the email→IP map: one
// deterministic CCD IP per enabled transport block (udp 10.2.x, tcp 10.3.x
// mirror), K device IPs per account when the User Limit says so
// (vpn-ui radius.go's OpenVPN section, over vpnrange's exported block math).
func openvpnEmailIPMap() map[string][]string {
	result := make(map[string][]string)
	var inboundService service.InboundService
	inbounds, err := inboundService.GetAllInbounds()
	if err != nil {
		return result
	}
	for _, inbound := range inbounds {
		if inbound.Protocol != protoOpenVPN || !inbound.Enable {
			continue
		}
		var settings openvpnSettingsJSON
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			continue
		}
		ranges := settings.effectiveRanges()
		k := vpnrange.EffectiveUserLimit(settings.UserLimit)
		udpOn := settings.udpEnabled()
		tcpOn := settings.tcpEnabled()
		var udpNet, tcpNet net.IP
		var udpPrefix, tcpPrefix int
		if udpOn {
			udpNet, udpPrefix = vpnrange.OvpnBlock(ranges, "udp", inbound.Id)
		}
		if tcpOn {
			tcpNet, tcpPrefix = vpnrange.OvpnBlock(ranges, "tcp", inbound.Id)
		}
		for i, client := range settings.Clients {
			if client.Email == "" {
				continue
			}
			slot := vpnrange.SlotOr(client.Slot, i)
			if udpOn {
				if k <= 1 {
					result[client.Email] = append(result[client.Email],
						vpnrange.OvpnBlockClientIP(udpNet, udpPrefix, slot))
				} else {
					for d := 0; d < k; d++ {
						result[client.Email] = append(result[client.Email],
							vpnrange.OvpnBlockClientIP(udpNet, udpPrefix, slot*k+d))
					}
				}
			}
			if tcpOn {
				if k <= 1 {
					result[client.Email] = append(result[client.Email],
						vpnrange.OvpnBlockClientIP(tcpNet, tcpPrefix, slot))
				} else {
					for d := 0; d < k; d++ {
						result[client.Email] = append(result[client.Email],
							vpnrange.OvpnBlockClientIP(tcpNet, tcpPrefix, slot*k+d))
					}
				}
			}
		}
	}
	return result
}
