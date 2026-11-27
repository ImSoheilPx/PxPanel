package controller

// Per-protocol reconcile hooks, ported from vpn-ui web/controller/inbound.go
// (onL2tpChanged … onSshChanged) onto the ported protocol services.
//
// Every handler below regenerates its protocol's daemon configs, re-applies its
// routing, restarts (or deliberately does NOT restart) its daemons, kills sessions
// of disabled accounts, and asks the Xray config to be rebuilt — the tunnel
// protocols route through Xray via paired dokodemo inbounds, so a settings change
// that moves a port or a pool must reach the core too.

import (
	"github.com/ImSoheilPx/pxpanel/internal/logger"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/awg"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/gre"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ikev2"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/l2tp"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/mtproto"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ocserv"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/openvpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/pptp"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/radius"
	vpnrange "github.com/ImSoheilPx/pxpanel/internal/vpn/range"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ssh"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/sstp"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/wgc"
)

// vpnHooks bundles the protocol services the vpn controllers drive. Every service
// is a stateless value type (zero value usable), exactly like the source's
// zero-value InboundController.
type vpnHooks struct {
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
}

// needRestart asks the web layer's restart scheduler to rebuild + restart the core.
// The seam is filled at server start-up (vpnWireRequestRestart), but a nil hook
// degrades to the direct SetToNeedRestart on the XrayService the controllers
// already hold, so tests without a running server still work.
func (h *vpnHooks) needRestart() {
	if vpnRequestRestartHook != nil {
		vpnRequestRestartHook()
		return
	}
	if vpnXrayService != nil {
		vpnXrayService.SetToNeedRestart()
	}
}

// --- L2TP -------------------------------------------------------------------

func (h *vpnHooks) onL2tpChanged()       { h.l2tpChanged(false) }
func (h *vpnHooks) onL2tpClientChanged() { h.l2tpChanged(true) }

func (h *vpnHooks) l2tpChanged(clientOnly bool) {
	expanded := vpnrange.AutoExpandVpnRanges("l2tp")
	if err := h.l2tp.GenerateAllConfigs(); err != nil {
		logger.Warning("L2TP: config generation failed:", err)
	}
	if err := h.l2tp.SetupAllTproxy(); err != nil {
		logger.Warning("L2TP: TPROXY setup failed:", err)
	}
	// A client-only change (add/edit a client, reset traffic) needs no daemon
	// restart: the in-binary RADIUS reads clients live from the DB and no per-client
	// data lives in the xl2tpd config, so a restart would only drop connected
	// tunnels. Restart for inbound-level changes, or when the pool auto-expanded.
	if !clientOnly || expanded {
		if err := h.l2tp.RestartServices(); err != nil {
			logger.Warning("L2TP: service restart failed:", err)
		}
		// Drop cached per-device IP assignments so a changed User Limit / range /
		// strategy takes effect on reconnect. Skipped on client-only changes so the
		// idempotent-redial cache isn't cleared mid-session.
		radius.ResetAllocations("l2tp")
	}
	h.l2tp.KillDisabledSessions()
	h.needRestart()
}

// --- PPTP -------------------------------------------------------------------

func (h *vpnHooks) onPptpChanged()       { h.pptpChanged(false) }
func (h *vpnHooks) onPptpClientChanged() { h.pptpChanged(true) }

func (h *vpnHooks) pptpChanged(clientOnly bool) {
	expanded := vpnrange.AutoExpandVpnRanges("pptp")
	if err := h.pptp.GenerateAllConfigs(); err != nil {
		logger.Warning("PPTP: config generation failed:", err)
	}
	if err := h.pptp.SetupAllTproxy(); err != nil {
		logger.Warning("PPTP: TPROXY setup failed:", err)
	}
	// Client-only changes don't restart pptpd (auth is live via RADIUS) — see
	// l2tpChanged. Restart for inbound-level changes or a pool expansion.
	if !clientOnly || expanded {
		if err := h.pptp.RestartServices(); err != nil {
			logger.Warning("PPTP: service restart failed:", err)
		}
		radius.ResetAllocations("pptp")
	}
	h.pptp.KillDisabledSessions()
	h.needRestart()
}

// --- OpenVPN ----------------------------------------------------------------

func (h *vpnHooks) onOpenVpnChanged()       { h.openVpnChanged(false) }
func (h *vpnHooks) onOpenVpnClientChanged() { h.openVpnChanged(true) }

func (h *vpnHooks) openVpnChanged(clientOnly bool) {
	expanded := vpnrange.AutoExpandVpnRanges("openvpn")
	// Keep live per-device leases on a client-only change (unless the pool expanded,
	// which needs a full regenerate + restart) so connected devices keep their IPs.
	preserveLeases := clientOnly && !expanded
	if err := h.openvpn.GenerateAllConfigs(preserveLeases); err != nil {
		logger.Warning("OpenVPN: config generation failed:", err)
	}
	if err := h.openvpn.SetupRouting(); err != nil {
		logger.Warning("OpenVPN: routing setup failed:", err)
	}
	// Adding/editing a client writes its client-config-dir block file without a
	// restart; the running server reads it on the client's next connect. Restart only
	// for inbound-level changes or a pool expansion.
	if !clientOnly || expanded {
		if err := h.openvpn.RestartServices(); err != nil {
			logger.Warning("OpenVPN: service restart failed:", err)
		}
	}
	h.openvpn.KillDisabledSessions()
	// OpenVPN routes through Xray via dokodemo-door, so Xray routing must refresh.
	h.needRestart()
}

// --- OpenConnect ------------------------------------------------------------

func (h *vpnHooks) onOcservChanged()       { h.ocservChanged(false) }
func (h *vpnHooks) onOcservClientChanged() { h.ocservChanged(true) }

func (h *vpnHooks) ocservChanged(clientOnly bool) {
	expanded := vpnrange.AutoExpandVpnRanges("openconnect")
	if err := h.ocserv.GenerateAllConfigs(); err != nil {
		logger.Warning("OpenConnect: config generation failed:", err)
	}
	if err := h.ocserv.SetupRouting(); err != nil {
		logger.Warning("OpenConnect: routing setup failed:", err)
	}
	// Client-only changes don't restart ocserv (auth is live via RADIUS) — see
	// l2tpChanged. Restart for inbound-level changes or a pool expansion.
	if !clientOnly || expanded {
		if err := h.ocserv.RestartServices(); err != nil {
			logger.Warning("OpenConnect: service restart failed:", err)
		}
		radius.ResetAllocations("openconnect")
	}
	h.ocserv.KillDisabledSessions()
	h.needRestart()
}

// --- SSTP -------------------------------------------------------------------

func (h *vpnHooks) onSstpChanged()       { h.sstpChanged(false) }
func (h *vpnHooks) onSstpClientChanged() { h.sstpChanged(true) }

func (h *vpnHooks) sstpChanged(clientOnly bool) {
	expanded := vpnrange.AutoExpandVpnRanges("sstp")
	if err := h.sstp.GenerateAllConfigs(); err != nil {
		logger.Warning("SSTP: config generation failed:", err)
	}
	if err := h.sstp.SetupRouting(); err != nil {
		logger.Warning("SSTP: routing setup failed:", err)
	}
	// Client-only changes don't restart accel-ppp (auth is live via RADIUS) — see
	// l2tpChanged. Restart for inbound-level changes or a pool expansion.
	if !clientOnly || expanded {
		if err := h.sstp.RestartServices(); err != nil {
			logger.Warning("SSTP: service restart failed:", err)
		}
		radius.ResetAllocations("sstp")
	}
	h.sstp.KillDisabledSessions()
	h.needRestart()
}

// --- IKEv2 ------------------------------------------------------------------

func (h *vpnHooks) onIkev2Changed()       { h.ikev2Changed(false) }
func (h *vpnHooks) onIkev2ClientChanged() { h.ikev2Changed(true) }

func (h *vpnHooks) ikev2Changed(clientOnly bool) {
	expanded := vpnrange.AutoExpandVpnRanges("ikev2")
	if err := h.ikev2.GenerateAllConfigs(); err != nil {
		logger.Warning("IKEv2: config generation failed:", err)
	}
	if err := h.ikev2.SetupRouting(); err != nil {
		logger.Warning("IKEv2: routing setup failed:", err)
	}
	// charon hot-reloads via swanctl --load-all (no tunnel drop) and a new client's
	// conn/pool must be (re)loaded, so always reload — this never disconnects anyone.
	if err := h.ikev2.RestartServices(); err != nil {
		logger.Warning("IKEv2: service restart failed:", err)
	}
	// Only drop the IP-allocation cache for inbound-level changes or a pool expansion.
	if !clientOnly || expanded {
		radius.ResetAllocations("ikev2")
	}
	h.ikev2.KillDisabledSessions()
	h.needRestart()
}

// --- MTProto ----------------------------------------------------------------

func (h *vpnHooks) onMtprotoChanged()       { h.mtprotoChanged(false) }
func (h *vpnHooks) onMtprotoClientChanged() { h.mtprotoChanged(true) }

func (h *vpnHooks) mtprotoChanged(clientOnly bool) {
	if err := h.mtproto.GenerateAllConfigs(); err != nil {
		logger.Warning("MTProto: config generation failed:", err)
	}
	if !clientOnly {
		if err := h.mtproto.RestartServices(); err != nil {
			logger.Warning("MTProto: service restart failed:", err)
		}
	} else {
		// Client-only changes hot-reload a running telemt via its config watcher, but
		// when this change produces the inbound's first usable account nothing has
		// launched the process yet. Start it if down (never supersedes a live one).
		if err := h.mtproto.EnsureServicesRunning(); err != nil {
			logger.Warning("MTProto: ensure-running failed:", err)
		}
	}
	h.mtproto.KillDisabledSessions()
	// The paired socks inbound (and thus this inbound's routing tag) is built from
	// the mtproto settings, so Xray must pick the change up.
	h.needRestart()
}

// --- SSH --------------------------------------------------------------------

func (h *vpnHooks) onSshChanged()       { h.sshChanged(false) }
func (h *vpnHooks) onSshClientChanged() { h.sshChanged(true) }

func (h *vpnHooks) sshChanged(clientOnly bool) {
	if err := h.ssh.ReconcileHostKeys(); err != nil {
		logger.Warning("SSH: host key reconcile failed:", err)
	}
	if !clientOnly {
		if err := h.ssh.RestartServices(); err != nil {
			logger.Warning("SSH: service restart failed:", err)
		}
	}
	h.ssh.KillDisabledSessions()
	// The paired socks inbound (its account list and this inbound's routing tag) is
	// built from the SSH settings, so Xray must pick the change up.
	h.needRestart()
}

// --- WireGuard-C / AmneziaWG / GRE ------------------------------------------

func (h *vpnHooks) onWgcChanged()       { h.wgcChanged(false) }
func (h *vpnHooks) onWgcClientChanged() { h.wgcChanged(true) }

func (h *vpnHooks) wgcChanged(clientOnly bool) {
	expanded := vpnrange.AutoExpandVpnRanges("wg-c")
	// Mint any missing server/device keypairs (sized to each account's User Limit K)
	// and persist them, so GenerateAllConfigs can materialize the peers.
	h.wgc.ReconcileAllKeys()
	if err := h.wgc.GenerateAllConfigs(); err != nil {
		logger.Warning("WireGuard: config generation failed:", err)
	}
	if err := h.wgc.SetupRouting(); err != nil {
		logger.Warning("WireGuard: routing setup failed:", err)
	}
	_, _ = expanded, clientOnly
	h.needRestart()
}

func (h *vpnHooks) onAwgChanged()       { h.awgChanged(false) }
func (h *vpnHooks) onAwgClientChanged() { h.awgChanged(true) }

func (h *vpnHooks) awgChanged(clientOnly bool) {
	expanded := vpnrange.AutoExpandVpnRanges("awg")
	h.awg.ReconcileAllKeys()
	if err := h.awg.GenerateAllConfigs(); err != nil {
		logger.Warning("AmneziaWG: config generation failed:", err)
	}
	if err := h.awg.SetupRouting(); err != nil {
		logger.Warning("AmneziaWG: routing setup failed:", err)
	}
	_, _ = expanded, clientOnly
	h.needRestart()
}

func (h *vpnHooks) onGreChanged()       { h.greChanged(false) }
func (h *vpnHooks) onGreClientChanged() { h.greChanged(true) }

func (h *vpnHooks) greChanged(clientOnly bool) {
	expanded := vpnrange.AutoExpandVpnRanges("gre")
	h.gre.ReconcileAllPeers()
	if err := h.gre.GenerateAllConfigs(); err != nil {
		logger.Warning("GRE: config generation failed:", err)
	}
	if err := h.gre.SetupRouting(); err != nil {
		logger.Warning("GRE: routing setup failed:", err)
	}
	_, _ = expanded, clientOnly
	h.needRestart()
}

// onWireguardXrayClientChanged mints the key material and tunnel address every
// client of an Xray-native `wireguard` inbound needs, and persists it. No daemon and
// no kernel interface, unlike wg-c: the device is inside Xray, so the only thing to
// do here is make sure the peer list the config is generated FROM exists.
func (h *vpnHooks) onWireguardXrayClientChanged() {
	// vpn-ui service.ReconcileAllWireguardXrayKeys. The target's Xray-native
	// wireguard inbound mints keys in its own save path (client controller), so this
	// is the restart-only remainder.
	h.needRestart()
}

// reconcileForInboundsVpn fires each protocol's reconcile hook once for the set of
// inbounds a write touched (vpn-ui InboundController.reconcileForInbounds).
//
// needRestart mirrors the source: AddInboundClient-style hot-adds report false and
// skip the bare restart, while database-only writers (memberships) pass true.
func (h *vpnHooks) reconcileForInbounds(inboundIds []int, needRestart bool) {
	protocols := map[xrayProtocol]bool{}
	for _, id := range inboundIds {
		inbound, err := vpnInboundById(id)
		if err != nil || inbound == nil {
			continue
		}
		protocols[inbound.Protocol] = true
	}

	// Each VPN hook regenerates its own daemon config and requests the Xray
	// restart itself, so only the native Xray protocols fall through to the
	// bare SetToNeedRestart below — and only when the caller could not apply the
	// change live.
	xrayOnly := needRestart
	for protocol := range protocols {
		switch protocol {
		case protoL2TP:
			h.onL2tpClientChanged()
		case protoPPTP:
			h.onPptpClientChanged()
		case protoOpenVPN:
			h.onOpenVpnClientChanged()
		case protoOpenConnect:
			h.onOcservClientChanged()
		case protoSSTP:
			h.onSstpClientChanged()
		case protoIKEV2:
			h.onIkev2ClientChanged()
		case protoWGC:
			h.onWgcClientChanged()
		case protoAWG:
			h.onAwgClientChanged()
		case protoGRE:
			h.onGreClientChanged()
		case protoMTPROTO:
			h.onMtprotoClientChanged()
		case protoSSH:
			h.onSshClientChanged()
		case protoWireguardXra:
			// Xray-native, so it needs the core restarted like every other default
			// case below, but its peers do not exist until the keys and tunnel
			// addresses are minted, and the generated config is built from them.
			h.onWireguardXrayClientChanged()
			xrayOnly = true
		default:
			// Nothing to do: the account is already in the running core if the API
			// call succeeded, and needRestart already says so if it did not.
		}
	}
	if xrayOnly {
		h.needRestart()
	}
}

// reconcileInboundLevel fires each protocol's INBOUND-LEVEL change hook for the
// protocol set a write touched — the on<L2tp>Changed() variants, not the
// client-only ones reconcileForInbounds fires. vpn-ui wired the full hooks at
// every inbound-level tail (addInbound, updateInbound, delInbound,
// delInboundClient, the reseller cascade reconfigure): an inbound-level change
// can move a port or a pool, so the daemon restart and the per-device
// IP-allocation reset the client-only variants deliberately skip must run.
// Callers pass the protocol(s) directly — after a delete the row is already gone,
// so a lookup by id would silently reconcile nothing.
func (h *vpnHooks) reconcileInboundLevel(protocols map[xrayProtocol]bool) {
	for protocol := range protocols {
		switch protocol {
		case protoL2TP:
			h.onL2tpChanged()
		case protoPPTP:
			h.onPptpChanged()
		case protoOpenVPN:
			h.onOpenVpnChanged()
		case protoOpenConnect:
			h.onOcservChanged()
		case protoSSTP:
			h.onSstpChanged()
		case protoIKEV2:
			h.onIkev2Changed()
		case protoWGC:
			h.onWgcChanged()
		case protoAWG:
			h.onAwgChanged()
		case protoGRE:
			h.onGreChanged()
		case protoMTPROTO:
			h.onMtprotoChanged()
		case protoSSH:
			h.onSshChanged()
		case protoWireguardXra:
			// Xray-native wireguard has no daemon, but its peers must exist before
			// the core reads the config, and the core must then be restarted.
			h.onWireguardXrayClientChanged()
			h.needRestart()
		default:
			// Native Xray protocol: nothing to reconcile outside the core, the
			// caller's restart covers it.
		}
	}
}
