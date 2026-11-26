// Package vpnout is the VPN-protocol OUTBOUND family: the panel dials out as a
// CLIENT of somebody else's VPN server, the client driver brings up a netdev
// (wg/amneziawg/gre/tun/ppp/xfrm), and Xray egresses through it via a
// synthesized `freedom` outbound whose socket is pinned to that netdev with
// SO_BINDTODEVICE (streamSettings.sockopt.interface). The mirror image of the
// inbound tunnel protocols, where the panel is the server.
//
// Provenance: ported from vpn-ui (Sir-MmD/vpn-ui, a 3x-ui v2.9.3 fork)
// web/service/vpnoutbound.go + vpnoutcarrier.go + vpnoutvia.go (the framework)
// and vpnout_wireguard.go / vpnout_awg.go / vpnout_gre.go / vpnout_openvpn.go /
// vpnout_openconnect.go / vpnout_sstp.go / vpnout_ikev2.go (the drivers),
// verbatim where possible, with the following mechanical adaptations:
//
//   - logger            → internal/vpn/log (imported as `logger`).
//   - xray + json_util  → internal/xray + internal/util/json_util.
//   - SettingService getString/setString/GetXrayConfigTemplate → local seams
//     (vpnout_settings.go) over vpn.DB(); the template lives in the same
//     `xrayTemplateConfig` settings row.
//   - XrayService.SetToNeedRestart → xrayplane.RequestNeedRestart; the restart
//     path additionally calls ReassertCarriers after the core is up (vpn-ui:
//     RestartXray → vpnOutReassertCarriers).
//   - SshOutboundService (same package in vpn-ui) → internal/vpn/ssh.
//   - backend.* bundle reads (client binaries, vpnc-script, sstpc + pppd
//     plugin) → vpnout_clients.go seams over procmgr.Bundles(), inert-but-
//     honest defaults until the bundle wave extends the BundleProvider with
//     client accessors. TODO(bundle wave) there.
//   - wgc.go / awg.go / gre.go / ifaceown.go / core.go helpers the drivers
//     shared with the inbound services → carried locally (vpnout_wgshared.go,
//     vpnout_grehost.go, vpnout_pppshared.go), since the target keeps those
//     unexported in their own packages. Manifest ownership uses the SAME
//     kinds/core tags as the inbound sides.
//   - charon's write/ensure/reload three-step (vpn-ui called it in-package) →
//     carried locally in vpnout_charon.go over procmgr/manifest/coreconfig,
//     keyed on the same "ikev2" proc name and /etc/swanctl paths as the
//     inbound copies. TODO(ipsec promotion wave): fold the three copies.
//   - OpenVpnService/GreService receiver members the drivers used → small
//     local stand-ins (ovpnOutHost, greOutHost).
//   - vpnOutboundNeedsCharon → vpnout_need.go + WireCharonNeed, registered
//     with ikev2.SetVpnOutboundNeedHook and ipsec.RegisterCharonNeeder.
//   - THE VANILLA-CORE GATE: vpn-ui's bundled core exposed patched-core
//     protocols. This target runs a stock xray-core, and the one shape here
//     that depends on a protocol outside the vanilla set is the bridged
//     carrier's `tun` INBOUND (vpnoutcarrier.go). It is gated at resolution
//     behind a runtime probe of the installed core (vpnout_corecap.go,
//     xray.CheckConfig against a minimal tun inbound) and refused with an
//     operator-readable sentence when the core lacks it. The framework's own
//     mechanism — freedom outbounds pinned to a netdev via sockopt.interface —
//     is vanilla-supported and ungated.
//
// Boot sequence (vpn-ui runWebServer/startTask): InitVpnOutCarriers FIRST,
// then ssh outbound init, then VpnOutboundService.InitVpnOutbound. On shutdown
// StopAll — carried tunnels first, which it does internally. The xray config
// build calls ApplyVpnOutboundsWith and ApplyCarrierBridgesWith (the ssh wave's
// ApplySshOutboundsWith pattern) with the stored tunnel list.
//
// pptp and l2tp outbounds (vpnout_pptp.go / vpnout_l2tp.go) are a later wave;
// they land in THIS package and reuse the ppp-device helpers here
// (vpnout_pppshared.go), exactly as vpn-ui's drivers shared them.
package vpnout
