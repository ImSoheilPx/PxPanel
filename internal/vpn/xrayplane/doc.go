// Package xrayplane is the VPN-side extension plane for the running Xray core:
// the paired-inbound machinery that lets the VPN protocols (the vpn-ui lineage)
// ride the panel's core for routing and accounting.
//
// Provenance. Ported from vpn-ui (github.com/mhsanaei/3x-ui/v2 fork):
//
//   - xray/api.go fork-account section (anytls/tuic/naive) -> forkaccount.go.
//     The panel links the published xray-core module; those three account
//     messages live only in the patched core binary, so they are hand-encoded.
//   - xray/api.go traffic parsing DELTA (direction-keyed aggregation,
//     CoreCounted user stats) -> traffic.go. The target's internal/xray keeps
//     the older tag-keyed parser for its own lineage; the vpn traffic job uses
//     the vpn-ui one, which keeps an inbound and an outbound that share a tag
//     in separate records.
//   - xray/process.go speed-limit sidecar path -> sidecar.go.
//   - web/service/xray.go pairing half of GetXrayConfig + the per-protocol
//     GetDokodemoConfig/GetSocksConfig helpers (l2tp.go, pptp.go, openvpn.go,
//     openconnect.go, sstp.go, ikev2.go, wgc.go, awg.go, gre.go, mtproto.go,
//     ssh.go) -> pairing.go / relayaccounts.go / inject.go. The nine tunnel
//     protocols' GetDokodemoConfig bodies are byte-identical and collapse into
//     one builder; the two relays keep their named shapes.
//   - web/service/xray.go translateVpnRoutingRules + web/service/radius.go
//     BuildVpnEmailToIPMap -> routing.go (the email->IP map needs only the
//     vpnrange block math for the PPP family; OpenVPN's transport-aware reader
//     is registered by its own wave).
//   - web/service/xray.go restart request hooks -> restart.go, as seams into
//     the web layer's own restart machinery (internal/web already ships the
//     3x-ui-lineage XrayService; the vpn side only asks, never manages the
//     process).
//
// NOT ported: the rest of vpn-ui's xray/ package (Config, InboundConfig,
// XrayAPI, Process, LogWriter, GetAccessLogPath &c). The target already ships
// that surface as internal/xray (a NEWER 3x-ui v2 lineage: hot-diff, node
// trees, delta-based GetTraffic). This package imports those types instead of
// redefining them, so there is exactly one Xray config graph on the panel.
//
// Seams kept free of internal/web (import cycle) and internal/database (cgo on
// cross-builds): the gorm handle arrives through vpn.DB(), relay account
// readers and the restart hook are registered, and the per-protocol services
// override the default relay readers when their waves land.
//
// TODO(controllers wave):
//   - wire SetRestartHook / SetNeedRestartHook to the web XrayService
//     (RestartXray / SetToNeedRestart) at server start-up; relay account
//     changes MUST raise SetToNeedRestart - a socks inbound has no AddUser API,
//     so its account list is fixed at config time (see restart.go).
//   - wire SetOnlineClientsSource to the core process's online list (feeds the
//     accounts layer's online sort through the accounts adapter).
//   - call InjectPairedInbounds from the vpn-side config build, after the
//     Xray-native inbounds are rendered and before routing translation
//     (TranslateVpnRoutingRules runs LAST: it also appends the blackhole
//     backstop, which must stay behind every operator rule).
//   - traffic job wave: use ParseTrafficStat/ProcessTraffic/ProcessClientTraffic
//     for the vpn-side sweep; records with no inbound placement must stay
//     unattributed (the CoreCounted flag of vpn-ui - carried here as doc only,
//     the target ClientTraffic has no such field; the job wave owns attribution).
//   - speedlimit wave: attach SpeedLimitEnv() to the core process env at start
//     (internal/xray.Start has no hook for it yet) and keep rate changes OUT of
//     the xray.Config graph - see sidecar.go.
//   - openvpn wave: RegisterOpenVPNAddressMap with the per-transport reader
//     (BuildVpnEmailToIPMap skips OpenVPN until then).
//   - mtproto/ssh waves: optionally replace the default relay account readers
//     via RegisterRelayAccounts (defaults already read the stored JSON shapes).
//   - per-protocol services keep their vpn-ui method names (e.g.
//     (L2tpService).GetDokodemoConfig) as one-line delegates to
//     GetDokodemoConfig/TproxyPort here.
package xrayplane
