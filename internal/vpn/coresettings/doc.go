// Package coresettings is vpn-ui's Core Settings service (web/service/core.go +
// corecatalog.go + coreuninstall.go + preflight.go + bootloader.go + the
// settings-adjacent halves of setting.go), ported as the ONE declarative core
// catalog and everything that reads it:
//
//	catalog    what each installable VPN core needs from the host (modules,
//	           daemons, provisioning features, owned paths, shared feats)
//	status     per-core status cards + the system/kernel card, against the
//	           recorded installed set
//	provision  the host/kernel preparation no bundled binary can do (modules,
//	           forwarding, rp_filter, nftables/iproute2, kernel packages with
//	           bootloader pin, DKMS AWG, bundle extraction via the seam)
//	control    RestartCore / RestartAll / StopCore / CoreLogs
//	uninstall  reference-counted per-core uninstall (safe because every
//	           "may I remove this shared thing?" question is asked of what
//	           REMAINS installed)
//
// THE CATALOG IS THE SOURCE (vpn-ui corecatalog.go's design comment, kept):
// setup used to be all-or-nothing, running every step for every protocol. The
// catalog replaces that with one declarative row per core which provisioning,
// the status card and uninstall all read; shared requirements are named feats
// (ipsec is claimed by BOTH l2tp and ikev2), so "remove ikev2" can see that
// l2tp still claims strongSwan and leave the bundle alone.
//
// ADAPTATIONS (import rewrite + seams, per the port rules):
//   - SettingService vpnProvisioned / provisionedProtocols became direct
//     model.Setting KV rows (settings.go; the settings service is a later wave).
//   - backend.* (bundle embeds) became the procmgr.BundleProvider seam; the
//     extraction steps honest-skip until the bundle/build wave lands.
//   - ensureAmneziawg/removeAmneziawgModule became awg.EnsureAmneziawgModule /
//     awg.RemoveAmneziawgModule (the awg wave's exports).
//   - own* ownership calls became manifest.* (Claim/Prepare*/Release/ReleasePath).
//   - procMgr became procmgr.GetProcManager(); xray control goes through
//     xrayplane.RequestRestart plus the local Xray status seam (internal/vpn
//     cannot import internal/web).
//   - vpn-ui product paths /etc/vpn-ui-sstp, /etc/vpn-ui-mtproto,
//     /etc/vpn-ui-ikev2, /etc/modules-load.d/vpn-ui.conf,
//     /etc/sysctl.d/99-vpn-ui.conf carry the product rename the target's
//     protocol waves already use: /etc/pxpanel-sstp, /etc/pxpanel/mtproto,
//     /etc/pxpanel-ikev2, /etc/modules-load.d/pxpanel.conf,
//     /etc/sysctl.d/99-pxpanel.conf.
//
// init() wires the foundation seams the README reserved for this wave:
// procmgr.InstalledCoresFunc, manifest.InstalledCoresFunc and
// manifest.CoreArtifactPathsFunc (see wire.go).
//
// Deferred to later waves, deliberately: the controller endpoints
// (GET/POST /core/...) and the config-editor save/health flow (both the
// controllers wave — the storage/catalog seam already lives in
// internal/vpn/coreconfig), RefreshInstalledDaemons (needs the bundle layer's
// ExtractOnly), and coreattribution.go (Xray traffic attribution — it belongs
// to the traffic job wave, not core settings).
package coresettings
