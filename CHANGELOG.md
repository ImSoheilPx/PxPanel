# Changelog

## 1.0.2

- Inbound form unification: VPN protocols are now configured inside the standard Add/Modify Inbound dialog (same tabs and Basics fields, per-field tooltips); the separate VPN dialog was removed and the protocol picker no longer shows a group-sentinel item.
- Inbound row actions for VPN protocols now match the native set exactly: Inbound Information, Export Inbound, Reset Traffic, Clone, Delete; bulk delete now settles VPN accounts and the reseller ledger per inbound; VPN inbound clones re-allocate fresh address ranges.
- Routing: panel xray routing rules now apply to all VPN protocol traffic (single nftables steering registry; OpenVPN/OpenConnect registered; SSH hostname passthrough pinned by tests). MTProto egresses directly by protocol design.
- Core Settings redesigned to the standard page structure with localized status tags, per-core Install buttons and tooltips; daemons installed by previous releases (legacy /opt/pxpanel and /usr/libexec/pxpanel-* layouts) are detected and adopted automatically.
- CI hardening: fixed go-test/race/golangci/codegen/govulncheck failures (ctl test deadlock, migration model sync, nil-hook guards, Go toolchain 1.27.4, regenerated API schemas); frontend lint (34) and locale parity issues resolved.
- Tooltips added across Admins, Resellers, VPN Outbounds and Core Settings.

## 1.0.1

- VPN Protocols page merged into the Inbounds page (unified list, vpn-specific row actions, add-inbound flow); the separate page and menu entry were removed.
- Panel xray routing rules now apply to VPN protocol traffic: fixed nftables steering regeneration dropping other protocols' TPROXY rules; OpenVPN and OpenConnect registered; SSH hostname passthrough verified and pinned by tests. MTProto (mtg sidecar) egresses directly and cannot ride xray routing — documented.
- Resellers/Admins/VPN Outbounds page boxes now match the Inbounds page spacing.
- Release assets are published as stable releases (no longer pre-release).
- Dependency updates: antd 6.7.2, swagger-ui-react 5.36.0, @tanstack/react-query(+devtools) 5.108.4, oxfmt 0.80.0, Jipok/wgctrl-go 1.3.1; locale parity restored across all 14 locales; frontend lint issues fixed.

## 1.0.0

- Linux-only release (amd64/arm64/armv7/armv6/386/armv5/s390x) + Docker; Windows packaging removed because the VPN protocol stack is Linux-only.

Initial release.

- PxPanel: all-in-one Xray management panel with a modern multi-language web UI.
- Multi-protocol Xray management plus extended VPN protocols: PPTP, L2TP RAW,
  L2TP/IPsec, OpenVPN, OpenConnect, SSTP, IKEv2, WireGuard C, AmneziaWG, GRE,
  MTProto, SSH.
- Reseller system, multi-admin support and core settings management.
- Multi-node orchestration, subscription server, REST API with scoped tokens and
  in-panel API docs.
- SQLite and PostgreSQL backends, fail2ban IP-limit enforcement, SSL certificate
  automation, Telegram/Discord/WeChat notification bots.
- `pxpanel` CLI, systemd/OpenRC services, Docker image and musl release builds
  for 7 architectures.
