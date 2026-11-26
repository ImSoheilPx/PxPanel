# Changelog

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
