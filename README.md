<p align="center">
  <img src="media/logo.png" alt="PxPanel logo" width="160" />
</p>

<h1 align="center">PxPanel</h1>

<p align="center">
  All-in-one Xray management panel — hardened, extended, multi-protocol.
</p>

<p align="center">
  <a href="https://github.com/ImSoheilPx/pxpanel/releases/latest"><img src="https://img.shields.io/github/v/release/ImSoheilPx/pxpanel?style=flat-square" alt="Latest release" /></a>
  <a href="https://github.com/ImSoheilPx/pxpanel/blob/main/LICENSE"><img src="https://img.shields.io/github/license/ImSoheilPx/pxpanel?style=flat-square" alt="License: GPL-3.0" /></a>
  <a href="https://github.com/ImSoheilPx/pxpanel/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/ImSoheilPx/pxpanel/ci.yml?branch=main&style=flat-square" alt="CI" /></a>
</p>

[English](/README.md) | [فارسی](/README.fa_IR.md)

---

## About PxPanel

PxPanel is an all-in-one, open-source web control panel for managing
[Xray-core](https://github.com/XTLS/Xray-core) servers. It provides a clean,
multi-language interface for deploying, configuring and monitoring a wide range
of proxy and VPN protocols — from a single VPS to multi-node deployments — and
extends the panel far beyond the Xray core with a large set of additional VPN
protocols and operator features.

> [!IMPORTANT]
> This project is intended for personal use only. Please do not use it for
> illegal purposes or in a production environment.

## Features

### Core panel

- **Multi-protocol Xray inbounds** — VLESS, VMess, Trojan, Shadowsocks, WireGuard,
  AmneziaWG, TUIC v5, Hysteria2, MTProto, HTTP, SOCKS (Mixed), Dokodemo-door /
  Tunnel, and TUN.
- **Modern transports & security** — TCP (Raw), mKCP, WebSocket, gRPC,
  HTTPUpgrade, and XHTTP, secured with TLS, XTLS, and REALITY.
- **AmneziaWG built in** — DPI-resistant WireGuard runs inside the panel on a
  userspace network stack, with no kernel module, DKMS, or extra packages.
- **Per-client management** — traffic quotas, expiry dates, IP limits with
  trusted-address exemptions, HWID device limits, scheduled renewal cycles, live
  online status, one-click share links, QR codes, and subscriptions.
- **Traffic statistics** — per inbound, per client, and per outbound, with reset
  controls and usage history.
- **Multi-node support** — manage and scale across multiple servers from a
  single master panel, including cloning inbounds onto other nodes.
- **Outbound & routing** — WARP, custom routing rules, load balancers, and
  outbound proxy chaining.
- **Built-in subscription server** — raw, JSON, and Clash output, auto-selected
  from the client's User-Agent.
- **RESTful API** with scoped, optionally expiring tokens and an in-panel API
  reference.
- **Secure access** — 2FA (TOTP) login, Fail2ban integration for per-client IP
  limits, CSRF-protected sessions.
- **SSL certificate management** — issue and auto-renew certificates with
  acme.sh.
- **Notification bots** — Telegram, Discord and WeChat for traffic, expiry and
  backup events.
- **Flexible storage** — SQLite (default) or PostgreSQL.
- **Installable panel (PWA)** — pin PxPanel to a desktop or phone home screen.
- **14 UI languages** with dark and light themes.

### Extended VPN protocols & operator features

- VPN protocols: **PPTP, L2TP RAW, L2TP/IPsec, OpenVPN, OpenConnect, SSTP,
  IKEv2, WireGuard C, AmneziaWG, GRE, MTProto, SSH**
- **Reseller** system
- **Multi-Admin** support
- **Core Settings** management

## Quick Start

```bash
bash <(curl -Ls https://raw.githubusercontent.com/ImSoheilPx/pxpanel/main/install.sh)
```

To install a specific version, append its tag (e.g. `v1.0.0`):

```bash
bash <(curl -Ls https://raw.githubusercontent.com/ImSoheilPx/pxpanel/main/install.sh) v1.0.0
```

During installation a random username, password, and access path are generated.
After installation, run `pxpanel` to open the management menu, where you can
start/stop the service, view or reset your login credentials, manage SSL
certificates, and more.

The installer sets up:

- the `pxpanel` systemd service (OpenRC on Alpine) — configuration under
  `/etc/pxpanel`, binaries under `/usr/local/pxpanel`, logs under `/var/log/pxpanel`
- the `pxpanel` CLI at `/usr/bin/pxpanel`

Every release asset is published with a `.sha256` sum next to it. Both
`install.sh` and the updater verify the archive against that sum and abort on a
mismatch.

### Docker

```bash
docker compose up -d
```

The image is published at `ghcr.io/ImSoheilPx/pxpanel`. The bundled Fail2ban
enforces per-client IP limits with `iptables`, which requires the `NET_ADMIN`
capability — `docker-compose.yml` already grants it via `cap_add`:

```bash
docker run -d --cap-add=NET_ADMIN --cap-add=NET_RAW ... ghcr.io/ImSoheilPx/pxpanel
```

## Tested operating systems

| OS | Status |
|---|---|
| Ubuntu 22.04 / 24.04 | ✅ Tested |
| Ubuntu 20.04 | ✅ Tested |
| Debian 11 / 12 | ✅ Tested |
| CentOS Stream 9+ | ✅ Tested |
| AlmaLinux 9 / Rocky Linux 9 | ✅ Tested |
| Fedora 38+ | ✅ Tested |
| Arch Linux | ✅ Tested |
| openSUSE Tumbleweed | ✅ Tested |
| Alpine Linux | ✅ Tested (Docker) |

**Architectures:** `amd64` · `386` · `arm64` (aarch64) · `armv7` · `armv6` ·
`armv5` · `s390x`.

## Screenshots

Screenshots will be added soon.

## Database Options

PxPanel supports two backends, chosen during install:

- **SQLite** (default) — a single file at `/etc/pxpanel/pxpanel.db`. Zero setup,
  ideal for small and medium deployments.
- **PostgreSQL** — recommended for high client counts or multi-node setups.

At runtime the backend is selected via environment variables (the installer
writes these to `/etc/default/pxpanel` for you):

```
PXPANEL_DB_TYPE=postgres
PXPANEL_DB_DSN=postgres://pxpanel:***@127.0.0.1:5432/pxpanel?sslmode=disable
```

## Attribution

PxPanel is a fork of [3x-ui](https://github.com/MHSanaei/3x-ui), hardened and
extended with many additional capabilities. All credit for the original panel
goes to the 3x-ui contributors; this repository continues that work under the
same GPL-3.0 license.

## Contributing

Contributions are welcome. Please read the [Contributing Guide](/CONTRIBUTING.md)
before opening an issue or pull request.

## License

PxPanel is licensed under the [GPL-3.0](LICENSE) license.
