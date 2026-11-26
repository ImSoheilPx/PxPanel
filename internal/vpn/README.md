# internal/vpn — VPN protocol stack foundation

Ported from the vpn-ui tree (`Sir-MmD/vpn-ui`, a 3x-ui v2.9.3 fork carrying a
full VPN protocol stack). This wave landed the FOUNDATION layer: the packages
every protocol service sits on. Protocol services land in later waves and mount
under `internal/vpn/<proto>/`.

Import paths: `github.com/ImSoheilPx/pxpanel/internal/vpn/...` (vpn-ui's
`github.com/mhsanaei/3x-ui/v2/...` mechanically adapted to the pxpanel tree:
`config/`→`internal/config`, `logger/`→`internal/logger`, `util/`→`internal/util`).

Build: `GOTOOLCHAIN=local GOOS=linux go build -modfile=.pxverify.mod ./internal/vpn/... ./internal/database/...`

## What landed

| Package | From (vpn-ui) | Contents |
|---|---|---|
| `internal/vpn/config` | `config/` | VPN-layer config facade delegating to `internal/config` (PXPANEL_* env). Adds `VPNDir` = `/etc/pxpanel` (the panel's fixed /etc directory). |
| `internal/vpn/log` | `logger/logger.go` | Thin facade over `internal/logger` — one log file, one buffer, one web-UI log viewer. vpn-ui's standalone op/go-logging wrapper is fully covered by the target logger. |
| `internal/vpn/range` (pkg `vpnrange`) | `web/service/vpnrange.go` | The address plan: per-protocol /16 bases (10.0 L2TP … 10.9 GRE inside 10.0.0.0/12), /24 range allocator/validator (`NormalizeVpnRanges`, `AutoExpandVpnRanges`), User-Limit device-block math, account slot allocation, OpenVPN block math. Exported surface in `export.go`. |
| `internal/vpn/defaults` | `web/service/protocoldefaults.go` (+ `sharedconfig.go`'s `SharedL2tpIpsecPsk`, `ikev2.go`'s MTU) | Server-side settings shapes+defaults for the non-Xray protocols (`DefaultSettingsFor`, `FillSettingsDefaults`, `NormalizeInboundSettings`) and the VPN protocol identity constants (`ProtoL2TP`…`ProtoHysteria2`, `TunnelProtocols`). |
| `internal/vpn/manifest` | `web/service/ownership.go` + `ifaceown.go` | The ownership manifest (`/etc/pxpanel/ownership.json`): what the panel put on this host, tri-state pre-existing veto, reference-counted release, shared-file backups, netdev name-shape ownership tests (gre/wgc/awg/xcar). |
| `internal/vpn/procmgr` | `web/service/procmgr.go` + `systemd.go` | Supervised child daemons (auto-restart, group-kill, ring-buffered logs, `StopAll` on shutdown) + the panel's own systemd unit management. |
| `internal/vpn/pkgmgr` | `web/service/pkgmgr.go` + `distro_support.go` + `virt.go` | apt/dnf/yum/zypper/pacman/apk install abstraction, kernel-module availability/install flow, libreswan distro setup, tested-distro matrix, virtualization detection. |
| `internal/vpn/cert` | `web/service/panelcert.go` | Self-signed ECDSA P-256 panel cert (SANs = localhost/127.0.0.1/detected IP). The protocol waves extend this package for their PKI. |
| `internal/vpn/accounts` | `web/service/account.go` + `accountlist.go` + `accountproject.go` + helpers from `migrationaccounts.go`/`inbound.go` | The account plane: Account + AccountInbound memberships, the settings.clients PROJECTION (`ProjectAccount`), the mirror (`SyncInboundAccounts`), membership application (`ApplyMemberships*`), the Clients-page read model (`ListAccounts`), validation (`ValidateClientEmail/SubID/VpnUsername/ShadowsocksKeys`), `clientIdentityKey`. |
| `internal/vpn/xrayplane` | `xray/` (fork-account + traffic-parser deltas, sidecar path) + `web/service/xray.go` pairing half + per-protocol `GetDokodemoConfig`/`GetSocksConfig` + `radius.go`'s `BuildVpnEmailToIPMap` | The VPN-side Xray extension plane: paired dokodemo-door inbounds for the nine tunnel protocols, paired loopback socks inbounds for the mtproto/ssh relays (`GetSocksConfig`), email→source routing-rule translation + blackhole backstop, restart/online-source seams into the web layer, speed-limit sidecar path. Reuses `internal/xray` types (config/API/process stay the 3x-ui-lineage package's). |
| `internal/database/model/vpnmodels.go` + `permission.go` | `database/model/model.go` + `permission.go` | gorm models: `Account`, `AccountInbound`, `InboundAccess`, `ResellerProfile`, `ResellerClient`, `CustomGeoResource`, `ClientDevice`, `ClientGrePeer` (JSON shapes), `PermissionDef`; permission bitmask + slug helpers. Registered in `database.allModels()` (`db.go` — the one file edited outside this tree). Table names pinned: `accounts`, `account_inbounds`. |

## Adapter seams (stub files / hooks for later waves)

Every seam is implemented MINIMALLY (usually over `database.GetDB()`) and marked
`TODO(<wave>)` at the exact swap point:

- `accounts/adapter.go` —
  - `InboundIdsServingEmailsTx` (was `InboundService.inboundIdsServingEmails`) → panel-wide settings.clients scan. TODO(inbound wave): richer scan/caching.
  - `AccessibleInboundIds` (was `AdminService`) → **WIRED (admins wave)**: `adminaccess` registers the access reader from init (`RegisterAccessibleInboundIds`); the minimal query stays as the fallback for builds that do not link it.
  - `OwnedResellerEmails` (was `ResellerService.OwnedEmails`) → **WIRED (reseller wave)**: `reseller` registers the ledger reader from init (`RegisterOwnedResellerEmails`, lower-cased keys); same fallback shape.
  - `ViewerForUser` role flags → **WIRED (admins wave)**: the derivation lives in `adminaccess.FlagsFor` and is registered via `RegisterRoleFlags`; the adapter's inline probes stay as the fallback.
  - `OnlineClientEmails` (was `InboundService.GetOnlineClients`) → returns nil ("none online"). TODO(xray plane wave): core session list.
  - `SettingsGet` (was `SettingService.getSetting`) → settings KV row. TODO(settings wave).
  - `Viewer` / `ViewerForUser` — pxpanel `model.User` lacks `IsSuperAdmin`/`IsReseller`; reseller-hood derived from a `ResellerProfile` row, super-admin from lowest user id (vpn-ui `migrateSuperAdmin` rule). WIRED (admins wave): the derivation is registered from `adminaccess`; when User grows the columns, `adminaccess.FlagsFor` is the one function that changes.
  - `defaults.ValidateSettings` hook (was `protocolvalidate.go`, ~760 LOC) → nil until a protocol wave registers its validator.
  - `defaults.MtprotoSettingsLifter` — the pre-move mtproto body lifter. LANDED by
    the mtproto wave: the trio (`LiftMtprotoSettingsBlob` + `resolveMtprotoPolicy` +
    `deriveMtprotoPolicy`, ~230 LOC with their vpn-ui comments) lives in
    `internal/vpn/mtproto/policy.go` — NOT here, because `deriveMtprotoPolicy`
    resolves device caps through vpnrange math and vpnrange imports this package
    (defaults→range would cycle). The mtproto package registers the lifter into the
    var from `init()`; a nil var stays the safe pass-through (only reachable in
    builds that do not link mtproto at all).
  - `procmgr.BundleProvider` / `SetBundleProvider` — daemon-bundle resolution (vpn-ui `backend/` embeds: DaemonPath, accel/strongswan trees, bundled pppd env/args, DistroUnitExists, bundle roots). Default = PATH-only. TODO(bundle/build wave).
  - `procmgr.InstalledCoresFunc`, `manifest.InstalledCoresFunc` — provisioned-core set. TODO(core wave): wire to the core catalog.
  - `manifest.CoreArtifactPathsFunc` — per-core uninstall paths/globs. TODO(core wave).
  - `procmgr.ServiceNameStore` / `SetServiceNameStore` — systemd service name persistence (vpn-ui SettingService key `systemdServiceName`). Default = fixed "pxpanel".
  - `pkgmgr.IpsecHooks` — bundled libreswan/charon paths (`usingBundledIpsec`, `ensureBundledLibreswan`, `start/stopBundledPluto`, `syncCharon`, `stopCharon`). Default = distro ipsec.service. TODO(ipsec wave).
  - `pkgmgr.RequiredModulesFor` — flat "any installed core → all vpn modules" approximation. TODO(core wave): per-core catalog module lists.
- vpn-ui files the port DELIBERATELY did not bring: `AccountsMigrationReport`/conflict-pair machinery (migrationaccounts.go — needed only by the `migrate`/`revert-accounts` CLI paths; re-port with the migration), model.Client's Slot/Peers/Devices columns (pxpanel's model.Client is the v3 shape; the projection works on raw JSON maps, `vpnrange.SlotClient` is the typed view).

## Contracts later waves must keep

1. **settings.clients is the source of truth; `accounts` is the mirror.** All
   writes still land in `Inbound.Settings` and `SyncInboundAccounts` runs after
   them. The projection (`renderClientEntry`) OVERLAYS on the stored entry
   (`AccountInbound.Extra`) and never rebuilds — wg/awg keypairs and GRE peers
   live in the unmodelled part of the entry.
2. **Protocol string values are the storage contract.** `defaults.Proto*`
   ("l2tp", "wg-c", "awg", …) must stay byte-identical; note pxpanel's
   `model.WireGuard`/`model.AmneziaWG` mean the Xray-NATIVE protocols, which are
   different things from `defaults.ProtoWGC`/`defaults.ProtoAWG`.
3. **The address plan (10.0–10.9 /16 inside 10.0.0.0/12) and the slot math are
   load-bearing.** User-Limit overrides may only LOWER a cap; slots are per
   membership, allocated lowest-free, and stored — never derived from list
   position on read.
4. **Host artifacts are claimed in the manifest before creation**
   (`manifest.PrepareHostFile/PrepareDir/Claim`); deletes go through
   `manifest.ReleasePath`. Netdev deletes must pass the name-shape + kind +
   manifest triple test (`manifest.GreOwnsLink` &c.).
5. **Daemons run as procmgr children** (`procmgr.GetProcManager()`), not systemd
   units; `StopAll()` belongs in the panel shutdown path. Start-up order when
   the waves land: `manifest.OwnSynthesize()` FIRST, then procmgr
   `migrateFromSystemd()`, then per-protocol `Init*`.
6. **One writer of settings.clients:** only the accounts projection rewrites
   client entries. Everything else reads.
7. **Email is THE identity** (lowercased/trimmed — `accounts.AccountKeyOf`);
   `xray.ClientTraffic.Email` stays the unique accounting key; `Account.Email`
   mirrors it with its own uniqueIndex.

## Not ported in this wave (later waves, dependency order)

per inventory §16: xray plane (GetXrayConfig dokodemo/socks pairing,
speedlimit sidecar, traffic jobs) → nftables → radius+rbridge →
protocolvalidate → daemon-less protocols (ssh, wgc, wgxray, awg, gre) →
daemon protocols (openvpn, pptp, l2tp, ikev2, openconnect, sstp, mtproto) → vpnout
family → reseller/admins/core settings → sub engine → migration CLI → build
system.

## Reseller + Admins wave (internal/vpn/reseller, internal/vpn/adminaccess)

Ported from vpn-ui `web/service/reseller.go` + `reseller_bulk.go` (inventory §5)
and `web/service/admin.go` (inventory §6).

| Package | From (vpn-ui) | Contents |
|---|---|---|
| `internal/vpn/reseller` | `reseller.go` + `reseller_bulk.go` (+ the bulk-op rules from `inbound.go`) | The QUOTE → CHARGE-TICKET engine: `Quote`/`forcedExpiry` (pure pricing), `ChargeTicket` reserve→apply→rollback over the balance (`PrepareClientCreate/Update/Reset`), metered balance (`addSpent`'s atomic debit guard, `AvailableBytes`, `BalanceFor`), the ledger (`ProfileFor`/`ClientOwner`/`RenameClient`/`DropInbound`/`RefundDeleted`/`UsageSnapshot`), bulk pricing (`PrepareBulk`/`PreviewBulk`/`ApplyBulkCharges`/`RollbackBulk`, one ticket per batch, ownership scoping + skip-toggle-exact pricing via the ported `bulkops.go` applier rules), profile CRUD (`GetResellers`/`AddReseller`/`UpdateReseller`/`Recharge`/`DeleteReseller` keep-vs-cascade) |
| `internal/vpn/adminaccess` | `admin.go` + the derived-mask rules | Per-inbound ASSIGNED access (`AccessibleInboundIds`, `CanAccessInbound`, `CanAccessAllInbounds`, `CanAccessClientEmail`, `GrantInbound`/`SetInboundAccess`/`RevokeInboundEverywhere`, `ClientEmailAccess` — all fail CLOSED), role resolution (`FlagsFor`/`IsSuperAdmin`/`IsReseller`/`Can`), the 14-bit mask evaluation over `model.AdminFlags` (already ported in `model/permission.go`), Admins-page CRUD adapted to the columns that exist, `ReassignInbounds` |

Seam notes (what replaced vpn-ui's in-package service calls):

- Roles: vpn-ui's `User.IsReseller/IsSuperAdmin/Enable/Permissions` COLUMNS do not
  exist on pxpanel's `User` yet. Everything resolves through
  `adminaccess.FlagsFor` (super admin = first-seeded lowest-id user; reseller =
  a `ResellerProfile` row, which clears the super-admin bit; enable = always).
  Role writes the schema cannot store are REFUSED (`ErrUnrepresentableRole`,
  `errEnableNotStorable`), not silently dropped. When the user-roles columns
  wave lands, `FlagsFor` is the one function that changes. `MigrationOverviewAccess`
  is deliberately not carried: it UPDATEs the missing permissions column.
- `database.GetDB()` → `vpn.DB()` (no `internal/database` imports; DB tests are
  gated `linux && cgo` like the radius ones and wire `vpn.SetDB(database.GetDB)`).
- Callers are `accounts.Viewer` (the role snapshot), not `*model.User`.
- Membership/identity resolution (`servingInboundIds`, `inboundAccountEmails`,
  `accountKey`, `ClientIdentityKey`) → the accounts package.
- `RemoveClientFromInbound` — the cascade delete's per-inbound removal (vpn-ui
  `DelInboundClientByEmail`). Registered by the inbound wave; unwired, a cascade
  REFUSES (`ErrInboundPlaneUnavailable`) instead of half-applying.
- Lifetime usage: vpn-ui read the never-reset `ClientTraffic.AllTime`; pxpanel's
  client_traffics has no such column, so consumption composes
  SUM(`client_traffic_windows`) + live counters (`lifetimeUsage`) — the target's
  own documented lifetime identity, which is what keeps a reset from laundering
  spent bytes back into refundable balance.
- The duplicate-email refusal (`checkEmailFree` + `duplicateEmailError`) reads the
  settings scan through `accounts.InboundIdsServingEmailsTx`, with the parked
  case answered from the accounts table.
- Delegation back into the accounts adapter runs through registered funcs from
  `init()` (`RegisterAccessibleInboundIds`, `RegisterOwnedResellerEmails`,
  `RegisterRoleFlags`) — the adapter cannot import these packages without an
  import cycle, so the owner pushes, the adapter pulls.

Tests: `quote_test.go` + `bulkops_test.go` + `quote_security_test.go` (pure,
run anywhere); `reseller_db_test.go`, `bulk_db_test.go`, `membership_db_test.go`
(security/concurrency/refund/cascade, gated `linux && cgo`); `adminaccess`:
`mask_test.go` (pure mask + derived-mask rules) and `access_db_test.go`
(grant/revoke lifecycle + the multi-inbound client-access agreement, gated
`linux && cgo`).

## Address-plan consolidation (done)

The concurrent-wave duplicate `internal/vpn/vpnrange/` (the pure-math subset of
the same vpn-ui file) has been DELETED; `internal/vpn/range` (package
`vpnrange`) is the single source of truth for `ProtocolBase`/`NormUserLimit`
and friends. The two allocators only the duplicate carried — `ComputeVpnClientIP`
and `PppSubnetsOrDefault`, from vpn-ui `web/service/radius.go` — moved into
`range/clientip.go`, so nothing was lost. Consumers (the RADIUS package) import
`internal/vpn/range`. The former duplicate also exported a few wrappers whose
counterparts are still package-private here (`DecodeClientCount`,
`DecodeUserLimit`, `WgcDecodeUserLimit`, `Ikev2AuthModeFromSettings`,
`MinNonZero`, `Log2i`, `NextPow2`); the logic lives on unexported, and any
later wave that needs them adds the wrapper to `export.go` — the established
package-boundary file — rather than reviving a second copy.

## Network infra wave (nftables / radius / rbridge)

Landed after the foundation: the in-binary RADIUS server, the nftables
table/counters writer and the non-RADIUS reconcile sweeper, with the adapter
seams in the root package (`infra_ports.go`). Layout:

| Package | From (vpn-ui) | Contents |
|---|---|---|
| `internal/vpn/nftables` | `web/service/nftables*` | vpn-table/rules management, per-client egress accounting counters (`AddClientAccounting`, `ReadAndResetClientCounters` — nil-receiver-safe so tests need no daemon), policy routing. |
| `internal/vpn/radius` | `web/service/radius.go` + `radius_eap.go` | Access-Request auth (PAP / MS-CHAPv2 / EAP-MSCHAPv2), Acct handling driving the nft counters, the per-account block allocator (`radius_alloc.go`), the rbridge.Sink implementation. EAP state machine in `eap.go`; the challenge's server identity string is `pxpanel`. |
| `internal/vpn/rbridge` | `web/service/rbridge/` | Adapter/Sink framework: poll live sessions, enforce disable/quota/User-Limit K (`TrimToLimit`), evict, hand survivors to the sink. |

Radius seam notes (what replaced vpn-ui's in-package service calls):

- `database.GetDB()` → `vpn.DB()` (root-injected handle; NO package under
  `internal/vpn/` imports `internal/database`, which is what keeps
  `GOOS=linux go build ./internal/vpn/...` green on cgo-less hosts — the
  foundation packages `range`/`defaults`/`accounts`/`manifest` were re-pointed
  the same way). Wire-up is ONE call: `vpn.SetDB(database.GetDB)`.
- `foldClientTraffic` → the `vpn.TrafficSink` port (`SetTrafficSink`; default
  sink is the plain `client_traffics` UPDATE until the account wave swaps in
  multiplier+membership semantics).
- Per-protocol session teardowns (`killOcservByIP`, `SstpService.KillClientIP`,
  `Ikev2Service.KillClientIP`) → `vpn.EvictProtocolIP` (registered per protocol
  by the protocol wave; unregistered = logged skip, nothing torn down blindly).
  The PPP (l2tp/pptp) force-disconnect is an injected hook on the service:
  `radius.PPPKillFunc` + `RadiusService.SetPPPKiller` — until the pptp/l2tp
  wave registers theirs, the generic `ip link delete` probe (the source
  implementation) is the fallback.
- Per-inbound subnet readers (`GetSubnetsForInbound`) →
  `vpn.RegisterSubnetResolver`, with a settings-JSON fallback; liveness probes
  via `vpn.RegisterIPProber` (l2tp/pptp/openvpn/openconnect ship default
  `ip`-based probes inside radius).

Tests: `radius_alloc_test.go` (block allocator, I/O-free) and `eap_test.go`
(EAP-MSCHAPv2 rounds 1-2 with an injected credential lookup) are cgo-free;
`eap_db_test.go` (the full 3-round exchange incl. Framed-IP/MS-MPPE assertions)
is additionally gated `//go:build linux && cgo` because RT3 reads the panel DB
(CGO sqlite). The whole package — tests included — compiles only on linux
(the nftables/netlink dependency has no Windows build), so the suite runs in
CI, not on a Windows dev host.
Ported but not carried: `radius_openconnect_test.go` (same DB-gated class,
small incremental value over the alloc+eap coverage) and `clientlimits_test.go`
(its subject — `ResolveSpeedLimitRates` — belongs to the skipped speed-limit
feature).

## PPTP + L2TP(RAW) + L2TP/IPsec wave (internal/vpn/pptp, internal/vpn/l2tp)

Ported from vpn-ui `web/service/pptp.go` + `l2tp.go` (incl. the IPsec variant and
the shared charon/libreswan layer). One `pptpd` serves every PPTP inbound; one
`xl2tpd` LNS serves every L2TP inbound; L2TP/IPsec rides the shared charon
(IKEv1 transport PSK over swanctl) with a host/bundled-libreswan fallback
(`/etc/ipsec.conf` + `/etc/ipsec.secrets`).

| Package | From (vpn-ui) | Contents |
|---|---|---|
| `internal/vpn/l2tp` | `web/service/l2tp.go` + sharedconfig.go (l2tp half) + inboundport.go predicates | `L2tpService`: xl2tpd.conf / options.xl2tpd / radcli config generators, TPROXY setup, supervised-daemon lifecycle, the swanctl + libreswan renderers (panel-wide vs per-listen PSK shapes, byte-pinned by `psk_test.go`), `CheckSharedDaemonConflicts` (PSK/DNS/MTU save refusals). DB tests gated `linux && cgo` like the radius ones. |
| `internal/vpn/pptp` | `web/service/pptp.go` | `PptpService`: pptpd.conf / pptpd-options generators, TPROXY setup, pptpd lifecycle (pptpctrl symlink via `procmgr.LinkPptpCtrl`), RADIUS-driven Kill/Disable. |
| `internal/vpn/ipsec` | `web/service/charon.go` + `ipsec_bundle.go` + ikev2.go's swanctl consts | The ONE shared charon lifecycle (`SyncCharon`/`StopCharon`, charonNeeded, strongswan.conf + swanctl.conf writers) and the bundled-libreswan (pluto) path (`StartBundledPluto`, `IpsecConnNames`, …). Populates `pkgmgr.IpsecHooks` from init(). ikev2/gre/vpnout register their "charon needed" clauses via `RegisterCharonNeeder`. |
| `internal/vpn/configedit` | `web/service/coreconfig.go` (storage+merge+apply half) | The operator config-override seam every generator merges through (`ApplyOverride`/`Merge`); the editor endpoints + file catalog are the core wave's. |
| `internal/vpn/protoval` | `web/service/protocolvalidate.go` (framework + l2tp/pptp entries) | The per-protocol settings-validator registry + shared checks (L2TP/PPTP registered from init). Wire-up: `defaults.ValidateSettings = protoval.Validate` at boot (single var, no per-wave clobber). |
| `internal/vpn/radius/radcli.go` | `web/service/radius.go` radcli block | `GenerateRadiusClientConfig` + dictionary + `CleanupLegacyPerInboundFiles` — the pppd radius.so client configs pointing at the in-binary RADIUS server. |
| `internal/vpn/nftables/rulesinput.go` | (new seam) | Contributor registry replacing vpn-ui's `ApplyNftRules()` self-gather: each protocol wave registers one `RegisterRulesContributor` (l2tp adds the raw-L2TP input gate), the caller builds with `RulesInputFor()`. |

Foundation extensions this wave made: `procmgr` — exported `PppdEnv`/`PptpdArgs`/
`LinkPptpCtrl`/`Bundles` wrappers (DaemonBin/MigrateFromSystemd existed), and the
`BundleProvider` grew the IPsec/strongSwan bundle methods (`IpsecBundledPath`,
`ExtractLibreswanBundle`, `LinkStrongswanIpsecDir`, `StrongswanDefaultConfDir`,
…; noop defaults keep the distro ipsec.service path); `pkgmgr.InitIpsecNSS`
exported. `SetRadius` on both services now also registers the composite PPP
force-disconnect (`radius.RadiusService.PPPForceDisconnect`) through
`SetPPPKiller`, as the alloc hook expected.

## Deliberately not ported (decisions recorded)

- `speedlimit` sidecar WRITER: skipped — the target core is vanilla; the
  in-core enforcement it fed no longer exists.
- `iplimiter` (vpn-ui `web/job/check_client_ip_job.go` + fail2ban path, and the
  old in-core limiter plan): skipped. The per-account device cap for the VPN
  protocols is enforced where it belongs — RADIUS block allocation
  (`radius_alloc.go`) for RADIUS protocols and the rbridge sweeper
  (`TrimToLimit`) for the daemon-backed ones. The Xray-inbound log-scrape
  limiter died with the vanilla-core decision; if the xray plane ever wants
  source-IP caps again, that is an in-core admission decision (see the old
  ip-limiter-plan.md), not a `web/job` port.


