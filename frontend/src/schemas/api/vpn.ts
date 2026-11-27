import { z } from 'zod';

/*
 * VPN wave read models (internal/vpn/accounts, reseller, adminaccess,
 * coresettings, coreconfig, vpnout, ssh). Schemas stay loose: the pages only
 * render what they declare, and an undeclared field must never fail a fetch.
 */

const loose = z.object({}).loose();

// --- accounts (/panel/api/accounts) -----------------------------------------

export const AccountMembershipSchema = loose.extend({
  inboundId: z.number(),
  protocol: z.string(),
  remark: z.string().default(''),
  port: z.number().default(0),
  enable: z.boolean().default(true),
  slot: z.number().nullable().optional(),
  clientId: z.string().optional(),
});
export type AccountMembership = z.infer<typeof AccountMembershipSchema>;

export const AccountRowSchema = loose.extend({
  id: z.number(),
  email: z.string(),
  enable: z.boolean().default(true),
  subId: z.string().default(''),
  comment: z.string().default(''),
  totalGB: z.number().default(0),
  expiryTime: z.number().default(0),
  reset: z.number().default(0),
  limitIp: z.number().default(0),
  tgId: z.number().default(0),
  up: z.number().default(0),
  down: z.number().default(0),
  memberships: z.array(AccountMembershipSchema).default([]),
  ownedByReseller: z.number().default(0),
});
export type AccountRow = z.infer<typeof AccountRowSchema>;

export const AccountListSchema = loose.extend({
  rows: z.array(AccountRowSchema).default([]),
  total: z.number().default(0),
  page: z.number().default(1),
  size: z.number().default(50),
  sort: z.string().default(''),
});
export type AccountList = z.infer<typeof AccountListSchema>;

export const ResellerBalanceSchema = loose.extend({
  isReseller: z.boolean().default(false),
  allowanceBytes: z.number().default(0),
  spentBytes: z.number().default(0),
  availableBytes: z.number().default(0),
});
export type ResellerBalance = z.infer<typeof ResellerBalanceSchema>;

export const BulkMembershipResultSchema = loose.extend({
  applied: z.number().default(0),
  skipped: z.number().default(0),
  reasons: z.array(z.string()).optional(),
});
export type BulkMembershipResult = z.infer<typeof BulkMembershipResultSchema>;

export const BulkPreviewSchema = loose.extend({
  isReseller: z.boolean().default(false),
  op: z.string().default(''),
  totalTargets: z.number().default(0),
  eligible: z.number().default(0),
  affordable: z.boolean().default(true),
  costBytes: z.number().default(0),
  availableBytes: z.number().default(0),
  shortBytes: z.number().default(0),
  canProcess: z.number().default(0),
  processEmails: z.array(z.string()).default([]),
});
export type BulkPreview = z.infer<typeof BulkPreviewSchema>;

// --- admins (/panel/api/admins) ---------------------------------------------

export const AdminRowSchema = loose.extend({
  id: z.number(),
  username: z.string(),
  nickname: z.string().default(''),
  isSuperAdmin: z.boolean().default(false),
  enable: z.boolean().default(true),
  twoFactorEnable: z.boolean().default(false),
  permissions: z.array(z.string()).default([]),
  inboundCount: z.number().default(0),
  inboundIds: z.array(z.number()).default([]),
});
export type AdminRow = z.infer<typeof AdminRowSchema>;

export const PermissionSlugSchema = loose.extend({ slug: z.string() });
export type PermissionSlug = z.infer<typeof PermissionSlugSchema>;

export const InboundBriefSchema = loose.extend({
  id: z.number(),
  remark: z.string().default(''),
  protocol: z.string().default(''),
  port: z.number().default(0),
});
export type InboundBrief = z.infer<typeof InboundBriefSchema>;

// --- resellers (/panel/api/resellers) ----------------------------------------

export const ResellerViewSchema = loose.extend({
  id: z.number(),
  username: z.string(),
  nickname: z.string().default(''),
  enable: z.boolean().default(true),
  twoFactorEnable: z.boolean().default(false),
  allowanceBytes: z.number().default(0),
  spentBytes: z.number().default(0),
  availableBytes: z.number().default(0),
  unlimited: z.boolean().default(false),
  daysPerGb: z.number().default(0),
  minCreateGb: z.number().default(0),
  minAddGb: z.number().default(0),
  allowExternalProxy: z.boolean().default(false),
  allowOverview: z.boolean().default(false),
  allowOverviewManage: z.boolean().default(false),
  inboundIds: z.array(z.number()).default([]),
  clientCount: z.number().default(0),
  createdBy: z.number().default(0),
});
export type ResellerView = z.infer<typeof ResellerViewSchema>;

// --- cores (/panel/api/core) -------------------------------------------------

export const CoreStatusSchema = loose.extend({
  name: z.string(),
  state: z.string().default(''),
  detail: z.string().default(''),
  version: z.string().default(''),
  inbounds: z.number().default(0),
});
export type CoreStatus = z.infer<typeof CoreStatusSchema>;

export const ModuleStatusSchema = loose.extend({
  name: z.string(),
  loaded: z.boolean().default(false),
  optional: z.boolean().default(false),
});
export type ModuleStatus = z.infer<typeof ModuleStatusSchema>;

export const SystemStatusSchema = loose.extend({
  ipForward: z.boolean().default(false),
  nftables: z.boolean().default(false),
  iproute: z.boolean().default(false),
  modules: z.array(ModuleStatusSchema).default([]),
  modulesOk: z.boolean().default(false),
});
export type SystemStatus = z.infer<typeof SystemStatusSchema>;

export const CoreStatusEnvelopeSchema = loose.extend({
  cores: z.array(CoreStatusSchema).default([]),
  system: SystemStatusSchema.optional(),
  provisioned: z.boolean().default(false),
  missingProtocols: z.array(z.string()).default([]),
  rebootRequired: z.boolean().default(false),
  rebootModules: z.array(z.string()).default([]),
  rebootPkg: z.string().default(''),
});
export type CoreStatusEnvelope = z.infer<typeof CoreStatusEnvelopeSchema>;

export const CoreCatalogEntrySchema = loose.extend({
  name: z.string(),
  title: z.string().default(''),
  backend: z.string().default(''),
  desc: z.string().default(''),
  installed: z.boolean().default(false),
  inbounds: z.number().default(0),
  shares: z.array(z.string()).default([]),
  builtin: z.boolean().default(false),
});
export type CoreCatalogEntry = z.infer<typeof CoreCatalogEntrySchema>;

export const CoreCatalogSchema = loose.extend({
  cores: z.array(CoreCatalogEntrySchema).default([]),
  provisioned: z.boolean().default(false),
});
export type CoreCatalog = z.infer<typeof CoreCatalogSchema>;

export const ProvisionStepSchema = loose.extend({
  what: z.string().default(''),
  ok: z.boolean().default(false),
  detail: z.string().default(''),
});
export type ProvisionStep = z.infer<typeof ProvisionStepSchema>;

export const ProvisionStateSchema = loose.extend({
  running: z.boolean().default(false),
  done: z.boolean().default(false),
  steps: z.array(ProvisionStepSchema).default([]),
  rebootRequired: z.boolean().default(false),
  rebootModules: z.array(z.string()).default([]),
  rebootPkg: z.string().default(''),
  provisioned: z.boolean().optional(),
});
export type ProvisionState = z.infer<typeof ProvisionStateSchema>;

export const UninstallStateSchema = loose.extend({
  running: z.boolean().default(false),
  done: z.boolean().default(false),
  steps: z.array(ProvisionStepSchema).default([]),
  kept: z.array(z.string()).default([]),
  cores: z.array(z.string()).default([]),
});
export type UninstallState = z.infer<typeof UninstallStateSchema>;

// coreconfig.Target has no json tags: Go marshals the exported names verbatim.
export const CoreConfigTargetSchema = loose.extend({
  Core: z.string().default(''),
  InboundId: z.number().default(0),
  File: z.string().default(''),
  Label: z.string().default(''),
  Remark: z.string().default(''),
  Path: z.string().default(''),
  Format: z.string().default(''),
  Mode: z.string().default(''),
  Text: z.string().default(''),
});
export type CoreConfigTarget = z.infer<typeof CoreConfigTargetSchema>;

export const CoreConfigEnvelopeSchema = loose.extend({
  core: z.string().default(''),
  targets: z.array(CoreConfigTargetSchema).default([]),
});
export type CoreConfigEnvelope = z.infer<typeof CoreConfigEnvelopeSchema>;

export const CoreConfigSaveResultSchema = loose.extend({
  health: loose
    .extend({ ok: z.boolean().default(false), logs: z.string().default('') })
    .default({ ok: false, logs: '' }),
  targets: z.array(CoreConfigTargetSchema).default([]),
});
export type CoreConfigSaveResult = z.infer<typeof CoreConfigSaveResultSchema>;

// --- vpnout / sshoutbound (/panel/api/xray) ----------------------------------

export const VpnOutboundConfigSchema = loose.extend({
  tag: z.string(),
  kind: z.string().default(''),
  remark: z.string().default(''),
  enable: z.boolean().default(true),
  iface: z.string().default(''),
  via: z.string().default(''),
});
export type VpnOutboundConfig = z.infer<typeof VpnOutboundConfigSchema>;

export const VpnOutKindSchema = loose.extend({
  kind: z.string(),
  available: z.boolean().default(true),
  why: z.string().default(''),
});
export type VpnOutKind = z.infer<typeof VpnOutKindSchema>;

export const SshOutboundConfigSchema = loose.extend({
  tag: z.string(),
  remark: z.string().default(''),
  address: z.string().default(''),
  port: z.number().default(22),
  username: z.string().default(''),
  authType: z.string().default('password'),
  socksPort: z.number().default(0),
  // Secrets come back masked; the forms never render them.
  password: z.string().default(''),
  privateKey: z.string().default(''),
  passphrase: z.string().default(''),
  knownHost: z.string().default(''),
});
export type SshOutboundConfig = z.infer<typeof SshOutboundConfigSchema>;

// --- protocols (/panel/api/inbounds/:id/...) ---------------------------------

export const DeviceConfigSchema = loose.extend({
  deviceIndex: z.number().default(0),
  ip: z.string().default(''),
  remark: z.string().default(''),
  publicKey: z.string().default(''),
  config: z.string().default(''),
  psk: z.string().default(''),
});
export type DeviceConfig = z.infer<typeof DeviceConfigSchema>;

export const SshClientConfigSchema = loose.extend({
  remark: z.string().default(''),
  host: z.string().default(''),
  port: z.number().default(0),
  singbox: z.string().default(''),
  plain: z.string().default(''),
  link: z.string().default(''),
});
export type SshClientConfig = z.infer<typeof SshClientConfigSchema>;

export const Ikev2RemoteIdSchema = loose.extend({ remoteId: z.string().default('') });
export type Ikev2RemoteId = z.infer<typeof Ikev2RemoteIdSchema>;

export const Ikev2CertCheckSchema = loose.extend({
  keyType: z.string().default(''),
  warning: z.string().default(''),
});
export type Ikev2CertCheck = z.infer<typeof Ikev2CertCheckSchema>;

export const AddressingAccountSchema = loose.extend({
  email: z.string(),
  slot: z.number().default(0),
  addresses: z.array(z.string()).default([]),
});
export type AddressingAccount = z.infer<typeof AddressingAccountSchema>;

export const AddressingReportSchema = loose.extend({
  inboundId: z.number().default(0),
  protocol: z.string().default(''),
  ranges: z.array(z.string()).default([]),
  subnets: z.array(z.string()).default([]),
  userLimit: loose
    .extend({
      posted: z.number().nullable().optional(),
      effective: z.number().default(0),
      rule: z.string().default(''),
    })
    .default({ effective: 0, rule: '' }),
  capacity: z.number().default(0),
  maxAccounts: z.number().default(0),
  used: z.number().default(0),
  accounts: z.array(AddressingAccountSchema).default([]),
});
export type AddressingReport = z.infer<typeof AddressingReportSchema>;

export const PoolBlockSchema = loose.extend({
  subnet: z.string(),
  protocol: z.string().default(''),
  inboundId: z.number().default(0),
  remark: z.string().default(''),
});
export type PoolBlock = z.infer<typeof PoolBlockSchema>;

// The VPN protocol family this panel's vpn surface serves. mtproto is
// deliberately absent: this panel's mtproto plane is the v3 sidecar.
export const VPN_PROTOCOLS = [
  'l2tp',
  'pptp',
  'openvpn',
  'openconnect',
  'sstp',
  'ikev2',
  'wg-c',
  'awg',
  'gre',
  'ssh',
] as const;

export type VpnProtocol = (typeof VPN_PROTOCOLS)[number];

const VPN_PROTOCOL_SET: ReadonlySet<string> = new Set(VPN_PROTOCOLS);

// The inbound table mixes xray-native and vpn-protocol rows (one DB table, one
// /panel/api/inbounds/list response); this is the row-level discriminator the
// inbounds page uses to pick the vpn-specific actions and forms.
export function isVpnProtocol(protocol: string): protocol is VpnProtocol {
  return VPN_PROTOCOL_SET.has(protocol);
}
