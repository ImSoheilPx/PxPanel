// VPN-layer gorm models, ported from vpn-ui database/model/model.go. Only the
// tables the VPN protocol stack owns are here; the panel's own models stay in
// model.go untouched. gorm tags are VERBATIM from vpn-ui — they are the storage
// contract for AutoMigrate and for round-tripping an imported vpn-ui backup.
//
// Naming note: vpn-ui's model.Client (with its Slot/Peers/Devices JSON fields)
// is NOT ported — pxpanel's existing model.Client (model.go) is the v3-shape
// client the core panel uses, and the account projection works on raw JSON maps,
// which carry those keys without needing the struct. ClientDevice and
// ClientGrePeer below are the two entry-shaped structs the protocol waves
// unmarshal devices[]/peers[] into.
package model

// Account is one sellable identity, usable across SEVERAL inbounds of different
// protocols with ONE quota, ONE expiry and ONE subscription. Membership of an
// inbound is a separate row (AccountInbound).
//
// This table sits ABOVE the existing settings JSON rather than replacing it.
// Inbound.Settings keeps its clients[] array and is maintained as a PROJECTION
// of the account onto each member inbound (internal/vpn/accounts). That is
// what leaves RADIUS, the slot allocator, every daemon config writer and the
// Xray config builder working unchanged: all of them parse settings.clients,
// and none of them need to learn a new source of truth.
//
// Email stays the global account identity, exactly as before: it is the unique
// key of client_traffics, the name RADIUS authenticates, and the selector the
// per-account routing rules are built from. One email, one traffic row, one
// quota, now spread over N inbounds instead of forcing N separate accounts.
type Account struct {
	Id int `json:"id" gorm:"primaryKey;autoIncrement"`

	// Email is the identity, and is matched case-insensitively after trimming
	// (see accounts.AccountKeyOf). uniqueIndex here mirrors
	// xray.ClientTraffic.Email's own unique constraint.
	Email string `json:"email" gorm:"uniqueIndex;not null"`

	// SubID is the subscription key, and is now INDEXED. It was previously free
	// text with no index, so a typo silently merged an account into someone else's
	// subscription. ValidateClientSubID rejects that at the write path.
	SubID string `json:"subId" gorm:"index;column:sub_id"`

	// Credentials are per FIELD, not per inbound: one uuid serves every vmess/vless
	// membership, one password every trojan membership. The projection picks the
	// field its member inbound's protocol keys on (see clientIdentityKey).
	//
	// This split is REQUIRED here and is not cosmetic: the legacy client "id" is
	// overloaded, holding a UUID for vmess/vless, a login name for the credential
	// VPNs and ssh, and the email itself for wg-c/awg/mtproto. Storing one "id"
	// column would make it impossible to say which of those an account holds
	// without knowing the protocol it is being rendered for.
	UUID        string `json:"uuid" gorm:"column:uuid"`                // vmess / vless / tuic
	VpnUsername string `json:"vpnUsername" gorm:"column:vpn_username"` // l2tp/pptp/openvpn/openconnect/sstp/ikev2/ssh login
	Password    string `json:"password" gorm:"column:password"`        // trojan/shadowsocks/anytls + every credential VPN
	Auth        string `json:"auth" gorm:"column:auth"`                // hysteria
	Security    string `json:"security" gorm:"column:security"`        // vmess
	Secret      string `json:"secret" gorm:"column:secret"`            // mtproto
	NaiveUser   string `json:"naiveUser" gorm:"column:naive_username"` // naive HTTP Basic username; empty means "use Email"

	// Quota and lifecycle: the entire point of the table. One set of these per
	// account, however many inbounds it is on.
	TotalGB    int64 `json:"totalGB" gorm:"column:total_gb"`
	ExpiryTime int64 `json:"expiryTime" gorm:"column:expiry_time"`
	// NO gorm default on Enable, deliberately. `default:1` makes GORM treat Go's
	// false as "unset" and write 1 instead, so a DISABLED client migrated to an
	// ENABLED account (the bug that rolled back vpn-ui's first migration).
	Enable  bool   `json:"enable"`
	Reset   int    `json:"reset" gorm:"default:0"`
	LimitIP int    `json:"limitIp" gorm:"column:limit_ip"`
	TgID    int64  `json:"tgId" gorm:"column:tg_id"`
	Comment string `json:"comment"`

	// Per-account OVERRIDES of the three limits an inbound sets for everyone on it.
	// nil means "inherit whatever the inbound says", which is what every row written
	// before these columns existed reads back as, and what clearing the box in the
	// client form writes.
	//
	// Pointers rather than ints, and the distinction is the whole feature. LimitIP
	// above is a plain int and so cannot tell "never set" from "explicitly 0". These
	// three can: 0 is a real value here (unlimited for the rates), and absent is a
	// different one.
	//
	// NO gorm default on any of them, deliberately, for the same reason Enable
	// carries none: GORM treats Go's zero value as "unset" and writes the default
	// over it, so `default:0` on a nullable column would turn an explicit
	// "unlimited" back into "inherit" on every save.
	//
	// The rates are KB/s, the same unit the inbound columns and the UI use; 0 in a
	// direction is unlimited THERE, which for an account on an otherwise limited
	// inbound is a genuine per-account exemption and not a way of saying "inherit".
	SpeedLimitDown *int `json:"speedLimitDown" gorm:"column:speed_limit_down"`
	SpeedLimitUp   *int `json:"speedLimitUp" gorm:"column:speed_limit_up"`

	// UserLimitOverride is the account's own device cap, and it may only LOWER the
	// inbound's User Limit K. Never raise it: an account's tunnel addresses are laid
	// out on a UNIFORM STRIDE of K (vpnrange.VpnAccountBlock), so a bigger block for
	// one account runs straight into the next account's addresses and two customers
	// silently share a tunnel IP, with no error anywhere. resolveUserLimitOverride
	// enforces the clamp on READ, so a value that arrives by API cannot raise it
	// either.
	UserLimitOverride *int `json:"userLimitOverride" gorm:"column:user_limit_override"`

	CreatedAt int64 `json:"createdAt" gorm:"autoCreateTime:milli"`
	UpdatedAt int64 `json:"updatedAt" gorm:"autoUpdateTime:milli"`
}

// TableName pins the table name so it does not collide with anything GORM would
// infer, and so a future rename of the Go type cannot silently orphan live data.
func (Account) TableName() string { return "accounts" }

// AccountInbound is ONE membership: this account is served on this inbound.
// Composite primary key, so the same pair cannot be inserted twice.
type AccountInbound struct {
	AccountId int `json:"accountId" gorm:"primaryKey;column:account_id;index"`
	InboundId int `json:"inboundId" gorm:"primaryKey;column:inbound_id;index"`

	// Slot is per MEMBERSHIP and never per account. It is defined as "the account's
	// index into THIS inbound's address pool", and one email on N pool inbounds
	// legitimately consumes N slots at N different addresses. A pointer for the same
	// reason as the legacy client slot: absent must stay distinguishable from slot 0,
	// because rows predating slots fall back to their list index.
	Slot *int `json:"slot" gorm:"column:slot"`

	// Flow is a per-membership override (vless only). Empty means "whatever the
	// account/protocol default is".
	Flow string `json:"flow" gorm:"column:flow"`

	// Enable is "is this account served on THIS inbound", which is a different
	// question from Account.Enable ("is this account live at all"). The projection
	// renders the AND of the two, so an account switched off here stops being served
	// on this inbound and keeps working on every other one.
	//
	// This column is what makes the Clients page's per-inbound switch honest. It
	// used to write Account.Enable, which is panel-wide: a switch documented as
	// "takes the account off ONE inbound and leaves the rest serving it" took the
	// customer off ALL of them.
	//
	// A POINTER for the same reason Slot is one: every row that predates this column
	// is NULL, and NULL has to mean "served", not "switched off". A plain bool with
	// `default:true` is the trap that already cost this table one whole migration:
	// GORM treats Go's false as unset and writes the default over it, so a membership
	// the operator disabled would come back enabled on the next save.
	Enable *bool `json:"enable" gorm:"column:enable"`

	// Extra is the VERBATIM client entry this membership was migrated from, minus
	// nothing: the whole original JSON object. The projection starts from it and
	// overlays only the keys the account layer owns, so any field neither Account
	// nor this struct models survives untouched.
	//
	// This is load-bearing, not an optimization. wg-c and awg mint a keypair PER
	// DEVICE and store them as clients[].devices[]; GRE stores pinned peer slots as
	// clients[].peers[]. A projection that rebuilt the entry from modelled fields
	// alone would therefore silently destroy every WireGuard keypair on the first
	// write, invalidating every already-installed client config on the box.
	Extra string `json:"-" gorm:"column:extra"`

	// Up/Down/AllTime are this membership's SHARE of the account's usage: the bytes
	// that entered through THIS inbound. They are a breakdown, never the truth.
	//
	// client_traffics stays the authoritative counter and is written exactly as it
	// was: it is the row RADIUS, the rbridge sink, the depletion sweep and every
	// daemon read, and quota enforcement must not move onto a column added here.
	// These are written alongside it from the same deltas, so they SUM TO IT, minus
	// whatever could not be attributed. Never sum them to answer "how much has this
	// account used".
	//
	// Up/Down are BILLED bytes (multiplier applied) and AllTime is RAW, matching
	// client_traffics column for column, so the two can be compared directly.
	Up      int64 `json:"up" gorm:"column:up;default:0"`
	Down    int64 `json:"down" gorm:"column:down;default:0"`
	AllTime int64 `json:"allTime" gorm:"column:all_time;default:0"`

	CreatedAt int64 `json:"createdAt" gorm:"autoCreateTime:milli"`
}

// TableName pins the table name. See Account.TableName.
func (AccountInbound) TableName() string { return "account_inbounds" }

// InboundAccess grants one admin access to one inbound.
//
// Access is ASSIGNED, not inferred from who created the row. A super admin ticks
// which inbounds each admin can see, and anything unticked does not exist as far
// as that admin is concerned. Inbound.UserId still records the creator (for the
// Admins list and Reassign), but it is bookkeeping: it does not decide access.
//
// Super admins are never listed here; they see every inbound by role.
type InboundAccess struct {
	Id        int `json:"id" gorm:"primaryKey;autoIncrement"`
	UserId    int `json:"userId" gorm:"index:idx_access_user_inbound,unique,priority:1;index"`
	InboundId int `json:"inboundId" gorm:"index:idx_access_user_inbound,unique,priority:2;index"`
}

// ResellerProfile holds one reseller's balance and the levers an admin sets on
// them. Split from User because these fields are meaningless for every admin
// row, and because the balance is written under transaction on every account
// create/edit/delete: keeping those writes off the row that every request reads
// is worth one join on the rare page that needs it.
type ResellerProfile struct {
	Id     int `json:"id" gorm:"primaryKey;autoIncrement"`
	UserId int `json:"userId" gorm:"uniqueIndex"`

	// AllowanceBytes is the cumulative traffic an admin has granted. SpentBytes
	// is what is currently committed to live accounts plus what past accounts
	// burned before being deleted. Available = Allowance - Spent.
	//
	// BYTES, never GB. Client.TotalGB is a byte count despite its name, and a unit
	// mismatch on this pair is free traffic.
	AllowanceBytes int64 `json:"allowanceBytes" gorm:"default:0"`
	SpentBytes     int64 `json:"spentBytes" gorm:"default:0"`
	// Unlimited skips the balance CHECK but not the accrual: SpentBytes keeps
	// climbing, so an admin who later sets a limit correctly accounts for what
	// this reseller already sold. Stored explicitly rather than overloading
	// AllowanceBytes==0, so that an admin who leaves the field blank while
	// creating a reseller does not silently mint an unlimited one.
	Unlimited bool `json:"unlimited" gorm:"default:0"`

	// DaysPerGB > 0 FORCES an account's duration: expiry is GB * DaysPerGB, and
	// the reseller gets no expiry field at all. 0 leaves the choice to them.
	DaysPerGB int `json:"daysPerGb" gorm:"default:0"`
	// MinCreateGB is the smallest account they may create, MinAddGB the smallest
	// top-up in one edit. Whole GB, as an operator sets them; 0 means no floor.
	MinCreateGB int `json:"minCreateGb" gorm:"default:0"`
	MinAddGB    int `json:"minAddGb" gorm:"default:0"`

	// AllowExternalProxy lets the configs and links this reseller generates carry
	// the inbound's external-proxy endpoints. Off strips them.
	AllowExternalProxy bool `json:"allowExternalProxy" gorm:"default:0"`

	// AllowOverview lets this reseller open the panel overview: the reseller's
	// counterpart to PermAccessOverview, which their derived mask can never carry.
	// Off (the default) hides the nav entry entirely rather than greying it.
	AllowOverview bool `json:"allowOverview" gorm:"default:0"`

	// AllowOverviewManage is the reseller's counterpart to PermOverviewManage: off,
	// the overview they were let into is a read-only showcase. It has no effect
	// unless AllowOverview is on, since there is no page to scope otherwise.
	AllowOverviewManage bool `json:"allowOverviewManage" gorm:"default:0"`

	// CreatedBy is the admin who owns this reseller. A non-super admin holding
	// PermManageResellers sees and edits only their own: without this, one such
	// admin could edit another's reseller balance or reassign their inbounds.
	CreatedBy int `json:"createdBy" gorm:"index"`
}

// ResellerClient records that a reseller owns an account, and what that account
// currently costs them. Ownership and charge are one row because they are 1:1
// on the account, so two tables would only be two things to keep in sync.
//
// ABSENCE of a row means the house owns the account. Admins and super admins
// have no balance, so there is nothing to charge and their paths need no ledger
// awareness at all.
type ResellerClient struct {
	Id int `json:"id" gorm:"primaryKey;autoIncrement"`
	// Email is the panel-wide account identity. xray.ClientTraffic.Email carries
	// gorm:"unique", so this matches the seam that exists rather than inventing a
	// second notion of "which client".
	Email string `json:"email" gorm:"uniqueIndex"`
	// InboundId is the HOME inbound: the one this account was first sold on. It is
	// DISPLAY ONLY, and nothing may decide anything by it.
	//
	// One account is served on N inbounds (see AccountInbound), and this column
	// holds exactly one of them, so every question of the form "which inbound is
	// this account on" has to be answered by resolving the memberships instead.
	// It is repointed when the inbound it names is deleted while the account lives
	// on elsewhere, so it keeps naming something real.
	InboundId int `json:"inboundId" gorm:"index"`
	UserId    int `json:"userId" gorm:"index"`

	// ChargedBytes is what this account currently holds against its reseller's
	// balance: raised on create and top-up, lowered on deduct and delete.
	ChargedBytes int64 `json:"chargedBytes" gorm:"default:0"`
	// AllTimeBase is ClientTraffic.AllTime at the moment of the charge, so
	// consumption is measured from the charge and not from the account's whole
	// life. AllTime is used rather than Up+Down because it is monotonic across a
	// traffic reset, which is what stops a reset from turning consumed bytes back
	// into a refundable balance.
	AllTimeBase int64 `json:"allTimeBase" gorm:"default:0"`
}

// CustomGeoResource is one operator-supplied geo source (a routing-list
// download), keyed by type+alias.
type CustomGeoResource struct {
	Id            int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Type          string `json:"type" gorm:"not null;uniqueIndex:idx_custom_geo_type_alias;column:geo_type"`
	Alias         string `json:"alias" gorm:"not null;uniqueIndex:idx_custom_geo_type_alias"`
	Url           string `json:"url" gorm:"not null"`
	LocalPath     string `json:"localPath" gorm:"column:local_path"`
	LastUpdatedAt int64  `json:"lastUpdatedAt" gorm:"default:0;column:last_updated_at"`
	LastModified  string `json:"lastModified" gorm:"column:last_modified"`
	CreatedAt     int64  `json:"createdAt" gorm:"autoCreateTime;column:created_at"`
	UpdatedAt     int64  `json:"updatedAt" gorm:"autoUpdateTime;column:updated_at"`
}

// ClientDevice is one wg-c/awg device slot: its own keypair (and optional preshared
// key) and, from its index, its own /32 out of the account's block. The JSON tags
// MUST match the protocol services' device struct, or normalizing a client
// silently rewrites the key material the data plane loads into the interface.
//
// No omitempty inside the entry: the array's own LENGTH is the device-slot count,
// and a slot whose keys have not been minted yet is a real, meaningful element.
type ClientDevice struct {
	PrivKey string `json:"privKey"`
	PubKey  string `json:"pubKey"`
	Psk     string `json:"psk"`
}

// ClientGrePeer is one GRE peer slot. The JSON tags MUST match the gre service's
// peer struct, or normalizing a client silently rewrites what the data plane
// reads.
//
// An EMPTY element is meaningful and must survive: it is a deliberately unpinned
// peer slot, and the array's LENGTH is the slot count.
type ClientGrePeer struct {
	PeerIp string `json:"peerIp,omitempty"`
	Remark string `json:"remark,omitempty"`
}

// PermissionDef pairs a permission bit with its stable wire slug. Kept next to
// the models (the Admins API serializes it); the bitmask itself and its
// constants live in permission.go.
type PermissionDef struct {
	Bit  Permission `json:"-"`
	Slug string     `json:"slug"`
}
