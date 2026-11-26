// The accounts layer: one sellable identity (Account), N inbound memberships
// (AccountInbound), one quota. Ported from vpn-ui web/service/account.go, on
// pxpanel's vpn.DB() and the ported models.
//
// AccountService never writes settings.clients directly; that is the
// projection's job (accountproject.go), so there is exactly one writer.
package accounts

import (
	"errors"
	"sort"
	"strings"
	"unicode"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/util/common"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/xray"

	"gorm.io/gorm"
)

// AccountKeyOf exposes the identity normalization (lower, trimmed) to callers
// outside this package, so a map keyed by it here is looked up the same way there.
func AccountKeyOf(email string) string { return accountKey(email) }

// accountKey is the identity normalization used across the accounts layer.
func accountKey(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// AccountService owns the accounts layer.
type AccountService struct{}

// -----------------------------------------------------------------------------
// Validation
//
// None of this existed in upstream 3x-ui. Client emails, subIds and VPN
// usernames were accepted verbatim and written straight into line-oriented
// daemon config files and into Xray's traffic stat names, both of which have
// delimiters. These helpers are enforced on the WRITE path only.
//
// Deliberately NOT enforced retroactively: an account whose email predates
// these checks must remain editable, or upgrading a live panel would strand
// real paying users.
// -----------------------------------------------------------------------------

// forbiddenClientRunes are rejected in every account-identifying string.
//
//   - Control characters (\n, \r, \t, \0 and friends) are the serious one. The
//     credential VPNs authenticate out of line-oriented, whitespace-delimited
//     files (chap-secrets for l2tp/pptp, ocpasswd for openconnect), so a newline
//     in a username or email is a config-injection primitive: it appends a record
//     the operator never created.
//   - '>' is rejected because Xray's per-account counter is named
//     "user>>><email>>>>traffic>>>uplink". An email carrying ">>>" splits wrong
//     when that name is parsed back apart, which misattributes traffic between
//     accounts silently and in a way no log would show.
const forbiddenClientRunes = ">"

// hasForbiddenClientChar reports whether s carries a character that cannot safely
// round-trip through the daemon configs and the Xray stat names.
func hasForbiddenClientChar(s string) bool {
	for _, r := range s {
		if r == unicode.ReplacementChar {
			// A lone surrogate or invalid UTF-8 byte. json.Marshal would rewrite it,
			// so the value stored would not be the value checked.
			return true
		}
		if unicode.IsControl(r) {
			return true
		}
		if strings.ContainsRune(forbiddenClientRunes, r) {
			return true
		}
	}
	return false
}

// ValidateClientEmail checks an email is usable as the global account identity.
func ValidateClientEmail(email string) error {
	trimmed := strings.TrimSpace(email)
	if trimmed == "" {
		return common.NewError("Client email cannot be empty: it is the account's identity across every inbound.")
	}
	if trimmed != email {
		// The caller should have normalized first. Saying so beats silently trimming
		// twice in two places that could drift apart.
		return common.NewErrorf("Client email %q has leading or trailing whitespace.", email)
	}
	if hasForbiddenClientChar(email) {
		return common.NewErrorf("Client email %q contains a control character or '>'; both corrupt the traffic counters and the VPN credential files.", email)
	}
	return nil
}

// ValidateClientSubID checks a subscription id is safe as a URL path component.
//
// subId was previously free text with no validation and no index, so a typo
// silently merged an account into a STRANGER'S subscription: a panel-wide scan
// keyed on this value alone is the lookup. That is the bug this closes.
func ValidateClientSubID(subID string) error {
	if subID == "" {
		// Absent is legal; the account simply has no subscription link yet.
		return nil
	}
	if strings.TrimSpace(subID) != subID {
		return common.NewErrorf("Subscription id %q has leading or trailing whitespace.", subID)
	}
	if hasForbiddenClientChar(subID) {
		return common.NewErrorf("Subscription id %q contains a control character.", subID)
	}
	// It is served as /sub/<subId>, so anything that changes what path that is
	// must be refused rather than escaped: an escaped value would no longer match
	// the id stored on the account.
	if strings.ContainsAny(subID, "/\\?#%") {
		return common.NewErrorf("Subscription id %q cannot contain / \\ ? # or %%: it is used directly as the subscription URL path.", subID)
	}
	if subID == "." || subID == ".." {
		return common.NewErrorf("Subscription id %q is not a usable URL path component.", subID)
	}
	return nil
}

// ValidateVpnUsername checks a credential-VPN login name.
//
// Stricter than the email check because this value is BOTH a whitespace-delimited
// field in chap-secrets AND, for openvpn, a filename: the per-client CCD block is
// written to /etc/openvpn/server-<id>/blocks-<proto>/<username>.
func ValidateVpnUsername(username string) error {
	if username == "" {
		return nil // resolved from the email by the caller
	}
	if strings.TrimSpace(username) != username {
		return common.NewErrorf("VPN username %q has leading or trailing whitespace.", username)
	}
	if hasForbiddenClientChar(username) {
		return common.NewErrorf("VPN username %q contains a control character or '>'.", username)
	}
	// Whitespace splits a chap-secrets record into extra fields.
	if strings.ContainsAny(username, " \t") {
		return common.NewErrorf("VPN username %q cannot contain spaces or tabs: the credential files are whitespace-delimited.", username)
	}
	// It becomes a filename on the openvpn path, so it must not be able to escape
	// the directory it is written into.
	if strings.ContainsAny(username, "/\\") || username == "." || username == ".." {
		return common.NewErrorf("VPN username %q cannot contain a path separator.", username)
	}
	return nil
}

// validateClientIdentities enforces the three checks above over a whole posted
// client list. This is the ONLY thing that makes them real: they are pure
// functions, so a path that does not call this does not validate.
//
// Called from all four write paths (add inbound, update inbound, add client,
// update client) rather than from one of them, because each is separately
// reachable from the HTTP API and any one left out is a hole through which the
// whole class walks in.
//
// Deliberately NOT called from the delete paths. An account that predates these
// checks and violates one has to remain deletable, or the only way to clean it up
// would be editing the database by hand.
//
// The VPN username is only checked for the protocols that actually key on it.
// wg-c, awg, gre and mtproto store id=email (nothing reads it) and the Xray-native
// protocols store a uuid or a password there, so applying the filename and
// whitespace rules to those would reject values that are correct.
func validateClientIdentities(protocol model.Protocol, clients []model.Client) error {
	return validateChangedClientIdentities(protocol, clients, nil)
}

// clientIdentityTuple is the exact triple these rules judge. Two clients with the
// same tuple are indistinguishable to every check below.
func clientIdentityTuple(c *model.Client) string {
	return c.Email + "\x00" + c.SubID + "\x00" + c.ID + "\x00" + c.Password
}

// ValidateShadowsocksKeys refuses a password a 2022-blake3 cipher cannot use.
//
// This family is the one protocol whose password is not free text: the user PSK must
// be base64 of EXACTLY the cipher's key length, and the core rejects anything else at
// handshake time. Nothing refused a bad one, at any layer. A hand-typed "hunter2" on
// a 2022-blake3-aes-256-gcm inbound was accepted by the form, spliced into the
// settings blob, and KEPT by the projection (an entry that already carries a password
// keeps it, which is what makes a minted PSK stable). The account was created,
// listed, looked healthy, and could never connect, with nothing logged anywhere.
//
// Judged only where the value CHANGED, exactly like the identity rules above and for
// the same reason: an account created before this check must stay editable.
// `stored` nil means every client is new and all of them are judged.
func ValidateShadowsocksKeys(inbound *model.Inbound, clients []model.Client, stored []model.Client) error {
	if inbound == nil || inbound.Protocol != model.Shadowsocks {
		return nil
	}
	unchanged := make(map[string]struct{}, len(stored))
	for i := range stored {
		unchanged[accountKey(stored[i].Email)+"\x00"+stored[i].Password] = struct{}{}
	}
	for i := range clients {
		client := &clients[i]
		if _, exempt := unchanged[accountKey(client.Email)+"\x00"+client.Password]; exempt {
			continue
		}
		// Blank is not a failure: the projection mints a correct PSK for a membership
		// that has none, which is the ordinary path for an account joining one of
		// these inbounds from another protocol.
		if client.Password == "" {
			continue
		}
		// The account's OWN cipher when it carries one. Multi-user shadowsocks in the
		// vpn-ui tree let each account carry its own `method` key; pxpanel's
		// model.Client has no per-client method column, so the inbound-level cipher
		// is the only one to judge by here. The projection still mints a
		// per-membership PSK for a 2022 inbound when the account password cannot
		// serve it (applyAccountCredential).
		method := inboundMethod(inbound.Settings)
		size := shadowsocksMethodKeySize(method)
		if size == 0 {
			// Every other cipher takes any string.
			continue
		}
		if !validShadowsocksKey(client.Password, size) {
			return common.NewErrorf(
				"the password for %q is not usable by this inbound's cipher: a %s key must be "+
					"base64 of exactly %d bytes. Leave it blank and the panel will generate one.",
				client.Email, method, size)
		}
	}
	return nil
}

// validateChangedClientIdentities is validateClientIdentities with an exemption
// for entries that are byte-identical to one already stored.
//
// This is what makes the rules safe to switch on over live data, and it is the
// difference between "enforced on writes" and "enforced retroactively".
//
// The whole-inbound save posts EVERY client on the inbound, not just the edited
// one. Without the exemption, a single account created years ago with a space in
// its VPN username would fail validation on every subsequent save, so the
// operator could not change the inbound's DNS, rename it, or add an unrelated
// account until they first went and fixed that one row. On a panel with hundreds
// of sold accounts that is an upgrade that bricks an inbound, which is a worse
// outcome than the hole the rules close.
//
// Exempting on the exact tuple rather than per field is deliberate: the moment
// any part of an account's identity is touched, the whole tuple is new and is
// held to the current rules. So a bad value can be kept but never edited into a
// different bad value, and it still cannot be created.
func validateChangedClientIdentities(protocol model.Protocol, clients []model.Client, stored []model.Client) error {
	unchanged := make(map[string]struct{}, len(stored))
	for i := range stored {
		unchanged[clientIdentityTuple(&stored[i])] = struct{}{}
	}

	for i := range clients {
		client := &clients[i]
		if _, exempt := unchanged[clientIdentityTuple(client)]; exempt {
			continue
		}
		if err := ValidateClientEmail(client.Email); err != nil {
			return err
		}
		if err := ValidateClientSubID(client.SubID); err != nil {
			return err
		}
		if isCredentialVPNProtocol(protocol) {
			if err := ValidateVpnUsername(client.ID); err != nil {
				return err
			}
		}
		// The vpn-ui tree ALSO validated a carried "vpnUsername" key here: its
		// Clients form posted every credential column of an account to whichever
		// inbound the write was addressed to, so a login name could ride on a vless
		// entry. pxpanel's model.Client carries no such column yet, so there is
		// nothing to judge — the check returns with the protocol-keyed one above.
		//
		// TODO(accounts wave): if the Clients form starts carrying vpnUsername on
		// pxpanel's client shape, validate it here unconditionally on protocol.
	}
	return nil
}

// credentialVPNProtocols lists the protocols whose client "id" is a login name.
// (The vpn-ui switch wrote the seven literals inline; a table keeps the same
// membership without re-importing a second protocol-constant set here.)
var credentialVPNProtocols = []model.Protocol{"l2tp", "pptp", "openvpn", "openconnect", "sstp", "ikev2", "ssh"}

// isCredentialVPNProtocol reports whether protocol's client "id" is a login name.
func isCredentialVPNProtocol(p model.Protocol) bool {
	for _, c := range credentialVPNProtocols {
		if c == p {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// Membership rules
// -----------------------------------------------------------------------------

// sameProtocolAmbiguous reports whether two inbounds of this protocol cannot tell
// their accounts apart, so one account must not be a member of both.
//
// The deciding factor is the NAS-Identifier their shared daemon sends to the
// in-binary RADIUS server. l2tp, pptp and ikev2 send a BARE protocol name,
// which resolves to inbound 0, so the lookup falls back to scanning every
// inbound of that protocol and taking the first match by id. The account would
// silently authenticate against the lowest-id inbound and take ITS ranges, user
// limit, strategy and slot, whichever inbound the operator thought they were
// selling.
//
// openvpn, openconnect and sstp already send "<proto>-<inboundId>", so they
// resolve exactly and are safe to have twice.
func sameProtocolAmbiguous(p model.Protocol) bool {
	return p == "l2tp" || p == "pptp" || p == "ikev2"
}

// ValidateMembershipSet refuses a membership set the data plane cannot serve.
//
// Refused at the API rather than silently accepted, because the failure mode is
// invisible: the account is created, appears on both inbounds, and logs in fine.
// It simply always lands on one of them.
func (s *AccountService) ValidateMembershipSet(inbounds []*model.Inbound) error {
	seen := map[model.Protocol]*model.Inbound{}
	for _, inbound := range inbounds {
		if !sameProtocolAmbiguous(inbound.Protocol) {
			continue
		}
		if first, clash := seen[inbound.Protocol]; clash {
			return common.NewErrorf(
				"an account cannot be on two %s inbounds at once (%q and %q). %s authenticates through a shared daemon that does not name the inbound, so the account would always be served by whichever has the lower id, silently taking that inbound's address range and user limit.",
				inbound.Protocol, first.Remark, inbound.Remark, inbound.Protocol)
		}
		seen[inbound.Protocol] = inbound
	}
	return nil
}

// -----------------------------------------------------------------------------
// Reads
// -----------------------------------------------------------------------------

// GetAccountByEmail returns the account for an email, matched the same
// case-insensitive, whitespace-trimmed way identity is compared everywhere else
// (accountKey). Returns nil with no error when there is none, because an
// unmigrated panel legitimately has clients with no account row.
func (s *AccountService) GetAccountByEmail(email string) (*model.Account, error) {
	return s.GetAccountByEmailTx(vpn.DB(), email)
}

// GetAccountByEmailTx is GetAccountByEmail inside a caller's transaction, so a
// read can see writes the same transaction has not committed yet.
func (s *AccountService) GetAccountByEmailTx(tx *gorm.DB, email string) (*model.Account, error) {
	key := accountKey(email)
	if key == "" {
		return nil, nil
	}
	var account model.Account
	err := tx.Where("LOWER(TRIM(email)) = ?", key).First(&account).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &account, nil
}

// GetMemberships returns every inbound this account is served on, in ascending
// inbound id order so callers that fan out over them are deterministic.
func (s *AccountService) GetMemberships(accountId int) ([]model.AccountInbound, error) {
	var memberships []model.AccountInbound
	err := vpn.DB().
		Where("account_id = ?", accountId).
		Order("inbound_id ASC").
		Find(&memberships).Error
	return memberships, err
}

// GetMembershipInboundIds is the common case of GetMemberships: just the ids.
func (s *AccountService) GetMembershipInboundIds(accountId int) ([]int, error) {
	var ids []int
	err := vpn.DB().
		Model(&model.AccountInbound{}).
		Where("account_id = ?", accountId).
		Order("inbound_id ASC").
		Pluck("inbound_id", &ids).Error
	return ids, err
}

// InboundIdsForEmail resolves an email straight to the inbounds serving it.
//
// This is the replacement for GetClientInboundByEmail, which returned
// traffics[0].InboundId: exactly ONE inbound, whichever one happened to own the
// single client_traffics row. Every caller of that was therefore acting on one
// arbitrary membership of N.
//
// Returns an empty slice for an account that has no memberships yet, so callers
// can fall back to the legacy single-inbound lookup during the period before the
// migration has run.
func (s *AccountService) InboundIdsForEmail(email string) ([]int, error) {
	key := accountKey(email)
	if key == "" {
		return nil, nil
	}
	var ids []int
	err := vpn.DB().
		Table("account_inbounds").
		Joins("JOIN accounts ON accounts.id = account_inbounds.account_id").
		Where("LOWER(TRIM(accounts.email)) = ?", key).
		Order("account_inbounds.inbound_id ASC").
		Pluck("account_inbounds.inbound_id", &ids).Error
	return ids, err
}

// servingInboundIds resolves account identities to every inbound that really
// serves them, ascending, deduplicated.
//
// This is the replacement for every "which inbound is this account on" that used
// to read a single column (ResellerClient.InboundId, client_traffics.inbound_id).
// Three sources, unioned, because no single one is right at every moment on a
// live panel:
//
//   - settings.clients, scanned. The source of truth in BOTH worlds: it is what
//     RADIUS, the daemon config writers and the Xray config builder read, and it
//     is correct before the accounts migration has run, after it, and on an
//     inbound an older binary added in between.
//   - account_inbounds. Carries a membership recorded by ApplyMemberships whose
//     entry a concurrent write has not spliced into settings yet.
//   - client_traffics.inbound_id, the legacy single-inbound answer. Kept so this
//     can never resolve to FEWER inbounds than the code it replaces.
//
// Filtered to inbounds that still EXIST, which the last two sources do not
// guarantee.
func servingInboundIds(tx *gorm.DB, emails ...string) ([]int, error) {
	keys := make([]string, 0, len(emails))
	for _, email := range emails {
		if key := accountKey(email); key != "" {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil, nil
	}

	found := map[int]bool{}
	served, err := InboundIdsServingEmailsTx(tx, emails)
	if err != nil {
		return nil, err
	}
	for _, id := range served {
		found[id] = true
	}

	var memberships []int
	if err := tx.Table("account_inbounds").
		Joins("JOIN accounts ON accounts.id = account_inbounds.account_id").
		Where("LOWER(TRIM(accounts.email)) IN (?)", keys).
		Pluck("account_inbounds.inbound_id", &memberships).Error; err != nil {
		return nil, err
	}
	for _, id := range memberships {
		found[id] = true
	}

	var legacy []int
	if err := tx.Model(&xray.ClientTraffic{}).
		Where("LOWER(TRIM(email)) IN (?)", keys).
		Pluck("inbound_id", &legacy).Error; err != nil {
		return nil, err
	}
	for _, id := range legacy {
		found[id] = true
	}

	if len(found) == 0 {
		return nil, nil
	}
	candidates := make([]int, 0, len(found))
	for id := range found {
		candidates = append(candidates, id)
	}
	var live []int
	if err := tx.Model(&model.Inbound{}).Where("id IN (?)", candidates).
		Pluck("id", &live).Error; err != nil {
		return nil, err
	}
	sort.Ints(live)
	return live, nil
}

// ServingInboundIds is the exported form, for the reseller/radius waves.
func (s *AccountService) ServingInboundIds(tx *gorm.DB, emails ...string) ([]int, error) {
	return servingInboundIds(tx, emails...)
}

// inboundAccountEmails lists the account identities ONE inbound serves, in its
// own settings order, with the memberships appended.
//
// The mirror of servingInboundIds, for the caller that has an inbound and needs
// its accounts. Returns the spelling each source stores, because the callers
// match emails against other tables by exact string.
func inboundAccountEmails(tx *gorm.DB, inboundId int) ([]string, error) {
	var inbound model.Inbound
	err := tx.Model(&model.Inbound{}).Select("id", "settings").
		Where("id = ?", inboundId).First(&inbound).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	out := make([]string, 0, 8)
	seen := map[string]bool{}
	add := func(email string) {
		key := accountKey(email)
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, email)
	}
	if err == nil {
		clients, ok := parseSettingsClients(inbound.Settings)
		if ok {
			for _, entry := range clients {
				email, _ := entry["email"].(string)
				add(email)
			}
		}
	}

	var members []string
	if err := tx.Table("account_inbounds").
		Joins("JOIN accounts ON accounts.id = account_inbounds.account_id").
		Where("account_inbounds.inbound_id = ?", inboundId).
		Pluck("accounts.email", &members).Error; err != nil {
		return nil, err
	}
	for _, email := range members {
		add(email)
	}
	return out, nil
}

// InboundAccountEmails is the exported form.
func (s *AccountService) InboundAccountEmails(tx *gorm.DB, inboundId int) ([]string, error) {
	return inboundAccountEmails(tx, inboundId)
}

// AccountsMigrated reports whether the accounts layer has been backfilled and
// verified. Everything that READS accounts as authoritative must gate on this:
// before it is set, settings.clients is the only truth and the accounts tables
// may be empty or partial.
func (s *AccountService) AccountsMigrated() bool {
	// Read the raw KV rather than demanding a typed getter: the ordinary
	// "never migrated yet" case must take the nil path, not an error path.
	setting, err := SettingsGet(vpn.DB(), accountsMigratedKey)
	if err != nil || setting == nil {
		return false
	}
	return setting.Value != ""
}
