// The ledger: profile lookup, client ownership, usage snapshots and the two
// balance moves. Ported from vpn-ui web/service/reseller.go, with the
// membership/identity resolution re-pointed at the accounts package (which
// ported those helpers with the accounts wave).
package reseller

import (
	"errors"
	"strings"

	"gorm.io/gorm"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/accounts"
	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

// accountSvc borrows the accounts layer's membership/identity resolution
// (vpn-ui called its own in-package servingInboundIds / inboundAccountEmails).
var accountSvc accounts.AccountService

// emailKey normalizes an account identity for map lookup, the same way
// OwnedEmails and sameEmail do. accounts.AccountKeyOf is the port-wide form.
func emailKey(email string) string {
	return accounts.AccountKeyOf(email)
}

// --- profile lookup -------------------------------------------------------------

// ProfileFor loads a reseller's profile. Returns ErrNotAReseller for an account
// that is not one, so a caller cannot accidentally price an admin's action.
func ProfileFor(userId int) (*model.ResellerProfile, error) {
	p := &model.ResellerProfile{}
	err := vpn.DB().Model(&model.ResellerProfile{}).
		Where("user_id = ?", userId).First(p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotAReseller
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// --- client ownership -----------------------------------------------------------
//
// Every one of these fails CLOSED, matching adminaccess's inbound access: an
// ownership question we cannot answer must never resolve to "allowed".

// OwnsClientEmail reports whether this reseller created that account.
func OwnsClientEmail(email string, userId int) (bool, error) {
	var n int64
	err := vpn.DB().Model(&model.ResellerClient{}).
		Where("email = ? AND user_id = ?", email, userId).Count(&n).Error
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// OwnedEmails is the set of accounts this reseller created, for scoping a
// panel-wide payload down to them. Lower-cased, because client emails are
// compared case-insensitively across the panel.
func OwnedEmails(userId int) (map[string]bool, error) {
	var emails []string
	err := vpn.DB().Model(&model.ResellerClient{}).
		Where("user_id = ?", userId).Pluck("email", &emails).Error
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(emails))
	for _, e := range emails {
		out[strings.ToLower(e)] = true
	}
	return out, nil
}

// ClientOwner returns the reseller row for an account, or nil when the house
// owns it. Absence is the admin case and is not an error.
func ClientOwner(email string) (*model.ResellerClient, error) {
	rc := &model.ResellerClient{}
	err := vpn.DB().Model(&model.ResellerClient{}).
		Where("email = ?", email).First(rc).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return rc, nil
}

// RenameClient carries ownership across an email change.
//
// Without it a rename orphans the row: the reseller loses the account from their
// own view and the refund path can never find it again, because the ledger is
// keyed on the panel-wide email identity.
func RenameClient(oldEmail, newEmail string) error {
	if oldEmail == "" || newEmail == "" || oldEmail == newEmail {
		return nil
	}
	return vpn.DB().Model(&model.ResellerClient{}).
		Where("email = ?", oldEmail).Update("email", newEmail).Error
}

// DropInbound settles the ledger after an inbound has been deleted. It removes a
// MEMBERSHIP, never an account.
//
// The distinction is the whole function. An account is one identity on N inbounds
// with ONE quota and ONE charge, so deleting one inbound it sits on does not end
// the sale: the other memberships keep serving it against the same charge. Keying
// this on ResellerClient.InboundId got both halves wrong at once. Delete inbound B
// while the row named A and nothing was refunded, the client vanished from B and
// the ledger kept charging; delete A and the whole charge came back while the
// account carried on selling on B and C.
//
// emails is the reseller-owned accounts that were SERVED BY that inbound and usage
// is UsageSnapshot over them. Both are parameters because both are unanswerable by
// now: the inbound's settings and its client_traffics rows went with it, and
// pricing from that wreckage reads every account as untouched and refunds the lot.
//
// Only the LAST membership going is a delete, and that one is refunded for what the
// account had left: an admin deleting the inbound out from under a reseller is not
// a sale they chose to unwind, but the bytes their customers already moved are
// still spent.
func DropInbound(inboundId int, emails []string, usage map[string]int64) error {
	db := vpn.DB()

	// Two sets. The accounts the inbound served are the sale to settle; the rows
	// whose HOME pointer named it are only a column to repair, and are usually a
	// subset of the first.
	candidates := make([]string, 0, len(emails))
	seen := map[string]bool{}
	add := func(email string) {
		key := emailKey(email)
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		candidates = append(candidates, email)
	}
	for _, email := range emails {
		add(email)
	}
	var homed []string
	if err := db.Model(&model.ResellerClient{}).
		Where("inbound_id = ?", inboundId).Pluck("email", &homed).Error; err != nil {
		return err
	}
	for _, email := range homed {
		add(email)
	}

	for _, email := range candidates {
		ids, err := accountSvc.ServingInboundIds(db, email)
		if err != nil {
			return err
		}
		if len(ids) > 0 {
			// Still served elsewhere: the account survives the inbound, so the charge
			// stands and the row stays. All that moves is the home pointer, and only
			// when it named the inbound that just went, so the column keeps naming an
			// inbound the account is really on.
			if err := db.Model(&model.ResellerClient{}).
				Where("email = ? AND inbound_id = ?", email, inboundId).
				Update("inbound_id", ids[0]).Error; err != nil {
				return err
			}
			continue
		}
		used, known := usage[emailKey(email)]
		if err := RefundDeleted(email, used, known); err != nil {
			return err
		}
	}
	return nil
}

// --- usage ----------------------------------------------------------------------

// lifetimeUsage is the LIFETIME counter the ledger bases consumption on.
//
// vpn-ui read xray.ClientTraffic.AllTime, its monotonic never-reset column. The
// target's client_traffics has no such column — Up+Down zero on every reset —
// and the target's own model documents the composition that replaces it:
// lifetime = SUM(client_traffic_windows rows) + live counters
// (model.ClientTrafficWindow). The windows table records exactly the usage a
// reset or auto-renewal zeroed, so the sum stays monotonic across resets. That
// is the property the refund rule NEEDS: resetting an account must not turn
// bytes already moved back into refundable balance.
//
// known is true only when a live client_traffics row exists — the same
// semantics as vpn-ui's snapshot, whose row was destroyed by the delete.
func lifetimeUsage(db *gorm.DB, emails []string) (map[string]int64, map[string]bool, error) {
	life := map[string]int64{}
	known := map[string]bool{}
	if len(emails) == 0 {
		return life, known, nil
	}
	keys := make([]string, 0, len(emails))
	seen := map[string]bool{}
	for _, e := range emails {
		k := emailKey(e)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return life, known, nil
	}

	var live []xray.ClientTraffic
	if err := db.Model(&xray.ClientTraffic{}).
		Select("email", "up", "down").
		Where("LOWER(TRIM(email)) IN (?)", keys).Find(&live).Error; err != nil {
		return nil, nil, err
	}
	for _, ct := range live {
		k := emailKey(ct.Email)
		life[k] += ct.Up + ct.Down
		known[k] = true
	}

	type windowRow struct {
		Email string
		Sum   int64
	}
	var windows []windowRow
	if err := db.Table("client_traffic_windows").
		Select("LOWER(TRIM(email)) as email, SUM(up + down) as sum").
		Where("LOWER(TRIM(email)) IN (?)", keys).
		Group("LOWER(TRIM(email))").Scan(&windows).Error; err != nil {
		return nil, nil, err
	}
	for _, w := range windows {
		life[w.Email] += w.Sum
	}
	return life, known, nil
}

// UsageSnapshot records how much each named account has moved in its lifetime,
// for refunding after it is deleted.
//
// MUST be called BEFORE the delete. Deleting a client removes the
// client_traffics row (and, in time, its windows), so a refund computed
// afterwards reads consumption as ZERO and hands back the entire charge. That
// is the whole balance system defeated by one button: sell an account, let the
// customer spend all of it, delete it, get every byte back.
//
// This is why no refund helper reads the counter for itself any more. The
// consumed figure has to be captured while the rows that prove it still exist,
// so it is a parameter, and the caller cannot forget to take it without the
// compiler asking where it is.
func UsageSnapshot(emails []string) (map[string]int64, error) {
	out := map[string]int64{}
	if len(emails) == 0 {
		return out, nil
	}
	life, _, err := lifetimeUsage(vpn.DB(), emails)
	if err != nil {
		return nil, err
	}
	return life, nil
}

// UsageOf is the single-account form of UsageSnapshot, with the same rule: call
// it before the delete, not after.
func UsageOf(email string) (int64, bool, error) {
	snap, err := UsageSnapshot([]string{email})
	if err != nil {
		return 0, false, err
	}
	used, known := snap[emailKey(email)]
	return used, known, nil
}

// OwnedEmailsOnInbound lists the reseller-owned accounts one inbound SERVES, so a
// caller about to delete that inbound can snapshot their usage first and hand both
// to DropInbound.
//
// Resolved from what the inbound actually holds and not from
// ResellerClient.InboundId: that column names the account's home inbound, exactly
// one of the N it may be on, so keying on it both missed accounts really served
// here (their home is elsewhere, so their usage was never snapshotted and their
// refund was silently withheld) and listed accounts that are not.
//
// Returns the LEDGER's spelling of each email, because that is what ClientOwner and
// the refund path match on.
func OwnedEmailsOnInbound(inboundId int) ([]string, error) {
	db := vpn.DB()
	served, err := accountSvc.InboundAccountEmails(db, inboundId)
	if err != nil {
		return nil, err
	}
	if len(served) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(served))
	for _, email := range served {
		keys = append(keys, emailKey(email))
	}
	var emails []string
	err = db.Model(&model.ResellerClient{}).
		Where("LOWER(TRIM(email)) IN (?)", keys).Pluck("email", &emails).Error
	return emails, err
}

// --- balance moves --------------------------------------------------------------

// addSpent moves a reseller's spent counter. Expressed as a SQL expression
// rather than read-modify-write so two concurrent client creates cannot both
// read the same value and lose one of the debits.
//
// SECURITY: a DEBIT also re-checks the balance in the same statement, and fails
// when it no longer fits. Quote's check happens against a profile read earlier
// in the request, so two concurrent creates can both see the same headroom and
// both pass: with 10 GB free, two 6 GB accounts are approved independently and
// the reseller sells 12. The WHERE clause below is the only place that decision
// is made atomically with the write, so it is the one that has to be right.
//
// Refunds are never blocked. Giving balance back must not depend on there being
// room for it, or an over-sold reseller could never be unwound.
func addSpent(tx *gorm.DB, userId int, delta int64) error {
	if delta == 0 {
		return nil
	}
	q := tx.Model(&model.ResellerProfile{}).Where("user_id = ?", userId)
	if delta > 0 {
		q = q.Where("unlimited = ? OR spent_bytes + ? <= allowance_bytes", true, delta)
	}
	res := q.Update("spent_bytes", gorm.Expr("spent_bytes + ?", delta))
	if res.Error != nil {
		return res.Error
	}
	if delta > 0 && res.RowsAffected == 0 {
		// Either the row vanished or the headroom did. Both mean this charge must
		// not stand, and the caller's reservation fails with it.
		return ErrInsufficientBalance
	}
	return nil
}

// restoreSpent moves the counter WITHOUT the headroom check, for undoing a move
// that already happened.
//
// A rollback is a correction, not a purchase, and it must never be refused. The
// case that needs it is undoing a DEDUCT: that refunded, so unwinding it debits,
// and routing that debit through the guard means an allowance an admin lowered
// in between can block the unwind. The reseller would keep the refund for a
// deduct that never landed, which is the guard causing the exact leak it exists
// to stop.
func restoreSpent(tx *gorm.DB, userId int, delta int64) error {
	if delta == 0 {
		return nil
	}
	return tx.Model(&model.ResellerProfile{}).Where("user_id = ?", userId).
		Update("spent_bytes", gorm.Expr("spent_bytes + ?", delta)).Error
}

// depletedAfter reports whether an account has already moved everything a given
// quota would allow it, and so must not be running.
//
// Reads Up+Down rather than AllTime, deliberately: this asks the same question
// the enforcement job asks (`up + down >= total`), and answering it any other
// way would let the two disagree about which accounts are alive. Total 0 is
// unlimited and never depleted.
func depletedAfter(ct *xray.ClientTraffic, total int64) bool {
	if ct == nil || total <= 0 {
		return false
	}
	return ct.Up+ct.Down >= total
}
