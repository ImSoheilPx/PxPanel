// Package adminaccess ports vpn-ui web/service/admin.go (the admin-access
// machinery behind inventory §6) into the pxpanel vpn tree.
//
// Two halves live here:
//
//   - the per-inbound ACCESS machinery (model.InboundAccess): what one admin
//     has been ASSIGNED to see. ASSIGNED, never creator-inferred:
//     Inbound.UserId is bookkeeping for the reassign flow, and access is
//     whatever a super admin ticked. Every check fails CLOSED.
//   - the ROLE machinery: super-admin / reseller flag resolution, the
//     derived-mask rules (a reseller's stored mask is ignored; the mask is
//     derived from the role) and the 14-bit permission-mask evaluation, which
//     is model.AdminFlags.Can over model.Permission (ported verbatim in
//     internal/database/model/permission.go).
//
// ADAPTATION (roles): vpn-ui carried the four role fields as columns on User
// (IsSuperAdmin / IsReseller / Enable / Permissions). pxpanel's model.User
// predates those columns, so the flags are RESOLVED rather than read:
//
//	IsSuperAdmin  — the migrateSuperAdmin invariant, frozen: exactly one, the
//	                first-seeded (lowest-id) user. vpn-ui seeded it once and
//	                let column updates move it; until the User-role columns
//	                wave lands, promotion/demotion has no storage, and the
//	                CRUD below REFUSES role writes it cannot represent rather
//	                than silently dropping them (a silently ignored
//	                "enable=false" would be a login that still works).
//	IsReseller    — existence of a ResellerProfile row (the same rule the
//	                accounts wave froze in accounts.ViewerForUser, now
//	                centralized here and registered back into that adapter).
//	Enable        — pxpanel has no disable column; every user is enabled.
//
// Every read goes through FlagsFor, so when the columns land the swap is one
// function.
//
// Like every package under internal/vpn, this file NEVER imports
// internal/database: the gorm handle comes from vpn.DB(), injected at boot
// with vpn.SetDB(database.GetDB).
package adminaccess

import (
	"encoding/json"
	"errors"

	"gorm.io/gorm"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/accounts"
	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

// accountSvc is the stateless accounts service the access checks borrow the
// membership/identity resolution from (vpn-ui called its own in-package
// helpers; the seam is the accounts package here).
var accountSvc accounts.AccountService

// --- per-inbound access ---------------------------------------------------------
//
// Access is ASSIGNED: a super admin ticks which inbounds each admin may see, and
// anything unticked is invisible to them. Inbound.UserId records who CREATED a row
// and is bookkeeping only; it does not decide access.
//
// Every one of these fails CLOSED. An access question we cannot answer must never
// resolve to "allowed".

// AccessibleInboundIds lists the inbounds this admin may see. Super admins are not
// listed in the table (they see everything by role), so callers must check
// IsSuperAdmin first; this returns only explicit grants.
//
// (vpn-ui AdminService.AccessibleInboundIds, verbatim over vpn.DB().)
func AccessibleInboundIds(userId int) ([]int, error) {
	var ids []int
	err := vpn.DB().Model(&model.InboundAccess{}).
		Where("user_id = ?", userId).Pluck("inbound_id", &ids).Error
	return ids, err
}

// CanAccessInbound reports whether userId has been granted this inbound.
func CanAccessInbound(inboundId, userId int) (bool, error) {
	var n int64
	err := vpn.DB().Model(&model.InboundAccess{}).
		Where("inbound_id = ? AND user_id = ?", inboundId, userId).Count(&n).Error
	return n > 0, err
}

// CanAccessAllInbounds reports whether userId has been granted every one of ids.
// Used by the paths whose targets come from the request body rather than the path.
func CanAccessAllInbounds(ids []int, userId int) (bool, error) {
	if len(ids) == 0 {
		return true, nil
	}
	// Distinct: a body may name the same inbound twice, which would undercount.
	uniq := make(map[int]struct{}, len(ids))
	for _, id := range ids {
		uniq[id] = struct{}{}
	}
	want := make([]int, 0, len(uniq))
	for id := range uniq {
		want = append(want, id)
	}
	var n int64
	err := vpn.DB().Model(&model.InboundAccess{}).
		Where("inbound_id IN (?) AND user_id = ?", want, userId).Count(&n).Error
	if err != nil {
		return false, err
	}
	return int(n) == len(want), nil
}

// CanAccessClientEmail reports whether userId has been granted ANY inbound serving
// this client. Client emails are a single panel-wide namespace, so an :email route
// reaches across admins without this.
//
// "Any", not "the": one account is served on N inbounds, and the join this used to
// be (inbound_accesses against client_traffics.inbound_id) asked about exactly one
// of them, the one that account's single traffic row happens to name. An admin
// holding inbound B but not A was therefore DENIED every :email route for a client
// sitting in their own inbound, which reads as the panel losing the account.
//
// Resolved through the accounts layer's servingInboundIds so this and
// ClientEmailAccess answer the same question the same way; two access checks that
// disagree are how a route ends up enforcing something the payload producer never
// scoped for.
func CanAccessClientEmail(email string, userId int) (bool, error) {
	db := vpn.DB()
	ids, err := accountSvc.ServingInboundIds(db, email)
	if err != nil {
		return false, err
	}
	if len(ids) == 0 {
		// No inbound serves it, so no grant can reach it. Fails closed, like every
		// other unanswerable access question here.
		return false, nil
	}
	var n int64
	err = db.Model(&model.InboundAccess{}).
		Where("inbound_id IN (?) AND user_id = ?", ids, userId).Count(&n).Error
	return n > 0, err
}

// GrantInbound gives one admin access to one inbound. Idempotent.
// Called when an admin creates an inbound: without it they could not see the thing
// they just made.
func GrantInbound(userId, inboundId int) error {
	if userId <= 0 || inboundId <= 0 {
		return nil
	}
	var n int64
	db := vpn.DB()
	if err := db.Model(&model.InboundAccess{}).
		Where("user_id = ? AND inbound_id = ?", userId, inboundId).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	return db.Create(&model.InboundAccess{UserId: userId, InboundId: inboundId}).Error
}

// SetInboundAccess replaces an admin's grants with exactly inboundIds.
func SetInboundAccess(userId int, inboundIds []int) error {
	return vpn.DB().Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userId).Delete(&model.InboundAccess{}).Error; err != nil {
			return err
		}
		for _, id := range inboundIds {
			if id <= 0 {
				continue
			}
			if err := tx.Create(&model.InboundAccess{UserId: userId, InboundId: id}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// RevokeInboundEverywhere drops every grant for an inbound, for use when it is
// deleted. Without it the rows linger and a recycled inbound id would silently
// inherit the old grants.
func RevokeInboundEverywhere(inboundId int) error {
	return vpn.DB().Where("inbound_id = ?", inboundId).Delete(&model.InboundAccess{}).Error
}

// ClientEmailAccess maps every client email to the set of admins granted an inbound
// SERVING it, so a producer can scope a panel-wide payload down to each audience.
//
// The plural matters here for the same reason it does in CanAccessClientEmail: an
// account lives on N inbounds and the join this used to be resolved one of them, so
// an admin holding only the others saw none of their own clients in the traffic
// broadcast or the online list while the single-account check waved them through.
// Both now go through the same three-source union, so they cannot disagree.
//
// Keyed by every spelling of an identity the panel stores, not just one. Callers
// index this with an email taken from wherever their payload came from
// (client_traffics for the traffic rows, an Xray stat name for the online list,
// which carries the settings spelling), and those differ in case on real panels.
// A single-spelling map silently hid a client from its own admin.
func ClientEmailAccess() (map[string]map[int]bool, error) {
	db := vpn.DB()
	if db == nil {
		return map[string]map[int]bool{}, nil
	}

	var grants []model.InboundAccess
	if err := db.Model(&model.InboundAccess{}).Find(&grants).Error; err != nil {
		return nil, err
	}
	adminsByInbound := make(map[int]map[int]bool, len(grants))
	for _, g := range grants {
		if adminsByInbound[g.InboundId] == nil {
			adminsByInbound[g.InboundId] = map[int]bool{}
		}
		adminsByInbound[g.InboundId][g.UserId] = true
	}

	// key -> inbounds serving it, and key -> every spelling seen. Built from the
	// same three sources the accounts layer's servingInboundIds unions, in one
	// pass rather than one query per account: this runs on the traffic broadcast's
	// tick.
	idsByKey := map[string]map[int]bool{}
	spellings := map[string][]string{}
	note := func(email string, inboundId int) {
		key := accounts.AccountKeyOf(email)
		if key == "" {
			return
		}
		if idsByKey[key] == nil {
			idsByKey[key] = map[int]bool{}
			spellings[key] = []string{key}
		}
		if inboundId > 0 {
			idsByKey[key][inboundId] = true
		}
		for _, seen := range spellings[key] {
			if seen == email {
				return
			}
		}
		spellings[key] = append(spellings[key], email)
	}

	var inbounds []*model.Inbound
	if err := db.Model(&model.Inbound{}).Select("id", "settings").Find(&inbounds).Error; err != nil {
		return nil, err
	}
	live := make(map[int]bool, len(inbounds))
	for _, inbound := range inbounds {
		live[inbound.Id] = true
		clients, ok := parseSettingsClients(inbound.Settings)
		if !ok {
			continue
		}
		for _, entry := range clients {
			email, _ := entry["email"].(string)
			note(email, inbound.Id)
		}
	}

	type membershipRow struct {
		Email     string
		InboundId int
	}
	var members []membershipRow
	if err := db.Table("account_inbounds").
		Select("accounts.email as email, account_inbounds.inbound_id as inbound_id").
		Joins("JOIN accounts ON accounts.id = account_inbounds.account_id").
		Scan(&members).Error; err != nil {
		return nil, err
	}
	for _, m := range members {
		if !live[m.InboundId] {
			continue // a membership outliving its inbound grants nothing
		}
		note(m.Email, m.InboundId)
	}

	var traffics []xray.ClientTraffic
	if err := db.Model(&xray.ClientTraffic{}).Select("email", "inbound_id").Find(&traffics).Error; err != nil {
		return nil, err
	}
	for _, ct := range traffics {
		if !live[ct.InboundId] {
			note(ct.Email, 0) // record the spelling; a dead inbound grants nothing
			continue
		}
		note(ct.Email, ct.InboundId)
	}

	out := make(map[string]map[int]bool, len(idsByKey))
	for key, ids := range idsByKey {
		admins := map[int]bool{}
		for id := range ids {
			for userId := range adminsByInbound[id] {
				admins[userId] = true
			}
		}
		if len(admins) == 0 {
			continue
		}
		for _, spelling := range spellings[key] {
			out[spelling] = admins
		}
	}
	return out, nil
}

// parseSettingsClients pulls the clients array out of a settings blob. The same
// three-line parse the accounts layer runs; duplicated here rather than widening
// that package's surface, because the shape it returns (raw JSON maps) is a
// projection detail the accounts wave deliberately keeps private.
func parseSettingsClients(settings string) ([]map[string]any, bool) {
	if settings == "" {
		return nil, false
	}
	root := map[string]any{}
	if err := json.Unmarshal([]byte(settings), &root); err != nil {
		return nil, false
	}
	clients, _ := root["clients"].([]any)
	if len(clients) == 0 {
		return nil, false
	}
	out := make([]map[string]any, 0, len(clients))
	for _, raw := range clients {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, entry)
	}
	return out, true
}

// --- role lookups over the access table ------------------------------------------

// SuperAdminIds returns the ids of the enabled super admins.
//
// vpn-ui read is_super_admin AND enable off the row. pxpanel has neither column,
// so the migrateSuperAdmin invariant is resolved instead: exactly one super
// admin, the first-seeded (lowest-id) user, and every pxpanel user is enabled.
func SuperAdminIds() (map[int]bool, error) {
	superId, err := SuperAdminId()
	if err != nil {
		return nil, err
	}
	if superId <= 0 {
		return map[int]bool{}, nil
	}
	return map[int]bool{superId: true}, nil
}

// SuperAdminId resolves THE super admin: the lowest-id user, or 0 when no user
// exists yet. See the package comment for why this is a derivation here.
func SuperAdminId() (int, error) {
	db := vpn.DB()
	if db == nil {
		return 0, nil
	}
	var lowestId int
	if err := db.Model(&model.User{}).Select("COALESCE(MIN(id), 0)").Scan(&lowestId).Error; err != nil {
		return 0, err
	}
	return lowestId, nil
}

// InboundBrief is one inbound as the Admins access checklist needs it: enough to
// identify it, and nothing else. Deliberately not the whole row, which carries the
// Settings blob with every client's credentials.
type InboundBrief struct {
	Id       int    `json:"id"`
	Remark   string `json:"remark"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

// AllInboundsBrief lists every inbound for the access checklist.
func AllInboundsBrief() ([]InboundBrief, error) {
	var out []InboundBrief
	err := vpn.DB().Model(&model.Inbound{}).
		Select("id", "remark", "protocol", "port").Order("id asc").Scan(&out).Error
	if out == nil {
		out = []InboundBrief{}
	}
	return out, err
}

// ReassignInbounds moves every inbound owned by one admin to another, so a super
// admin can empty an account before deleting it.
func ReassignInbounds(fromId, toId int) (int64, error) {
	db := vpn.DB()
	if fromId == toId {
		return 0, errors.New("source and destination admin are the same")
	}
	var n int64
	if err := db.Model(&model.User{}).Where("id = ?", toId).Count(&n).Error; err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, ErrAdminNotFound
	}
	res := db.Model(&model.Inbound{}).Where("user_id = ?", fromId).Update("user_id", toId)
	return res.RowsAffected, res.Error
}

// OwnedInboundCount counts the inbounds whose user_id (creator bookkeeping)
// points at this user — the "what would a delete strand" figure the Admins list
// and DeleteAdmin's guard both need.
func OwnedInboundCount(db *gorm.DB, userId int) (int64, error) {
	var owned int64
	err := db.Model(&model.Inbound{}).Where("user_id = ?", userId).Count(&owned).Error
	return owned, err
}

// GrantsByUser loads every InboundAccess row and groups the inbound ids by user,
// for list views (the Admins page's checklist column). One query rather than one
// per admin.
func GrantsByUser(db *gorm.DB, userIds []int) (map[int][]int, error) {
	var grants []model.InboundAccess
	q := db.Model(&model.InboundAccess{})
	if len(userIds) > 0 {
		q = q.Where("user_id IN (?)", userIds)
	}
	if err := q.Find(&grants).Error; err != nil {
		return nil, err
	}
	out := make(map[int][]int, len(grants))
	for _, g := range grants {
		out[g.UserId] = append(out[g.UserId], g.InboundId)
	}
	return out, nil
}
