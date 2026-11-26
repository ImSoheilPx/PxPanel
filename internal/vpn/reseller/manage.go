// Reseller profile CRUD: the Resellers page's list/add/update/recharge/delete,
// ported from vpn-ui web/service/reseller.go.
//
// ADAPTATIONS:
//   - the caller is accounts.Viewer (role snapshot), as everywhere in this
//     package; the super-admin / manage-anything rules resolve through
//     adminaccess (CreatedBy scoping stays a profile-column query).
//   - AddReseller creates the user row with a bcrypt password. vpn-ui also wrote
//     IsReseller / Enable / Permissions columns, which pxpanel's User does not
//     have: the ROLE is the ResellerProfile row (adminaccess.IsReseller derives
//     from it), the mask is derived and stays zero by construction, and Enable
//     has no storage — an operator asking for a disabled reseller gets a refusal,
//     not a row that can log in.
//   - the cascade delete's per-inbound client removal (vpn-ui
//     InboundService.DelInboundClientByEmail) is the RemoveClientFromInbound
//     seam, registered by the inbound wave. Unwired, a cascade refuses rather
//     than leaving half the accounts it was asked to delete live.
package reseller

import (
	"errors"
	"strings"

	"gorm.io/gorm"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/util/crypto"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/accounts"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/adminaccess"
)

// RemoveClientFromInbound is the inbound plane's "remove this account from one
// inbound's settings (and its daemon / core, as the layer sees fit)": vpn-ui's
// InboundService.DelInboundClientByEmail, which returns whether the live Xray
// API could not drop the user (needing a restart) and an error when the client
// was not found — the cascade treats a not-found as already gone.
//
// The inbound wave registers its implementation (RegisterRemoveClientFromInbound).
// Unwired, cascadeClients returns ErrInboundPlaneUnavailable: refusing the whole
// cascade beats half-applying it, because a half-applied cascade leaves live
// accounts whose ledger rows are already gone.
var RemoveClientFromInbound func(inboundId int, email string) (needXrayRestart bool, err error)

// ErrInboundPlaneUnavailable is what a cascade delete reports while the inbound
// wave has not registered its client-removal seam.
var ErrInboundPlaneUnavailable = errors.New("reseller cascade delete needs the inbound layer's client removal, which is not wired yet")

// RegisterRemoveClientFromInbound attaches the inbound wave's client removal.
// One call, from that package's init only.
func RegisterRemoveClientFromInbound(fn func(inboundId int, email string) (bool, error)) {
	RemoveClientFromInbound = fn
}

// ResellerView is a reseller as the Resellers page shows it. Hand-built rather
// than returning model.User so the password hash and TOTP secret can never be
// serialized.
type ResellerView struct {
	Id              int    `json:"id"`
	Username        string `json:"username"`
	Nickname        string `json:"nickname"`
	Enable          bool   `json:"enable"`
	TwoFactorEnable bool   `json:"twoFactorEnable"`

	AllowanceBytes int64 `json:"allowanceBytes"`
	SpentBytes     int64 `json:"spentBytes"`
	AvailableBytes int64 `json:"availableBytes"`
	Unlimited      bool  `json:"unlimited"`

	DaysPerGB           int  `json:"daysPerGb"`
	MinCreateGB         int  `json:"minCreateGb"`
	MinAddGB            int  `json:"minAddGb"`
	AllowExternalProxy  bool `json:"allowExternalProxy"`
	AllowOverview       bool `json:"allowOverview"`
	AllowOverviewManage bool `json:"allowOverviewManage"`

	InboundIds  []int `json:"inboundIds"`
	ClientCount int64 `json:"clientCount"`
	CreatedBy   int   `json:"createdBy"`
}

// ResellerSpec is the mutable shape of a reseller as the UI submits it.
type ResellerSpec struct {
	Username string
	// Password empty on update means "keep the existing one".
	Password string
	Nickname string
	Enable   bool

	// AllowanceGB seeds the balance on CREATE and is ignored on update, where
	// Recharge is the only way to move it: an admin typing over the total would
	// silently rewrite history and either free or strand every outstanding
	// account.
	AllowanceGB int
	Unlimited   bool

	DaysPerGB           int
	MinCreateGB         int
	MinAddGB            int
	AllowExternalProxy  bool
	AllowOverview       bool
	AllowOverviewManage bool

	// InboundIds is the exact set this reseller may sell on. Replaces whatever
	// they had; empty means none, which is a legitimate state.
	InboundIds []int
}

// GetResellers lists the resellers this caller may manage. A super admin sees
// every one; anyone else sees only those they created.
func GetResellers(caller accounts.Viewer) ([]ResellerView, error) {
	if caller.Id == 0 {
		return []ResellerView{}, nil
	}
	db := vpn.DB()

	var profiles []model.ResellerProfile
	q := db.Model(&model.ResellerProfile{})
	if !caller.IsSuperAdmin {
		q = q.Where("created_by = ?", caller.Id)
	}
	if err := q.Find(&profiles).Error; err != nil {
		return nil, err
	}
	if len(profiles) == 0 {
		return []ResellerView{}, nil
	}

	ids := make([]int, 0, len(profiles))
	byUser := make(map[int]model.ResellerProfile, len(profiles))
	for _, p := range profiles {
		ids = append(ids, p.UserId)
		byUser[p.UserId] = p
	}

	var users []*model.User
	if err := db.Model(&model.User{}).Where("id IN (?)", ids).
		Order("id asc").Find(&users).Error; err != nil {
		return nil, err
	}

	// One query each for grants and account counts, rather than one per reseller.
	grantsBy, err := adminaccess.GrantsByUser(db, ids)
	if err != nil {
		return nil, err
	}

	type countRow struct {
		UserId int
		N      int64
	}
	var counts []countRow
	if err := db.Model(&model.ResellerClient{}).Where("user_id IN (?)", ids).
		Select("user_id as user_id, count(*) as n").Group("user_id").Scan(&counts).Error; err != nil {
		return nil, err
	}
	countBy := make(map[int]int64, len(counts))
	for _, c := range counts {
		countBy[c.UserId] = c.N
	}

	out := make([]ResellerView, 0, len(users))
	for _, u := range users {
		p := byUser[u.Id]
		gs := grantsBy[u.Id]
		if gs == nil {
			gs = []int{} // marshal as [], not null: the UI ticks against it
		}
		available := p.AllowanceBytes - p.SpentBytes
		if available < 0 {
			available = 0
		}
		out = append(out, ResellerView{
			Id:                  u.Id,
			Username:            u.Username,
			Enable:              true, // no disable column yet
			AllowanceBytes:      p.AllowanceBytes,
			SpentBytes:          p.SpentBytes,
			AvailableBytes:      available,
			Unlimited:           p.Unlimited,
			DaysPerGB:           p.DaysPerGB,
			MinCreateGB:         p.MinCreateGB,
			MinAddGB:            p.MinAddGB,
			AllowExternalProxy:  p.AllowExternalProxy,
			AllowOverview:       p.AllowOverview,
			AllowOverviewManage: p.AllowOverviewManage,
			InboundIds:          gs,
			ClientCount:         countBy[u.Id],
			CreatedBy:           p.CreatedBy,
		})
	}
	return out, nil
}

// assertAssignable refuses inbounds the caller does not hold themselves.
//
// This is the clamp that closes the escalation: without it an admin holding
// manageResellers creates a reseller on ANOTHER admin's inbound, sets its
// password, logs in as it, and is now looking at inbounds they were never
// granted. A checklist that only renders the intersection is cosmetic; the save
// is one crafted form away, so the check has to be here.
func assertAssignable(caller accounts.Viewer, inboundIds []int) error {
	if caller.Id == 0 {
		return ErrInboundNotAssignable
	}
	if caller.IsSuperAdmin || len(inboundIds) == 0 {
		return nil
	}
	ok, err := adminaccess.CanAccessAllInbounds(inboundIds, caller.Id)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInboundNotAssignable
	}
	return nil
}

// AssignableInbounds is the checklist a caller may pick from: every inbound for
// a super admin, only their own for anyone else.
func AssignableInbounds(caller accounts.Viewer) ([]adminaccess.InboundBrief, error) {
	all, err := adminaccess.AllInboundsBrief()
	if err != nil {
		return nil, err
	}
	if caller.Id == 0 {
		return []adminaccess.InboundBrief{}, nil
	}
	if caller.IsSuperAdmin {
		return all, nil
	}
	ids, err := adminaccess.AccessibleInboundIds(caller.Id)
	if err != nil {
		return nil, err
	}
	allowed := make(map[int]bool, len(ids))
	for _, id := range ids {
		allowed[id] = true
	}
	out := make([]adminaccess.InboundBrief, 0, len(all))
	for _, b := range all {
		if allowed[b.Id] {
			out = append(out, b)
		}
	}
	return out, nil
}

// AddReseller creates a reseller and its profile.
func AddReseller(caller accounts.Viewer, spec ResellerSpec) (*model.User, error) {
	spec.Username = adminaccess.NormalizeUsername(spec.Username)
	if spec.Username == "" {
		return nil, errors.New("username is required")
	}
	if spec.Password == "" {
		return nil, errors.New("password is required")
	}
	if !spec.Enable {
		// No enable column: a "disabled" reseller would be stored able to log in.
		// Refused, not silently enabled.
		return nil, errEnableNotStorable
	}
	if err := assertAssignable(caller, spec.InboundIds); err != nil {
		return nil, err
	}

	db := vpn.DB()
	taken, err := adminaccess.UsernameTaken(db, spec.Username, 0)
	if err != nil {
		return nil, err
	}
	if taken {
		return nil, ErrResellerNameTaken
	}
	hash, err := crypto.HashPasswordAsBcrypt(spec.Password)
	if err != nil {
		return nil, err
	}

	user := &model.User{
		Username: spec.Username,
		Password: hash,
	}
	// The role columns vpn-ui wrote here are DERIVED in pxpanel: IsReseller from
	// the profile row created below, the permission mask from the role (and so
	// stays 0 — a future demotion lands them with nothing rather than with a
	// stale grant), IsSuperAdmin never. Enable is refused above.
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			return err
		}
		return tx.Create(&model.ResellerProfile{
			UserId:              user.Id,
			AllowanceBytes:      gbToBytes(spec.AllowanceGB),
			Unlimited:           spec.Unlimited,
			DaysPerGB:           spec.DaysPerGB,
			MinCreateGB:         spec.MinCreateGB,
			MinAddGB:            spec.MinAddGB,
			AllowExternalProxy:  spec.AllowExternalProxy,
			AllowOverview:       spec.AllowOverview,
			AllowOverviewManage: spec.AllowOverviewManage,
			CreatedBy:           caller.Id,
		}).Error
	})
	if err != nil {
		return nil, err
	}
	if err := adminaccess.SetInboundAccess(user.Id, spec.InboundIds); err != nil {
		return nil, err
	}
	return user, nil
}

// errEnableNotStorable refuses the enable flag until pxpanel's User has the
// column: storing a disabled reseller as able to log in is the exact bug the
// vpn-ui transaction guarded against.
var errEnableNotStorable = errors.New("pxpanel's user table has no enable column yet; a disabled reseller cannot be stored (lands with the user-roles wave)")

// manageable loads a reseller the caller is allowed to touch, or reports it as
// not found. Not-found rather than forbidden, so the endpoint cannot be used to
// enumerate other admins' resellers.
func manageable(caller accounts.Viewer, id int) (*model.User, *model.ResellerProfile, error) {
	if caller.Id == 0 {
		return nil, nil, ErrResellerNotFound
	}
	user := &model.User{}
	if err := vpn.DB().Model(&model.User{}).Where("id = ?", id).First(user).Error; err != nil {
		return nil, nil, ErrResellerNotFound
	}
	isReseller, err := adminaccess.IsReseller(id)
	if err != nil || !isReseller {
		return nil, nil, ErrResellerNotFound
	}
	profile, err := ProfileFor(id)
	if err != nil {
		return nil, nil, ErrResellerNotFound
	}
	if !caller.IsSuperAdmin && profile.CreatedBy != caller.Id {
		return nil, nil, ErrResellerNotFound
	}
	return user, profile, nil
}

// UpdateReseller edits a reseller. An empty password leaves the existing one
// alone. AllowanceGB is ignored here; see Recharge.
func UpdateReseller(caller accounts.Viewer, id int, spec ResellerSpec) error {
	user, _, err := manageable(caller, id)
	if err != nil {
		return err
	}
	spec.Username = adminaccess.NormalizeUsername(spec.Username)
	if spec.Username == "" {
		return errors.New("username is required")
	}
	if !spec.Enable {
		return errEnableNotStorable
	}
	if err := assertAssignable(caller, spec.InboundIds); err != nil {
		return err
	}

	db := vpn.DB()
	taken, err := adminaccess.UsernameTaken(db, spec.Username, id)
	if err != nil {
		return err
	}
	if taken {
		return ErrResellerNameTaken
	}

	updates := map[string]any{
		"username": spec.Username,
		// Re-asserted on every save so a row that acquired a mask some other way
		// cannot keep it — and in pxpanel the stored mask stays 0 for a reseller
		// by construction, so this is the same assertion with no column to
		// forget (vpn-ui also reset permissions=0 / is_super_admin=false /
		// is_reseller=true here).
	}
	if spec.Password != "" {
		hash, err := crypto.HashPasswordAsBcrypt(spec.Password)
		if err != nil {
			return err
		}
		updates["password"] = hash
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.User{}).Where("id = ?", user.Id).Updates(updates).Error; err != nil {
			return err
		}
		return tx.Model(&model.ResellerProfile{}).Where("user_id = ?", user.Id).
			Updates(map[string]any{
				"unlimited":             spec.Unlimited,
				"days_per_gb":           spec.DaysPerGB,
				"min_create_gb":         spec.MinCreateGB,
				"min_add_gb":            spec.MinAddGB,
				"allow_external_proxy":  spec.AllowExternalProxy,
				"allow_overview":        spec.AllowOverview,
				"allow_overview_manage": spec.AllowOverviewManage,
			}).Error
	})
	if err != nil {
		return err
	}
	return adminaccess.SetInboundAccess(user.Id, spec.InboundIds)
}

// Recharge moves a reseller's allowance. Positive tops them up; negative takes
// back, clamped so an allowance never goes below zero.
func Recharge(caller accounts.Viewer, id int, deltaBytes int64) error {
	_, profile, err := manageable(caller, id)
	if err != nil {
		return err
	}
	next := profile.AllowanceBytes + deltaBytes
	if next < 0 {
		next = 0
	}
	return vpn.DB().Model(&model.ResellerProfile{}).
		Where("user_id = ?", id).Update("allowance_bytes", next).Error
}

// Delete modes decide the fate of a reseller's accounts when it still owns some.
const (
	DeleteModeKeep    = "keep"    // drop the reseller, hand its accounts to the house
	DeleteModeCascade = "cascade" // drop the reseller and delete its accounts
)

// DeleteResult reports what a delete touched so the controller can reconfigure
// the daemons whose clients a cascade removed. Zero-valued for a keep or a
// childless reseller: nothing on the data plane changed, nothing to regenerate.
type DeleteResult struct {
	Protocols       map[model.Protocol]bool // VPN daemon protocols to regenerate, deduped
	NeedXrayRestart bool                    // a native client the live Xray API could not drop
	Deleted         int                     // accounts the cascade removed
	Kept            int                     // last-on-inbound / stale accounts handed to the house
}

// DeleteReseller removes a reseller. With accounts still owned, mode decides
// their fate: "cascade" deletes them the same way the per-account delete route
// does, "keep" hands them to the house (absence of a ResellerClient row is
// exactly "the admin owns this account"). An empty mode with accounts present
// refuses, as it always has, so the destructive path is never the default and an
// old client or a script cannot silently destroy or orphan accounts.
//
// On cascade the accounts are removed BEFORE the reseller, so a mid-cascade
// failure leaves "some accounts gone, reseller still owns the rest" (retryable)
// rather than a deleted reseller with live accounts nobody bills.
func DeleteReseller(caller accounts.Viewer, id int, mode string) (DeleteResult, error) {
	user, _, err := manageable(caller, id)
	if err != nil {
		return DeleteResult{}, err
	}
	db := vpn.DB()
	var rows []model.ResellerClient
	if err := db.Where("user_id = ?", id).Find(&rows).Error; err != nil {
		return DeleteResult{}, err
	}
	if len(rows) == 0 {
		return DeleteResult{}, dropReseller(user.Id) // childless: mode is moot
	}
	switch mode {
	case DeleteModeKeep:
		// The accounts stay byte-for-byte; only the ownership ledger goes, which
		// makes them house-owned and visible to the inbound's admin.
		if err := db.Where("user_id = ?", id).Delete(&model.ResellerClient{}).Error; err != nil {
			return DeleteResult{}, err
		}
		return DeleteResult{}, dropReseller(user.Id)
	case DeleteModeCascade:
		res, err := cascadeClients(rows)
		if err != nil {
			return res, err // stop before dropping the reseller so a retry is possible
		}
		return res, dropReseller(user.Id)
	default:
		return DeleteResult{}, errClientsNeedMode(len(rows))
	}
}

// errClientsNeedMode is DeleteReseller's refusal when accounts remain and no
// mode was named (vpn-ui wrapped ErrResellerHasClients with the count).
func errClientsNeedMode(n int) error {
	return &ClientsNeedModeError{Owned: n}
}

// ClientsNeedModeError is the typed form of that refusal.
type ClientsNeedModeError struct{ Owned int }

func (e *ClientsNeedModeError) Error() string {
	return "this reseller still owns accounts; delete them first"
}

// Unwrap hands back the sentinel so errors.Is(err, ErrResellerHasClients) keeps
// working across the port.
func (e *ClientsNeedModeError) Unwrap() error { return ErrResellerHasClients }

// dropReseller removes the reseller row, its profile and its inbound grants once
// the accounts have been dealt with. The balance vanishes with the profile: a
// deleted reseller has nothing to refund to.
func dropReseller(userId int) error {
	return vpn.DB().Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userId).Delete(&model.ResellerProfile{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", userId).Delete(&model.InboundAccess{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", userId).Delete(&model.User{}).Error
	})
}

// cascadeClients deletes every VPN account a reseller owns the same way the
// single-account delete route does (settings surgery, IP release, traffic-row
// removal, live Xray RemoveUser) and drops each ledger row. It returns the set
// of daemon protocols it touched so the caller can regenerate their configs.
//
// EVERY membership of each account, not the one its ledger row names. An account
// is one identity on N inbounds, and deleting it from the single inbound recorded
// in ResellerClient.InboundId left N-1 live memberships behind with no ledger row,
// which by this table's own rule means the house owns them: a working account,
// serving traffic, that nobody is billed for and no reseller page shows.
//
// An account is handed to the house instead of deleted when it is STILL SERVED
// somewhere after the cascade has done what it can, or when it was already gone
// (a stale ledger row). Neither aborts the cascade, and the ledger row goes either
// way, because the reseller it belongs to is being deleted and a charge against a
// user that no longer exists can never be settled.
//
// That "still served" test is the load-bearing rule of this function and is checked
// against the database at the end, not inferred from what the removal loop managed
// to do. The reseller's ledger row is dropped unconditionally, so an account this
// function leaves behind is a live, working client that nobody is billed for; if it
// is also miscounted as deleted, nothing anywhere will ever surface it.
func cascadeClients(rows []model.ResellerClient) (DeleteResult, error) {
	res := DeleteResult{Protocols: map[model.Protocol]bool{}}
	db := vpn.DB()
	if RemoveClientFromInbound == nil {
		return res, ErrInboundPlaneUnavailable
	}
	dropLedger := func(email string) error {
		return db.Where("email = ?", email).Delete(&model.ResellerClient{}).Error
	}
	for _, rc := range rows {
		ids, err := accountSvc.ServingInboundIds(db, rc.Email)
		if err != nil {
			return res, err
		}
		removed := 0
		for _, id := range ids {
			inbound := &model.Inbound{}
			if err := db.Model(&model.Inbound{}).First(inbound, id).Error; err != nil {
				continue // gone between resolving and now: nothing left to remove
			}
			// The ledger's own spelling is handed over as-is. The removal seam
			// matches the settings entry on accountKey, so an account whose
			// tables spell it differently is found.
			needRestart, err := RemoveClientFromInbound(id, rc.Email)
			if err != nil {
				// "not found" only: already gone from this one, which is not a failure.
				if !strings.Contains(err.Error(), "not found") {
					return res, err
				}
				continue
			}
			res.Protocols[inbound.Protocol] = true
			res.NeedXrayRestart = res.NeedXrayRestart || needRestart
			removed++
		}
		if derr := dropLedger(rc.Email); derr != nil {
			return res, derr
		}

		// Reported by what became of the ACCOUNT, not by how many memberships moved:
		// an account still serving ANYWHERE was handed to the house, whatever else the
		// cascade managed to remove. The ledger row has just gone, so a survivor is a
		// live, working, unbilled client and must not be counted as deleted.
		//
		// Asked of the database rather than inferred from the loop above.
		//
		// settings.clients ONLY, which is why this is
		// accounts.InboundIdsServingEmailsTx and not the ServingInboundIds that
		// drove the removal loop. That one unions account_inbounds and
		// client_traffics.inbound_id as well, and a membership outlives the
		// settings entry it described, so asking it here would report every
		// cascaded account as a survivor and nothing would ever be counted
		// deleted. Being served is a property of the settings blob: it is what
		// RADIUS, the daemon config writers and the Xray config builder all read.
		stillServed, serr := accounts.InboundIdsServingEmailsTx(db, []string{rc.Email})
		if serr != nil {
			return res, serr
		}
		if len(stillServed) > 0 || removed == 0 {
			res.Kept++
			continue
		}
		res.Deleted++
	}
	return res, nil
}
