// Role resolution + the Admins-page CRUD, ported from vpn-ui web/service/admin.go
// onto the role model documented in the package comment: the four vpn-ui User
// role columns are RESOLVED here, not read off the row, and the mutation paths
// REFUSE what they cannot represent instead of silently dropping it.
package adminaccess

import (
	"errors"
	"strings"

	"gorm.io/gorm"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/util/crypto"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
)

var (
	ErrAdminUsernameTaken = errors.New("that username is already taken")
	ErrAdminNotFound      = errors.New("admin not found")
	ErrLastSuperAdmin     = errors.New("this is the only super admin; promote another one first")
	// Role writes pxpanel's User cannot store yet. Each is a refusal, not a
	// silent drop: an "update" that reports success while leaving the account
	// enabled / promoted / re-permissioned is worse than a 400.
	ErrUnrepresentableRole = errors.New("pxpanel's user table has no role columns yet; this role change cannot be stored (lands with the user-roles wave)")
)

// FlagsFor resolves a user's role snapshot (vpn-ui's IsSuperAdmin / IsReseller /
// Enable / Permissions read off the row). Enable is always true — pxpanel has no
// disable column — and a reseller clears the super-admin bit, matching the
// never-both invariant vpn-ui's ResellerService enforced on the columns.
//
// THE single read path for roles in the ported reseller/admin machinery; when
// model.User grows the columns, this function is the one that changes.
func FlagsFor(userId int) (model.AdminFlags, error) {
	db := vpn.DB()
	flags := model.AdminFlags{Enable: true}
	if db == nil {
		return flags, nil
	}
	isReseller, err := IsReseller(userId)
	if err != nil {
		return flags, err
	}
	if isReseller {
		flags.IsReseller = true
		return flags, nil
	}
	superId, err := SuperAdminId()
	if err != nil {
		return flags, err
	}
	flags.IsSuperAdmin = superId == userId
	return flags, nil
}

// IsSuperAdmin reports whether userId is THE super admin (lowest-id rule).
func IsSuperAdmin(userId int) bool {
	if userId <= 0 {
		return false
	}
	superId, err := SuperAdminId()
	if err != nil {
		return false // fail closed on a lookup we cannot answer
	}
	return superId == userId
}

// IsReseller reports whether a ResellerProfile row exists for the user. ABSENCE
// is the admin case and is not an error.
func IsReseller(userId int) (bool, error) {
	db := vpn.DB()
	if db == nil {
		return false, nil
	}
	var n int64
	if err := db.Model(&model.ResellerProfile{}).Where("user_id = ?", userId).Count(&n).Error; err != nil {
		return false, err
	}
	return n > 0, nil
}

// Can reports whether the user may do perm — vpn-ui's User.Can, expressed over
// the resolved flags. Super admins bypass the mask entirely (which is why they
// are the only account type that can reach the escalation-class endpoints); a
// reseller's mask is DERIVED from the role (model.resellerPerms), so a stale or
// tampered stored mask cannot widen it; everyone else answers from their mask.
func Can(userId int, perm model.Permission) (bool, error) {
	flags, err := FlagsFor(userId)
	if err != nil {
		return false, err
	}
	return flags.Can(perm), nil
}

// normalizeUsername trims and lowercases. Usernames are matched exactly at login
// against a unique index, so folding case here stops "Admin" and "admin" from
// being two accounts that look identical in the list.
func normalizeUsername(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// NormalizeUsername is the exported form (the reseller CRUD shares it).
func NormalizeUsername(name string) string { return normalizeUsername(name) }

// UsernameTaken reports whether another user already holds the username.
// (vpn-ui AdminService.usernameTaken, exported for the reseller CRUD.)
func UsernameTaken(db *gorm.DB, username string, exceptId int) (bool, error) {
	var n int64
	q := db.Model(&model.User{}).Where("username = ?", username)
	if exceptId > 0 {
		q = q.Where("id != ?", exceptId)
	}
	if err := q.Count(&n).Error; err != nil {
		return false, err
	}
	return n > 0, nil
}

// isLastSuperAdmin reports whether id is the only super admin. Under the derived
// rule there is at most one, so the answer is "id IS the super admin". The
// vpn-ui shape is kept (a count over others) so the columns wave swaps the body,
// not the callers.
func isLastSuperAdmin(db *gorm.DB, id int) (bool, error) {
	superId, err := SuperAdminId()
	if err != nil {
		return false, err
	}
	return superId == id, nil
}

// --- Admins-page CRUD ------------------------------------------------------------

// AdminView is an admin as shown to the UI. Deliberately hand-built rather than
// returning model.User: it carries the permission slugs, and it keeps the password
// hash and TOTP secret from ever being serialized.
type AdminView struct {
	Id              int      `json:"id"`
	Username        string   `json:"username"`
	Nickname        string   `json:"nickname"`
	IsSuperAdmin    bool     `json:"isSuperAdmin"`
	Enable          bool     `json:"enable"`
	TwoFactorEnable bool     `json:"twoFactorEnable"`
	Permissions     []string `json:"permissions"`
	InboundCount    int64    `json:"inboundCount"`
	// InboundIds is what this admin may see, for the modal's checklist. Always [] for
	// a super admin: they see everything by role, not by grant.
	InboundIds []int `json:"inboundIds"`
}

// GetAdmins lists every admin, with how many inbounds each owns so the super admin
// can see what a delete would strand.
//
// Resellers are EXCLUDED. They live in the same table but are managed on their own
// page: listing one here would put it in a modal whose "Super Admin" tick promotes
// it, which is an escalation and not a cosmetic leak.
//
// ADAPTATION: vpn-ui filtered `is_reseller = false` off the column; pxpanel
// derives reseller-hood from the profile table, so the exclusion is a NOT IN over
// reseller_profiles. Nickname/Enable/TwoFactor/Permissions have no columns: they
// read back as "", true, false and an empty mask — the honest zero values of the
// storage that exists.
func GetAdmins() ([]AdminView, error) {
	db := vpn.DB()
	var users []*model.User
	if err := db.Model(&model.User{}).
		Where("id NOT IN (SELECT user_id FROM reseller_profiles)").
		Order("id asc").Find(&users).Error; err != nil {
		return nil, err
	}

	// One grouped count rather than a query per admin.
	type countRow struct {
		UserId int
		N      int64
	}
	var rows []countRow
	if err := db.Model(&model.Inbound{}).
		Select("user_id as user_id, count(*) as n").Group("user_id").Scan(&rows).Error; err != nil {
		return nil, err
	}
	counts := make(map[int]int64, len(rows))
	for _, r := range rows {
		counts[r.UserId] = r.N
	}

	// One query for every grant rather than one per admin.
	byUser, err := GrantsByUser(db, nil)
	if err != nil {
		return nil, err
	}

	superId, err := SuperAdminId()
	if err != nil {
		return nil, err
	}

	out := make([]AdminView, 0, len(users))
	for _, u := range users {
		ids := byUser[u.Id]
		if ids == nil {
			ids = []int{} // marshal as [], not null: the UI ticks against it
		}
		out = append(out, AdminView{
			Id:              u.Id,
			Username:        u.Username,
			IsSuperAdmin:    u.Id == superId,
			Enable:          true, // no disable column yet
			TwoFactorEnable: false,
			Permissions:     []string{},
			InboundCount:    counts[u.Id],
			InboundIds:      ids,
		})
	}
	return out, nil
}

// AdminSpec is the mutable shape of an admin as the Admins UI submits it. A struct
// rather than a positional list: the two adjacent int pairs are trivially swappable
// at a call site, and the compiler cannot catch it.
type AdminSpec struct {
	Username string
	// Password empty on update means "keep the existing one".
	Password     string
	Nickname     string
	Permissions  model.Permission
	Enable       bool
	IsSuperAdmin bool
	// InboundIds is the exact set of inbounds this admin may see. Replaces whatever
	// they had. Empty means no access at all, which is a legitimate state (an admin
	// who has not been given anything yet), so it must not be read as "leave alone".
	InboundIds []int
}

// AddAdmin creates an admin. Password is required and always bcrypt-hashed here:
// nothing downstream will retro-hash it.
//
// ADAPTATION: the role fields the spec carries but pxpanel cannot store are
// REFUSED, loudly: a super-admin tick (vpn-ui also refused this at create), a
// disable (would have to keep working to be a silent bug) and a non-zero
// permission mask (the mask is what this whole feature is about) all fail with
// ErrUnrepresentableRole until the user-roles wave lands the columns.
func AddAdmin(spec AdminSpec) (*model.User, error) {
	spec.Username = normalizeUsername(spec.Username)
	if spec.Username == "" {
		return nil, errors.New("username is required")
	}
	if spec.Password == "" {
		return nil, errors.New("password is required")
	}
	if spec.IsSuperAdmin {
		// A super admin is never created through this path: promotion is a separate,
		// deliberate act (UpdateAdmin in vpn-ui), so a misfiled create can't mint one.
		return nil, ErrUnrepresentableRole
	}
	if !spec.Enable {
		return nil, ErrUnrepresentableRole
	}
	if spec.Permissions != 0 {
		return nil, ErrUnrepresentableRole
	}
	username := spec.Username
	db := vpn.DB()
	taken, err := UsernameTaken(db, username, 0)
	if err != nil {
		return nil, err
	}
	if taken {
		return nil, ErrAdminUsernameTaken
	}
	hash, err := crypto.HashPasswordAsBcrypt(spec.Password)
	if err != nil {
		return nil, err
	}
	user := &model.User{
		Username: username,
		Password: hash,
	}
	if err := db.Create(user).Error; err != nil {
		return nil, err
	}
	if err := SetInboundAccess(user.Id, spec.InboundIds); err != nil {
		return nil, err
	}
	return user, nil
}

// UpdateAdmin edits an admin. An empty password leaves the existing one alone, so
// the UI can save inbound-grant changes without asking for a password.
//
// ADAPTATION: username / password / inbound grants are storable and are stored;
// every role mutation (mask, enable, super-admin tick) is refused with
// ErrUnrepresentableRole rather than dropped on the floor. Demoting or disabling
// the last super admin is therefore unreachable-by-construction until the columns
// wave, and the ErrLastSuperAdmin guard stays for that wave's swap-in.
func UpdateAdmin(id int, spec AdminSpec) error {
	db := vpn.DB()
	existing := &model.User{}
	if err := db.Model(&model.User{}).Where("id = ?", id).First(existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrAdminNotFound
		}
		return err
	}

	// The Admins page must not reach a reseller. It is excluded from the list, but
	// the id travels in the URL and this is the only thing between a crafted POST
	// and a reseller being ticked into a super admin.
	if isReseller, err := IsReseller(id); err != nil {
		return err
	} else if isReseller {
		return ErrAdminNotFound
	}

	if spec.IsSuperAdmin != FlagsForQuiet(id) {
		return ErrUnrepresentableRole
	}
	if !spec.Enable {
		return ErrUnrepresentableRole
	}
	if spec.Permissions != 0 {
		return ErrUnrepresentableRole
	}

	spec.Username = normalizeUsername(spec.Username)
	if spec.Username == "" {
		return errors.New("username is required")
	}
	taken, err := UsernameTaken(db, spec.Username, id)
	if err != nil {
		return err
	}
	if taken {
		return ErrAdminUsernameTaken
	}

	updates := map[string]any{
		"username": spec.Username,
	}
	if spec.Password != "" {
		hash, err := crypto.HashPasswordAsBcrypt(spec.Password)
		if err != nil {
			return err
		}
		updates["password"] = hash
	}
	if err := db.Model(&model.User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return err
	}
	// Super admins see everything by role, so carrying explicit grants for one would
	// be dead rows that reappear if they are ever demoted.
	if spec.IsSuperAdmin {
		return SetInboundAccess(id, nil)
	}
	return SetInboundAccess(id, spec.InboundIds)
}

// FlagsForQuiet is FlagsFor with the error collapsed to false, for the one caller
// that only needs "was this a super admin before the call" as part of a refusal
// decision that has its own error.
func FlagsForQuiet(id int) bool {
	flags, err := FlagsFor(id)
	if err != nil {
		return false
	}
	return flags.IsSuperAdmin
}

// DeleteAdmin removes an admin. Refuses the last super admin, and refuses while
// the account still owns inbounds: those would become invisible to everyone,
// while their daemons kept running and their clients kept connecting.
func DeleteAdmin(id int) error {
	db := vpn.DB()
	existing := &model.User{}
	if err := db.Model(&model.User{}).Where("id = ?", id).First(existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrAdminNotFound
		}
		return err
	}
	// Resellers are deleted from their own page, which also has to settle the
	// balance and the accounts they own. Deleting one from here would leave both
	// stranded.
	if isReseller, err := IsReseller(id); err != nil {
		return err
	} else if isReseller {
		return ErrAdminNotFound
	}
	if FlagsForQuiet(id) {
		last, err := isLastSuperAdmin(db, id)
		if err != nil {
			return err
		}
		if last {
			return ErrLastSuperAdmin
		}
	}
	owned, err := OwnedInboundCount(db, id)
	if err != nil {
		return err
	}
	if owned > 0 {
		return &OwnedInboundError{Owned: owned}
	}
	return db.Where("id = ?", id).Delete(&model.User{}).Error
}

// OwnedInboundError is DeleteAdmin's refusal when the account still owns
// inbounds (vpn-ui built the sentence inline; a typed error survives the port's
// wording change).
type OwnedInboundError struct{ Owned int64 }

func (e *OwnedInboundError) Error() string {
	return "this admin still owns inbound(s); delete or reassign them first"
}
