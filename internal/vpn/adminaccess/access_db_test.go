//go:build linux && cgo

package adminaccess

// Ported from vpn-ui web/service/admin_membership_test.go onto the injected
// handle (InitDB + SetDB; CGO sqlite — CI runs it, dev hosts compile the
// cgo-free builds). The property under test: an account is one identity on
// SEVERAL inbounds and ONE client_traffics row, and that row names one inbound.
// Both client-access checks used to join through it, so they answered "is this
// admin granted the inbound that account's traffic row happens to point at"
// instead of "does this admin hold an inbound serving it".
//
// The admin holding the OTHER inbound was therefore denied every :email route
// for a client sitting on their own inbound, and dropped from every scoped
// payload: the account is on their page, and acting on it 404s.

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/database"
	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

func newAccessDB(t *testing.T) {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	vpn.SetDB(database.GetDB)
}

// seedAccessInbound writes an inbound holding the given clients, DISABLED so no
// path under test is tempted to push to a live core.
func seedAccessInbound(t *testing.T, port int, protocol model.Protocol, clients []map[string]any) *model.Inbound {
	t.Helper()
	settings, err := json.Marshal(map[string]any{"clients": clients})
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	inbound := &model.Inbound{
		UserId: 1, Tag: fmt.Sprintf("inbound-%d", port), Port: port,
		Protocol: protocol, Enable: false, Settings: string(settings),
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("create inbound on port %d: %v", port, err)
	}
	return inbound
}

// accessFixture is two admins holding one inbound each, and one account served on
// BOTH, whose single traffic row names only the first.
type accessFixture struct {
	first, second   *model.Inbound
	firstAdmin      *model.User
	secondAdmin     *model.User
	strangerAdmin   *model.User
	sharedAccount   string
	firstOnlyClient string
}

func newAccessFixture(t *testing.T) *accessFixture {
	t.Helper()
	newAccessDB(t)
	db := database.GetDB()

	f := &accessFixture{sharedAccount: "bob@example.com", firstOnlyClient: "alice@example.com"}
	f.first = seedAccessInbound(t, 44001, model.VMESS, []map[string]any{
		{"id": "uuid-bob", "email": f.sharedAccount, "enable": false, "totalGB": 5 * testGB},
		{"id": "uuid-alice", "email": f.firstOnlyClient, "enable": false, "totalGB": 5 * testGB},
	})
	f.second = seedAccessInbound(t, 44002, model.Trojan, []map[string]any{
		{"password": "pw-bob", "email": f.sharedAccount, "enable": false, "totalGB": 5 * testGB},
	})
	// ONE traffic row for the account, naming the FIRST inbound. This is the shape
	// the accounts layer creates and the one both checks used to resolve through.
	for _, email := range []string{f.sharedAccount, f.firstOnlyClient} {
		if err := db.Create(&xray.ClientTraffic{
			InboundId: f.first.Id, Email: email, Enable: true,
		}).Error; err != nil {
			t.Fatalf("create traffic %s: %v", email, err)
		}
	}

	for i, spec := range []struct {
		name    string
		inbound *model.Inbound
	}{
		{"first-admin", f.first},
		{"second-admin", f.second},
		{"stranger-admin", nil},
	} {
		u := &model.User{Username: spec.name, Password: "x"}
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("create %s: %v", spec.name, err)
		}
		if spec.inbound != nil {
			if err := GrantInbound(u.Id, spec.inbound.Id); err != nil {
				t.Fatalf("grant to %s: %v", spec.name, err)
			}
		}
		switch i {
		case 0:
			f.firstAdmin = u
		case 1:
			f.secondAdmin = u
		default:
			f.strangerAdmin = u
		}
	}
	return f
}

// The single check, which every :email route is gated on.
func TestCanAccessClientEmailFollowsEveryInboundServingTheClient(t *testing.T) {
	f := newAccessFixture(t)

	if ok, err := CanAccessClientEmail(f.sharedAccount, f.firstAdmin.Id); err != nil || !ok {
		t.Errorf("ok=%v err=%v; the admin of the inbound the traffic row names must still reach it", ok, err)
	}
	if ok, err := CanAccessClientEmail(f.sharedAccount, f.secondAdmin.Id); err != nil || !ok {
		t.Errorf("ok=%v err=%v; the account is served on this admin's own inbound, so every :email route for it must work",
			ok, err)
	}
	// The wall is still a wall: holding no inbound that serves it grants nothing.
	if ok, _ := CanAccessClientEmail(f.sharedAccount, f.strangerAdmin.Id); ok {
		t.Error("an admin holding no inbound that serves the account must not reach it")
	}
	// And an account on the first inbound only stays confined to its admin.
	if ok, _ := CanAccessClientEmail(f.firstOnlyClient, f.secondAdmin.Id); ok {
		t.Error("an account on somebody else's inbound must not be reachable")
	}
	// An email nothing serves is not an access question that can resolve to yes.
	if ok, _ := CanAccessClientEmail("nobody@example.com", f.firstAdmin.Id); ok {
		t.Error("an unknown email must fail closed")
	}
}

// The bulk producer and the single check answer the same question, so they must
// agree account by account and admin by admin. Disagreement is how a route ends up
// enforcing something the payload was never scoped for, in whichever direction.
func TestClientEmailAccessAgreesWithTheSingleCheck(t *testing.T) {
	f := newAccessFixture(t)

	access, err := ClientEmailAccess()
	if err != nil {
		t.Fatalf("ClientEmailAccess: %v", err)
	}
	for _, email := range []string{f.sharedAccount, f.firstOnlyClient} {
		for _, admin := range []*model.User{f.firstAdmin, f.secondAdmin, f.strangerAdmin} {
			want, err := CanAccessClientEmail(email, admin.Id)
			if err != nil {
				t.Fatalf("CanAccessClientEmail: %v", err)
			}
			if got := access[email][admin.Id]; got != want {
				t.Errorf("%s / admin %s: map says %v, the check says %v",
					email, admin.Username, got, want)
			}
		}
	}
	if !access[f.sharedAccount][f.secondAdmin.Id] {
		t.Error("the traffic broadcast and the online list still hide an account from the admin of the inbound serving it")
	}
}

// The map is indexed with whatever spelling the caller's payload carried: the
// traffic rows use one, an Xray stat name carries the settings' own. Identity is
// case-insensitive across the panel, so a map keyed on one spelling silently hid a
// client from its own admin.
func TestClientEmailAccessIsKeyedByEverySpelling(t *testing.T) {
	newAccessDB(t)
	db := database.GetDB()

	inbound := seedAccessInbound(t, 44101, model.VMESS, []map[string]any{
		{"id": "uuid-mixed", "email": "Mixed-Case", "enable": false, "totalGB": 5 * testGB},
	})
	if err := db.Create(&xray.ClientTraffic{
		InboundId: inbound.Id, Email: "mixed-case", Enable: true,
	}).Error; err != nil {
		t.Fatalf("create traffic: %v", err)
	}
	admin := &model.User{Username: "mixed-admin", Password: "x"}
	if err := db.Create(admin).Error; err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := GrantInbound(admin.Id, inbound.Id); err != nil {
		t.Fatalf("grant: %v", err)
	}

	access, err := ClientEmailAccess()
	if err != nil {
		t.Fatalf("ClientEmailAccess: %v", err)
	}
	for _, spelling := range []string{"Mixed-Case", "mixed-case"} {
		if !access[spelling][admin.Id] {
			t.Errorf("%q resolves to nothing; the caller cannot know which table its email came from", spelling)
		}
	}
}

// A membership recorded in the accounts tables counts as service too, so an admin is
// not locked out of an account during the window between the membership landing and
// the projection splicing its entry into settings.
func TestClientAccessFollowsAMembershipWithoutASettingsEntry(t *testing.T) {
	newAccessDB(t)
	db := database.GetDB()

	// The account is nowhere in this inbound's settings: only account_inbounds says
	// it belongs here.
	pending := seedAccessInbound(t, 44201, model.VMESS, []map[string]any{
		{"id": "uuid-other", "email": "someone-else", "enable": false, "totalGB": testGB},
	})
	account := &model.Account{Email: "bob@example.com", TotalGB: 5 * testGB, Enable: true}
	if err := db.Create(account).Error; err != nil {
		t.Fatalf("create account: %v", err)
	}
	if err := db.Create(&model.AccountInbound{AccountId: account.Id, InboundId: pending.Id}).Error; err != nil {
		t.Fatalf("create membership: %v", err)
	}
	admin := &model.User{Username: "pending-admin", Password: "x"}
	if err := db.Create(admin).Error; err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := GrantInbound(admin.Id, pending.Id); err != nil {
		t.Fatalf("grant: %v", err)
	}

	if ok, err := CanAccessClientEmail("bob@example.com", admin.Id); err != nil || !ok {
		t.Errorf("ok=%v err=%v; a recorded membership on this admin's inbound is service", ok, err)
	}
	access, err := ClientEmailAccess()
	if err != nil {
		t.Fatalf("ClientEmailAccess: %v", err)
	}
	if !access["bob@example.com"][admin.Id] {
		t.Error("the two checks disagree about a membership-only account")
	}
}

// A membership or a traffic row that outlived its inbound must grant nothing: an
// inbound id is only evidence while there is an inbound behind it, and a dangling
// one would also read as "this account is still served somewhere", which is the
// answer that withholds a reseller's refund.
func TestServingInboundIdsIgnoresDeadInbounds(t *testing.T) {
	newAccessDB(t)
	db := database.GetDB()

	inbound := seedAccessInbound(t, 44301, model.VMESS, []map[string]any{
		{"id": "uuid-ghost", "email": "ghost@example.com", "enable": false, "totalGB": testGB},
	})
	account := &model.Account{Email: "ghost@example.com", TotalGB: testGB, Enable: true}
	if err := db.Create(account).Error; err != nil {
		t.Fatalf("create account: %v", err)
	}
	if err := db.Create(&model.AccountInbound{AccountId: account.Id, InboundId: inbound.Id}).Error; err != nil {
		t.Fatalf("create membership: %v", err)
	}
	if err := db.Create(&xray.ClientTraffic{
		InboundId: inbound.Id, Email: "ghost@example.com", Enable: true,
	}).Error; err != nil {
		t.Fatalf("create traffic: %v", err)
	}

	ids, err := accountSvc.ServingInboundIds(db, "ghost@example.com")
	if err != nil {
		t.Fatalf("ServingInboundIds: %v", err)
	}
	if len(ids) != 1 || ids[0] != inbound.Id {
		t.Fatalf("ids = %v; want the one inbound really serving it", ids)
	}

	// Delete the inbound row alone, leaving the membership and the traffic row
	// pointing at nothing, which is exactly what a delete leaves behind today.
	if err := db.Where("id = ?", inbound.Id).Delete(&model.Inbound{}).Error; err != nil {
		t.Fatalf("delete inbound: %v", err)
	}
	ids, err = accountSvc.ServingInboundIds(db, "ghost@example.com")
	if err != nil {
		t.Fatalf("ServingInboundIds: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("ids = %v; rows naming a deleted inbound are not service, and reading them as service withholds refunds forever", ids)
	}
}

// testGB is 1 << 30, the source tree's shared test constant.
const testGB = int64(1) << 30

// The grant/revoke lifecycle the Admins checklist and every owns() middleware
// sit on. Creating an inbound row grants nothing on its own: access is
// ASSIGNED, and the creator's grant is added by the controller.
func TestInboundAccessChecks(t *testing.T) {
	newAccessDB(t)
	db := database.GetDB()

	ali := &model.User{Username: "ali", Password: "pw"}
	reza := &model.User{Username: "reza", Password: "pw"}
	for _, u := range []*model.User{ali, reza} {
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("create user: %v", err)
		}
	}

	alisInbound := &model.Inbound{UserId: ali.Id, Tag: "inbound-31001", Port: 31001, Protocol: model.VMESS, Enable: true}
	rezasInbound := &model.Inbound{UserId: reza.Id, Tag: "inbound-31002", Port: 31002, Protocol: model.VMESS, Enable: true}
	for _, ib := range []*model.Inbound{alisInbound, rezasInbound} {
		if err := db.Create(ib).Error; err != nil {
			t.Fatalf("create inbound: %v", err)
		}
	}
	if err := GrantInbound(ali.Id, alisInbound.Id); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := GrantInbound(reza.Id, rezasInbound.Id); err != nil {
		t.Fatalf("grant: %v", err)
	}

	if ok, _ := CanAccessInbound(alisInbound.Id, ali.Id); !ok {
		t.Error("Ali must reach the inbound granted to him")
	}
	if ok, _ := CanAccessInbound(alisInbound.Id, reza.Id); ok {
		t.Error("Reza must NOT reach an inbound he was never granted")
	}
	if ok, _ := CanAccessInbound(9999, ali.Id); ok {
		t.Error("a nonexistent inbound must not be accessible")
	}

	// A batch is refused unless EVERY id is granted; one foreign id poisons it.
	if ok, _ := CanAccessAllInbounds([]int{alisInbound.Id}, ali.Id); !ok {
		t.Error("Ali must reach a batch of only his own")
	}
	if ok, _ := CanAccessAllInbounds([]int{alisInbound.Id, rezasInbound.Id}, ali.Id); ok {
		t.Error("a batch containing an ungranted inbound must be refused")
	}
	if ok, _ := CanAccessAllInbounds([]int{}, ali.Id); !ok {
		t.Error("an empty batch is vacuously accessible")
	}
	// A duplicated id must not undercount the distinct set and pass by accident.
	if ok, _ := CanAccessAllInbounds([]int{alisInbound.Id, alisInbound.Id}, ali.Id); !ok {
		t.Error("a repeated id must not break the count")
	}

	// Granting is what the super admin's checklist does. It is idempotent.
	if err := GrantInbound(reza.Id, alisInbound.Id); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := GrantInbound(reza.Id, alisInbound.Id); err != nil {
		t.Fatalf("re-grant must be idempotent: %v", err)
	}
	if ok, _ := CanAccessInbound(alisInbound.Id, reza.Id); !ok {
		t.Error("Reza must reach an inbound granted to him")
	}

	// SetInboundAccess REPLACES: an empty set means no access, not "leave alone".
	if err := SetInboundAccess(reza.Id, nil); err != nil {
		t.Fatalf("SetInboundAccess: %v", err)
	}
	if ok, _ := CanAccessInbound(alisInbound.Id, reza.Id); ok {
		t.Error("revoking must actually revoke")
	}
	if ok, _ := CanAccessInbound(rezasInbound.Id, reza.Id); ok {
		t.Error("an empty set must clear every grant, including his own")
	}

	// Deleting an inbound must drop its grants, or a stale row lingers forever.
	if err := SetInboundAccess(ali.Id, []int{alisInbound.Id}); err != nil {
		t.Fatalf("SetInboundAccess: %v", err)
	}
	if err := RevokeInboundEverywhere(alisInbound.Id); err != nil {
		t.Fatalf("RevokeInboundEverywhere: %v", err)
	}
	if ok, _ := CanAccessInbound(alisInbound.Id, ali.Id); ok {
		t.Error("a deleted inbound's grants must not survive")
	}
}
