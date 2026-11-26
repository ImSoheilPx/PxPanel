//go:build linux && cgo

package reseller

// The DB-bound halves of vpn-ui web/service/reseller_security_test.go and
// reseller_delete_test.go, ported onto the injected handle (InitDB + SetDB, the
// same gating the radius/l2tp DB tests use: CGO sqlite; CI runs them, Windows
// dev hosts compile the cgo-free quote suite instead).
//
// The bypasses here are the ones that let a reseller obtain traffic an admin
// never granted. Each states the attack rather than the mechanism: a refactor
// that reopens one must fail here with the attack named.

import (
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/database"
	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/accounts"
	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

// newResellerDB boots a fresh panel database and wires it into the vpn seams.
func newResellerDB(t *testing.T) {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	vpn.SetDB(database.GetDB)
}

// An admin's account must not be claimable by posting its email.
//
// The create path rejects a duplicate email, but it runs AFTER the reservation,
// and the reservation writes the ResellerClient row that OwnsClientEmail answers
// from. For the width of the failed create the reseller owned an admin's
// account, which a second concurrent request could edit or delete. Rollback
// closes that window afterwards, and afterwards is not a security boundary.
func TestResellerCannotClaimAnExistingEmail(t *testing.T) {
	newResellerDB(t)
	db := database.GetDB()

	// The victim as it really exists: a client inside an ADMIN's inbound
	// settings blob, which is where the duplicate-email check looks.
	victim, err := json.Marshal(map[string]any{"clients": []any{map[string]any{
		"id": "uuid-victim", "email": "victim", "enable": true, "totalGB": float64(5 * gb),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.Inbound{
		Id: 1, UserId: 1, Enable: true, Remark: "admins", Protocol: model.VMESS,
		Port: 21001, Tag: "inbound-21001", Settings: string(victim),
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&xray.ClientTraffic{
		InboundId: 1, Email: "victim", Enable: true, Total: 5 * gb,
	}).Error; err != nil {
		t.Fatal(err)
	}

	reseller := &model.User{Username: "claimer", Password: "x"}
	if err := db.Create(reseller).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.ResellerProfile{
		UserId: reseller.Id, AllowanceBytes: 100 * gb,
	}).Error; err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]any{"clients": []any{map[string]any{
		"email": "victim", "totalGB": float64(gb),
	}}})
	data := &model.Inbound{Id: 1, Settings: string(body)}

	viewer := accountsViewerOf(reseller.Id)
	if _, err := PrepareClientCreate(viewer, data); err == nil {
		t.Fatal("claiming an admin's existing email was accepted")
	}
	// And the attempt must leave nothing behind: no ownership row to answer
	// OwnsClientEmail with, and no charge.
	var owned int64
	db.Model(&model.ResellerClient{}).Where("email = ?", "victim").Count(&owned)
	if owned != 0 {
		t.Error("a ResellerClient row was written for an account the reseller does not own")
	}
	var p model.ResellerProfile
	db.Model(&model.ResellerProfile{}).Where("user_id = ?", reseller.Id).First(&p)
	if p.SpentBytes != 0 {
		t.Errorf("SpentBytes = %d; a refused create must not charge", p.SpentBytes)
	}
}

// Concurrent creates must not both fit into headroom that only covers one.
//
// Quote checks against a profile read earlier in the request, so two requests
// can see the same 10 GB free and each approve a 6 GB account. Only the debit
// statement itself can decide this atomically.
func TestResellerCannotOversellByRacing(t *testing.T) {
	newResellerDB(t)
	db := database.GetDB()
	if err := db.Create(&model.ResellerProfile{
		UserId: 9, AllowanceBytes: 10 * gb,
	}).Error; err != nil {
		t.Fatal(err)
	}

	const racers = 8
	var wg sync.WaitGroup
	ok := make([]bool, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// 6 GB each: exactly one can fit inside 10 GB.
			ok[i] = addSpent(db, 9, 6*gb) == nil
		}(i)
	}
	wg.Wait()

	granted := 0
	for _, o := range ok {
		if o {
			granted++
		}
	}
	if granted != 1 {
		t.Errorf("%d of %d concurrent 6 GB debits were accepted against a 10 GB balance; want exactly 1", granted, racers)
	}
	var p model.ResellerProfile
	db.Model(&model.ResellerProfile{}).Where("user_id = ?", 9).First(&p)
	if p.SpentBytes > p.AllowanceBytes {
		t.Errorf("SpentBytes %d exceeds AllowanceBytes %d: the reseller sold traffic nobody granted", p.SpentBytes, p.AllowanceBytes)
	}
}

// A refund must never be blocked by the headroom check that guards a debit.
// An over-sold reseller has to remain unwindable.
func TestRefundsAreNeverBlockedByTheBalanceGuard(t *testing.T) {
	newResellerDB(t)
	db := database.GetDB()
	if err := db.Create(&model.ResellerProfile{
		UserId: 11, AllowanceBytes: 1 * gb, SpentBytes: 50 * gb,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := addSpent(db, 11, -20*gb); err != nil {
		t.Fatalf("refund refused on an over-spent profile: %v", err)
	}
	var p model.ResellerProfile
	db.Model(&model.ResellerProfile{}).Where("user_id = ?", 11).First(&p)
	if p.SpentBytes != 30*gb {
		t.Errorf("SpentBytes = %d; want %d", p.SpentBytes, 30*gb)
	}
}

// An unlimited reseller is exempt from the headroom check but still accrues, so
// a later switch to a limited plan accounts for what they already sold.
func TestUnlimitedResellerStillAccrues(t *testing.T) {
	newResellerDB(t)
	db := database.GetDB()
	if err := db.Create(&model.ResellerProfile{
		UserId: 12, AllowanceBytes: 0, Unlimited: true,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := addSpent(db, 12, 500*gb); err != nil {
		t.Fatalf("unlimited debit refused: %v", err)
	}
	var p model.ResellerProfile
	db.Model(&model.ResellerProfile{}).Where("user_id = ?", 12).First(&p)
	if p.SpentBytes != 500*gb {
		t.Errorf("SpentBytes = %d; want the debit to accrue even while unlimited", p.SpentBytes)
	}
}

// A delete refunds ONLY what the customer never used, on every path.
//
// The trap this defends: the delete removes the client_traffics row (and, in
// time, the windows that hold the rest of the lifetime figure). A refund priced
// after the delete reads consumption as zero and hands back the entire charge,
// so a reseller could sell 10 GB, let the customer spend all of it, delete the
// account and get all 10 GB back. Repeat for unlimited free traffic.
//
// Which is why RefundDeleted takes the lifetime figure as an ARGUMENT: it must
// be captured while the rows that prove it still exist.
func TestDeleteRefundsOnlyUnusedTraffic(t *testing.T) {
	for _, tc := range []struct {
		name            string
		charged, base   int64
		allTimeAtDelete int64
		known           bool
		wantRefund      int64
	}{
		{"nothing used refunds the whole charge", 10 * gb, 0, 0, true, 10 * gb},
		{"half used refunds half", 10 * gb, 0, 4 * gb, true, 6 * gb},
		{"fully used refunds nothing", 10 * gb, 0, 10 * gb, true, 0},
		{"over-used refunds nothing, never negative", 10 * gb, 0, 25 * gb, true, 0},
		{"consumption counts from the charge, not the account's whole life", 10 * gb, 100 * gb, 103 * gb, true, 7 * gb},
		{"a lost snapshot withholds the refund rather than inventing one", 10 * gb, 0, 0, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newResellerDB(t)
			db := database.GetDB()
			if err := db.Create(&model.ResellerProfile{
				UserId: 3, AllowanceBytes: 100 * gb, SpentBytes: 40 * gb,
			}).Error; err != nil {
				t.Fatal(err)
			}
			if err := db.Create(&model.ResellerClient{
				Email: "sold", InboundId: 1, UserId: 3,
				ChargedBytes: tc.charged, AllTimeBase: tc.base,
			}).Error; err != nil {
				t.Fatal(err)
			}

			if err := RefundDeleted("sold", tc.allTimeAtDelete, tc.known); err != nil {
				t.Fatalf("RefundDeleted: %v", err)
			}
			var p model.ResellerProfile
			db.Model(&model.ResellerProfile{}).Where("user_id = ?", 3).First(&p)
			got := 40*gb - p.SpentBytes
			if got != tc.wantRefund {
				t.Errorf("refund = %d; want %d", got, tc.wantRefund)
			}
			// The ownership row must go with the account either way, or a recycled
			// email inherits a charge that is no longer real.
			var left int64
			db.Model(&model.ResellerClient{}).Where("email = ?", "sold").Count(&left)
			if left != 0 {
				t.Error("the ownership row outlived the account it belonged to")
			}
		})
	}
}

// UsageSnapshot is the thing that has to be taken BEFORE a delete, so prove it
// reads what the refund needs and tolerates an account with no row at all.
//
// ADAPTATION: the lifetime figure here is the target's composition — live
// counters plus every closed window (model.ClientTrafficWindow) — standing in
// for vpn-ui's never-reset AllTime column. The reset-leak the comment below
// names is what the windows table exists to prevent.
func TestUsageSnapshotReadsLifetimeTraffic(t *testing.T) {
	newResellerDB(t)
	db := database.GetDB()
	if err := db.Create(&xray.ClientTraffic{
		InboundId: 1, Email: "a", Up: 1 * gb, Down: 1 * gb,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&xray.ClientTraffic{InboundId: 1, Email: "b"}).Error; err != nil {
		t.Fatal(err)
	}
	// Account a's history: 5 GB moved before a reset zeroed the live counters.
	if err := db.Create(&model.ClientTrafficWindow{
		Email: "a", Up: 5 * gb, Down: 0, Reason: "reset",
	}).Error; err != nil {
		t.Fatal(err)
	}
	snap, err := UsageSnapshot([]string{"a", "b", "never-existed"})
	if err != nil {
		t.Fatal(err)
	}
	// Lifetime, not Up+Down: a reset zeroes the counters but not the lifetime
	// record, and pricing a refund off the resettable pair would let a reset
	// launder consumed bytes back into refundable balance.
	if snap[emailKey("a")] != 7*gb {
		t.Errorf("a = %d; want the lifetime figure %d (live 2 GB + closed window 5 GB)", snap[emailKey("a")], 7*gb)
	}
	if _, ok := snap[emailKey("never-existed")]; ok {
		t.Error("an account with no traffic row must be absent, which reads as zero usage")
	}
	if used, known, err := UsageOf("a"); err != nil || !known || used != 7*gb {
		t.Errorf("UsageOf = %d, known=%v, %v; want %d known", used, known, err, 7*gb)
	}
	if _, known, err := UsageOf("never-existed"); err != nil || known {
		t.Error("an account with no traffic row must report its usage as UNKNOWN, which withholds the refund")
	}
}

// Undoing a deduct must never be blocked by the headroom guard.
//
// A deduct refunds, so its rollback DEBITS. Routed through the guard, an
// allowance an admin lowered in between refuses the unwind and the reseller
// keeps a refund for a deduct that never landed: the guard causing the exact
// leak it exists to stop.
func TestRollbackOfADeductIsNeverRefused(t *testing.T) {
	newResellerDB(t)
	db := database.GetDB()
	if err := db.Create(&model.ResellerProfile{
		UserId: 21, AllowanceBytes: 3 * gb, SpentBytes: 5 * gb,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.ResellerClient{
		Email: "sold", InboundId: 1, UserId: 21, ChargedBytes: 5 * gb,
	}).Error; err != nil {
		t.Fatal(err)
	}
	// A deduct that refunded 5 GB, now being unwound: the debit is larger than
	// the (already exceeded) allowance allows.
	err := Rollback(ChargeTicket{
		Active: true, UserId: 21, Email: "sold",
		Quote:       ChargeQuote{DeltaSpent: -5 * gb, NewCharged: 0},
		PrevCharged: 5 * gb,
	})
	if err != nil {
		t.Fatalf("rollback refused: %v", err)
	}
	var p model.ResellerProfile
	db.Model(&model.ResellerProfile{}).Where("user_id = ?", 21).First(&p)
	if p.SpentBytes != 10*gb {
		t.Errorf("SpentBytes = %d; want the deduct fully unwound to %d", p.SpentBytes, 10*gb)
	}
	var rc model.ResellerClient
	db.Model(&model.ResellerClient{}).Where("email = ?", "sold").First(&rc)
	if rc.ChargedBytes != 5*gb {
		t.Errorf("ChargedBytes = %d; want the previous charge restored", rc.ChargedBytes)
	}
}

// Switching a depleted account back on is a traffic grant whichever verb does
// it, so unfreeze is filtered exactly like enable. Exempting it because it
// "only restores a deadline" ignored that it writes enable=true as well.
func TestUnfreezeCannotReviveADepletedAccount(t *testing.T) {
	for _, op := range []string{"enable", "unfreeze"} {
		t.Run(op, func(t *testing.T) {
			newResellerDB(t)
			db := database.GetDB()
			for _, ct := range []xray.ClientTraffic{
				{InboundId: 1, Email: "spent", Total: 5 * gb, Up: 3 * gb, Down: 2 * gb},
				{InboundId: 1, Email: "healthy", Total: 5 * gb, Up: 1 * gb, Down: 0},
			} {
				if err := db.Create(&ct).Error; err != nil {
					t.Fatal(err)
				}
			}
			req := &BulkClientUpdateRequest{Op: op, Targets: []BulkClientTarget{
				{InboundId: 1, Email: "spent"}, {InboundId: 1, Email: "healthy"},
			}}
			if err := dropDepletedTargets(req); err != nil {
				t.Fatal(err)
			}
			if len(req.Targets) != 1 || req.Targets[0].Email != "healthy" {
				t.Errorf("targets = %+v; the depleted account must be dropped and the healthy one kept", req.Targets)
			}
		})
	}
}

// accountsViewerOf is the test's role snapshot for a seeded user id (the
// controller builds the real one from the session; adminaccess registers the
// resolvers the adapter uses).
func accountsViewerOf(id int) accounts.Viewer {
	return accounts.Viewer{Id: id, IsReseller: true}
}
