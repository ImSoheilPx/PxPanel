package reseller

// The cgo-free halves of vpn-ui web/service/reseller_security_test.go: the
// bypass checks that need no database. The DB-bound ones live in
// reseller_db_test.go (gated linux && cgo).

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

// A reseller must not be able to set an auto-renew period.
//
// `reset` is a number of DAYS after which the auto-renew job zeroes an account's
// counters, re-enables it and pushes its deadline forward, on a timer, forever,
// consulting no balance. Sell one gigabyte with reset=1 and the account is
// handed a fresh gigabyte every day for the rest of its life, charged once.
func TestResellerCannotSetAutoRenewPeriod(t *testing.T) {
	profile := &model.ResellerProfile{AllowExternalProxy: true}
	for _, reset := range []any{float64(1), float64(30), float64(-1)} {
		body := map[string]any{"clients": []any{map[string]any{
			"email": "sold", "totalGB": float64(gb), "reset": reset,
		}}}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		data := &model.Inbound{Settings: string(raw)}
		cm, settings, clients, err := postedClient(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := applyToSettings(data, profile, ChargeQuote{}, cm, settings, clients); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(data.Settings, "\"reset\"") {
			t.Errorf("reset=%v survived into the stored client: an unmetered renewal every period", reset)
		}
	}
}

// depletedAfter must answer the same question the enforcement job asks, or the
// two disagree about which accounts are allowed to run.
func TestDepletedAfterMatchesTheEnforcementPredicate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		up, down  int64
		total     int64
		wantSpent bool
	}{
		{"unlimited is never depleted", 900 * gb, 900 * gb, 0, false},
		{"under the limit", 1 * gb, 1 * gb, 5 * gb, false},
		{"exactly at the limit counts as spent", 2 * gb, 3 * gb, 5 * gb, true},
		{"over the limit", 5 * gb, 5 * gb, 5 * gb, true},
		{"a raised quota revives it", 2 * gb, 3 * gb, 50 * gb, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct := &xray.ClientTraffic{Up: tc.up, Down: tc.down}
			if got := depletedAfter(ct, tc.total); got != tc.wantSpent {
				t.Errorf("depletedAfter = %v; want %v", got, tc.wantSpent)
			}
		})
	}
	if depletedAfter(nil, 5*gb) {
		t.Error("a missing traffic row must not read as depleted")
	}
}

// The zero-quota and negative-quota refusals are the two cheapest ways to mint
// traffic, so they are asserted here as well as in the ledger tests: this file
// is what someone reads when asking "what stops a reseller cheating".
func TestQuoteRefusesTheFreeTrafficShapes(t *testing.T) {
	limited := model.ResellerProfile{AllowanceBytes: 100 * gb}
	if _, err := Quote(QuoteInput{Profile: limited, Create: true, NewTotal: 0}); !errors.Is(err, ErrUnlimitedAccount) {
		t.Errorf("err = %v; an unlimited ACCOUNT out of a limited balance must be refused", err)
	}
	if _, err := Quote(QuoteInput{Profile: limited, Create: true, NewTotal: -5 * gb}); !errors.Is(err, ErrInvalidQuota) {
		t.Errorf("err = %v; a negative quota prices as a negative charge, which pays the reseller", err)
	}
	unlimited := model.ResellerProfile{Unlimited: true}
	if _, err := Quote(QuoteInput{Profile: unlimited, Create: true, NewTotal: -5 * gb}); !errors.Is(err, ErrInvalidQuota) {
		t.Errorf("err = %v; a negative quota must be refused for an unlimited reseller too", err)
	}
	// Zeroing an account that already carries a charge is the refund-and-uncap
	// path: the flag is read at quote time, so a moment of being unlimited must
	// not be enough to keep the traffic AND the refund.
	sold := model.ResellerProfile{Unlimited: true}
	if _, err := Quote(QuoteInput{
		Profile: sold, OldTotal: 100 * gb, NewTotal: 0, OldCharged: 100 * gb,
	}); !errors.Is(err, ErrUnlimitedAccount) {
		t.Errorf("err = %v; an account holding a charge must never be zeroed", err)
	}
}
