// Package reseller ports vpn-ui web/service/reseller.go + reseller_bulk.go
// (inventory §5): the balance a reseller sells out of, the accounts it owns,
// and the arithmetic that moves bytes between the two.
//
// The heart of the port is the QUOTE → CHARGE-TICKET pattern: every account
// mutation is priced by Quote (pure, clock-injected, database-free) before
// anything is written, reserved against the balance by reserve (one
// transaction: the debit and the ledger row), and rolled back by Rollback when
// the client write it paid for fails. The bulk path runs the same shape with
// one ticket per batch (PrepareBulk → ApplyBulkCharges/RollbackBulk).
//
// ADAPTATIONS (each at its site, summarized here):
//   - vpn.DB() replaces database.GetDB() — the port-wide seam; NO internal/web
//     or internal/database imports.
//   - vpn-ui's *model.User parameters (which carried IsReseller / IsSuperAdmin /
//     Id columns) become accounts.Viewer, the role snapshot the accounts wave
//     defined; the role flags themselves resolve in internal/vpn/adminaccess.
//   - InboundService cross-calls (servingInboundIds, inboundAccountEmails,
//     the duplicate-email check) resolve through the accounts package, which is
//     where the accounts wave ported them. The one mutation cross-call
//     (DelInboundClientByEmail, used by the cascade delete) is a REGISTERED
//     seam (RemoveClientFromInbound) for the inbound wave; unwired, a cascade
//     refuses rather than half-apply.
//   - The bulk-op mutation semantics (applyBulkClientOp / bulkClientSkipped /
//     BulkClientUpdateRequest) are ported VERBATIM into bulkops.go, because the
//     pricer must run the applier's own rules rather than restate them (see
//     bulkPriceables). The inbound wave's applier should re-point at these, not
//     re-implement them.
package reseller

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/util/common"
)

// oneGB — the operator levers are whole GB; everything downstream is bytes.
const oneGB = int64(1024 * 1024 * 1024)

var (
	ErrNotAReseller         = errors.New("that account is not a reseller")
	ErrResellerNotFound     = errors.New("reseller not found")
	ErrResellerNameTaken    = errors.New("that username is already taken")
	ErrInsufficientBalance  = errors.New("not enough traffic left on your balance")
	ErrResetNotOwned        = errors.New("you can only reset accounts you created")
	ErrBelowMinCreate       = errors.New("below the minimum traffic you may create an account with")
	ErrBelowMinAdd          = errors.New("below the minimum traffic you may add in one edit")
	ErrUnlimitedAccount     = errors.New("you cannot create an account with unlimited traffic")
	ErrInvalidQuota         = errors.New("that traffic quota is not a number of bytes an account can hold")
	ErrClientNotOwned       = errors.New("not found")
	ErrResellerHasClients   = errors.New("this reseller still owns accounts; delete them first")
	ErrInboundNotAssignable = errors.New("you can only assign inbounds you have access to")
)

// gbToBytes converts a whole-GB operator setting. The levers an admin types are
// in GB; everything downstream of them is bytes.
func gbToBytes(gb int) int64 {
	if gb <= 0 {
		return 0
	}
	// Saturate rather than wrap. The product overflows above about 8 billion GB,
	// and a wrapped negative reads as "no floor set", so an absurd number typed
	// into a minimum would SILENTLY DISABLE the very limit it was setting.
	if int64(gb) > math.MaxInt64/oneGB {
		return math.MaxInt64
	}
	return int64(gb) * oneGB
}

// AvailableBytes is what a reseller may still commit. Zero for an unlimited one,
// who never has a balance to check against, so callers must test Unlimited before
// reading anything into this.
//
// Both ends are clamped. An admin who lowers an allowance below what is already
// spent leaves a reseller who can sell nothing more rather than one who owes
// negative traffic, and a SpentBytes that somehow went negative must not read as
// balance on top of the allowance.
func AvailableBytes(p model.ResellerProfile) int64 {
	if p.Unlimited {
		return 0
	}
	spent := p.SpentBytes
	if spent < 0 {
		spent = 0
	}
	available := p.AllowanceBytes - spent
	if available < 0 {
		return 0
	}
	return available
}

// shortBy names the exact deficit, because "not enough traffic" leaves a reseller
// guessing how much to ask an admin for. The shortfall, not the price: they can
// see what they asked for, what they cannot see is the gap.
func shortBy(want, available int64) error {
	short := want - available
	if short < 0 {
		short = 0
	}
	return fmt.Errorf("%w: you are short %s", ErrInsufficientBalance, common.FormatTraffic(short))
}

// --- balance arithmetic ---------------------------------------------------------
//
// This section is deliberately free of database access. It is where the money
// is, so it is a pure function of its inputs and can be proven on its own.

// QuoteInput is everything one client mutation needs to be priced.
type QuoteInput struct {
	Profile model.ResellerProfile
	// Create distinguishes a new account from an edit of an existing one.
	Create bool
	// OldTotal and NewTotal are the account's traffic quota in BYTES, before and
	// after. model.Client.TotalGB is a byte count despite its name.
	OldTotal int64
	NewTotal int64
	// OldCharged is ResellerClient.ChargedBytes, what this account currently
	// holds against the reseller's balance. Consumed is AllTime - AllTimeBase,
	// the traffic this account has moved SINCE it was charged.
	OldCharged int64
	Consumed   int64
	// CurrentExpiry is the account's expiry in ms since epoch, 0 for none.
	CurrentExpiry int64
	NowMillis     int64

	// Reset prices a traffic-counter reset rather than a quota change, and
	// ClearedBytes is the up+down about to be zeroed.
	//
	// A reset is a PURCHASE, not an adjustment. Zeroing the counters lets the
	// account move ClearedBytes again against the same quota, so the reseller is
	// buying that traffic a second time and their balance has to pay for it.
	// Without this a reset would be an unlimited-traffic button: set 1 GB, sell
	// it, reset, repeat, all for one gigabyte of balance.
	Reset        bool
	ClearedBytes int64
}

// ChargeQuote is the decided effect of one mutation, computed before anything
// is written.
type ChargeQuote struct {
	// DeltaSpent is added to ResellerProfile.SpentBytes. Positive debits the
	// reseller, negative refunds them.
	DeltaSpent int64
	// NewCharged is what ResellerClient.ChargedBytes becomes.
	NewCharged int64
	// ForceExpiry reports whether ExpiryTime must overwrite whatever the form
	// posted. False when the reseller has no days-per-GB coupling, in which case
	// they pick the expiry themselves.
	ForceExpiry bool
	ExpiryTime  int64
}

// Quote prices one client mutation against a reseller's limits.
//
// The refund rule is the whole feature: bytes already moved are gone, so a
// deduct or a delete can only return the UNUSED part of what was charged.
// Consumed is measured from ClientTraffic.AllTime, which is monotonic across a
// traffic reset, so resetting an account cannot turn spent bytes back into
// refundable balance.
func Quote(in QuoteInput) (ChargeQuote, error) {
	p := in.Profile
	available := AvailableBytes(p)

	// Priced before the quota rules below, and deliberately outside them: a reset
	// does not change NewTotal, so running it through the zero-quota and minimum
	// checks would judge it against a quota nobody is editing.
	if in.Reset {
		cleared := in.ClearedBytes
		if cleared < 0 {
			cleared = 0
		}
		if !p.Unlimited && cleared > available {
			return ChargeQuote{}, shortBy(cleared, available)
		}
		q := ChargeQuote{DeltaSpent: cleared, NewCharged: in.OldCharged + cleared}
		// AllTimeBase is deliberately NOT advanced by the caller: AllTime is
		// monotonic across a reset, so consumption keeps counting from the
		// original charge and the extra bytes show up as the account's new
		// headroom rather than as a refund.
		q.ForceExpiry, q.ExpiryTime = forcedExpiry(p, in, q.DeltaSpent)
		return q, nil
	}

	// NewTotal is jsonInt64(cm["totalGB"]) straight off the request body, so it is
	// the caller's to choose. A negative one prices as a NEGATIVE charge, which
	// reserve() writes into SpentBytes: the account creation would pay the
	// reseller. Refused before anything else looks at it.
	if in.NewTotal < 0 {
		return ChargeQuote{}, ErrInvalidQuota
	}

	// An unlimited ACCOUNT out of a limited balance is the whole feature bypassed
	// in one click, and it is the first thing anyone will try.
	//
	// The second clause matters as much as the first. Unlimited is read at quote
	// time, so keying only on the flag would let an account SOLD out of a limited
	// balance be uncapped during any window in which its reseller is unlimited:
	// the full unused refund lands AND the customer keeps a now-unlimited
	// account, and flipping the flag back leaves the reseller holding both. An
	// account that carries a charge can never be zeroed, whatever the flag says.
	if in.NewTotal == 0 && (!p.Unlimited || in.OldCharged > 0) {
		return ChargeQuote{}, ErrUnlimitedAccount
	}

	var q ChargeQuote
	switch {
	case in.Create:
		if min := gbToBytes(p.MinCreateGB); min > 0 && in.NewTotal < min {
			return ChargeQuote{}, fmt.Errorf("%w: %d GB", ErrBelowMinCreate, p.MinCreateGB)
		}
		if !p.Unlimited && in.NewTotal > available {
			return ChargeQuote{}, shortBy(in.NewTotal, available)
		}
		q.DeltaSpent = in.NewTotal
		q.NewCharged = in.NewTotal

	case in.NewTotal > in.OldTotal: // top up
		delta := in.NewTotal - in.OldTotal
		if min := gbToBytes(p.MinAddGB); min > 0 && delta < min {
			return ChargeQuote{}, fmt.Errorf("%w: %d GB", ErrBelowMinAdd, p.MinAddGB)
		}
		if !p.Unlimited && delta > available {
			return ChargeQuote{}, shortBy(delta, available)
		}
		q.DeltaSpent = delta
		q.NewCharged = in.OldCharged + delta

	case in.NewTotal < in.OldTotal: // deduct
		// Refund only what has not been used. The clamp at Consumed is the rule:
		// a reseller cannot claw back bytes the customer already moved.
		newCharged := in.NewTotal
		if in.Consumed > newCharged {
			newCharged = in.Consumed
		}
		// A deduct must never RAISE the charge, which it otherwise would on an
		// account that has already overshot what it was charged for.
		if newCharged > in.OldCharged {
			newCharged = in.OldCharged
		}
		q.DeltaSpent = newCharged - in.OldCharged // <= 0
		q.NewCharged = newCharged

	default: // quota unchanged
		q.NewCharged = in.OldCharged
	}

	q.ForceExpiry, q.ExpiryTime = forcedExpiry(p, in, q.DeltaSpent)
	return q, nil
}

// forcedExpiry derives an account's deadline from the traffic just moved, when
// the reseller has a days-per-GB factor.
//
// One rule covers create, top-up and deduct: the new deadline is the CURRENT one
// (or now, whichever is later) shifted by the days the charge change buys. An
// expired account therefore restarts from now while a live one extends, and a
// deduct gives back the time it gives back the traffic.
//
// Absolute, never the panel's negative "delayed start" form: that encoding is
// also what freeze writes (a frozen account is enable=false AND expiryTime<0),
// so borrowing it here would make forced-expiry accounts indistinguishable from
// frozen ones.
func forcedExpiry(p model.ResellerProfile, in QuoteInput, deltaSpent int64) (bool, int64) {
	if p.DaysPerGB <= 0 || deltaSpent == 0 {
		return false, 0
	}
	// An account with unlimited traffic has no GB to derive days from.
	if in.NewTotal <= 0 {
		return false, 0
	}
	base := in.CurrentExpiry
	if base < in.NowMillis {
		base = in.NowMillis
	}
	// float64 rather than integer arithmetic: bytes * days * ms-per-day overflows
	// int64 well inside the range of a real account, and a 53-bit mantissa is
	// far more precision than a millisecond deadline needs.
	days := float64(deltaSpent) / float64(oneGB) * float64(p.DaysPerGB)
	ms := days * 24 * 60 * 60 * 1000

	// Saturate the offset. A quota big enough to push the deadline past int64 is
	// a typo rather than a plan, and converting an out-of-range float64 to int64
	// is undefined in Go: in practice it wraps, so the account would come out
	// ALREADY EXPIRED, which is the opposite of what the operator asked for.
	const maxOffsetMs = int64(100*365*24) * 60 * 60 * 1000 // a century
	var out int64
	switch {
	case ms > float64(maxOffsetMs):
		out = base + maxOffsetMs
	case ms < float64(-maxOffsetMs):
		out = base - maxOffsetMs
	default:
		out = base + int64(ms)
	}
	if out < in.NowMillis {
		out = in.NowMillis
	}
	return true, out
}

// jsonInt64 reads a number out of an unmarshalled settings blob, which decodes
// every number as float64.
func jsonInt64(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	}
	return 0
}
