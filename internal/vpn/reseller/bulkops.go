// The bulk-op mutation semantics, ported VERBATIM from vpn-ui
// web/service/inbound.go (the shared bulk applier's per-client rules).
//
// Why this lives in the reseller package: the bulk PRICER must run the applier's
// own rules over every targeted membership — "what does subTraffic do to
// totalGB", the floor-at-one rule, which clients the skip toggles pass over —
// because charging for an account the applier would skip is an overcharge, and
// REFUNDING one is free balance. A second implementation of those rules is a
// second place for them to drift, and a drift here is money.
//
// The inbound wave's applier (vpn-ui InboundService.BulkUpdateClients) should
// re-point at THESE definitions rather than re-porting its own copy.
package reseller

import "encoding/json"

// BulkClientTarget is one (inbound, email) pair a bulk request names.
type BulkClientTarget struct {
	InboundId int    `json:"inboundId"`
	Email     string `json:"email"`
}

// BulkClientUpdateRequest describes a bulk operation applied to many clients across
// many inbounds. Op is one of addDays/subDays/addTraffic/subTraffic/enable/disable.
// Days is used by the day ops; AmountBytes by the traffic ops.
type BulkClientUpdateRequest struct {
	Op            string `json:"op"`
	Days          int64  `json:"days"`
	AmountBytes   int64  `json:"amountBytes"`
	SkipFirstUse  bool   `json:"skipFirstUse"`
	SkipUnlimited bool   `json:"skipUnlimited"`
	SkipDisabled  bool   `json:"skipDisabled"`
	// InboundIds is the membership operations' own argument: the inbounds the
	// selected accounts are being added TO or removed FROM. Every other op names
	// its targets and nothing else, and leaves this empty.
	//
	// It is deliberately NOT a second way to name targets. The bulk applier does
	// not read it at all; only the membership handler does, and that one applies
	// its change through the accounts layer rather than through this applier.
	InboundIds []int              `json:"inboundIds"`
	Targets    []BulkClientTarget `json:"targets"`
}

// BulkClientUpdateResult reports how many targeted clients were changed vs skipped
// (by a skip toggle, a no-op op, or because the client wasn't found).
type BulkClientUpdateResult struct {
	Applied int `json:"applied"`
	Skipped int `json:"skipped"`
}

const bulkMsPerDay = int64(86400000)

// bulkClientSkipped reports whether the skip toggles pass this client over.
func bulkClientSkipped(cm map[string]any, req BulkClientUpdateRequest) bool {
	expiry := bulkNumToInt64(cm["expiryTime"])
	total := bulkNumToInt64(cm["totalGB"])
	enable, _ := cm["enable"].(bool)

	if req.SkipFirstUse && expiry < 0 {
		return true
	}
	if req.SkipDisabled && !enable {
		return true
	}
	if req.SkipUnlimited {
		switch req.Op {
		case "addDays", "subDays":
			if expiry == 0 { // unlimited time (lifetime): don't stamp a deadline
				return true
			}
		default: // traffic ops, enable/disable, freeze/unfreeze, delete: unlimited traffic
			if total == 0 {
				return true
			}
		}
	}
	return false
}

// applyBulkClientOp mutates one client map per the request, returning false when the
// op is a no-op for that client. Skip-toggle filtering is done by the caller via
// bulkClientSkipped, so every op is filtered uniformly. Semantics:
//   - addDays/subDays adjust expiryTime: >0 absolute (ms), <0 delayed "start after
//     first use" (grow the delay when adding), ==0 no expiry (addDays anchors from now).
//   - subTraffic floors totalGB at 1 byte so a subtract never flips a limited account
//     to unlimited (totalGB==0 means unlimited).
func applyBulkClientOp(cm map[string]any, req BulkClientUpdateRequest, now int64) bool {
	expiry := bulkNumToInt64(cm["expiryTime"])
	total := bulkNumToInt64(cm["totalGB"])
	enable, _ := cm["enable"].(bool)

	// Skip-toggle filtering happens in the caller (bulkClientSkipped). Freeze disables
	// the account and LOCKS its remaining time: a running (absolute) expiry is stored as
	// its negative remaining — the panel's "delayed start" form, which does not tick down
	// or trigger the auto-disable/expire check while the account is off. GB is locked for
	// free (a disabled account passes no traffic). Unfreeze re-enables and resumes the
	// clock immediately, converting the locked remaining back to an absolute deadline from
	// now. A frozen account is thus recognisable as (enable=false AND expiryTime<0).
	// frozenNoExpiry marks a frozen account that had NO expiry to lock (unlimited
	// duration). A frozen account must be recognisable as (enable=false AND
	// expiryTime<0); a no-expiry account has expiryTime==0, so without this sentinel
	// freezing it would leave expiryTime==0 and it would read as a plain disable, not
	// frozen (no cross icon / no "Frozen" badge, and it could never be unfrozen). The
	// magnitude 1(ms) can't collide with a real locked remaining (always a multi-day
	// duration) or a real delayed-start value, so unfreeze restores it to 0.
	const frozenNoExpiry int64 = -1
	switch req.Op {
	case "freeze":
		if !enable && expiry < 0 {
			return false // already frozen (disabled + locked) -> no-op
		}
		switch {
		case expiry > 0:
			cm["expiryTime"] = now - expiry // = -(remaining): a non-ticking delayed value
		case expiry == 0:
			cm["expiryTime"] = frozenNoExpiry // no expiry to lock: mark frozen via sentinel
			// expiry < 0 (a delayed-start account being frozen): keep its value as-is.
		}
		cm["enable"] = false
		return true
	case "unfreeze":
		if enable {
			return false // already active -> nothing to unfreeze
		}
		switch {
		case expiry == frozenNoExpiry:
			cm["expiryTime"] = int64(0) // had no expiry -> restore unlimited
		case expiry < 0:
			cm["expiryTime"] = now - expiry // = now + remaining: resume from this moment
		}
		cm["enable"] = true
		return true
	}

	switch req.Op {
	case "addDays":
		ms := req.Days * bulkMsPerDay
		if expiry > 0 {
			expiry += ms
		} else if expiry < 0 {
			expiry -= ms
		} else {
			expiry = now + ms
		}
		cm["expiryTime"] = expiry
	case "subDays":
		if expiry == 0 {
			return false // nothing to shorten on a no-expiry account
		}
		ms := req.Days * bulkMsPerDay
		if expiry > 0 {
			expiry -= ms
		} else { // delayed start: shrink the delay, clamped at 0
			expiry += ms
			if expiry > 0 {
				expiry = 0
			}
		}
		cm["expiryTime"] = expiry
	case "addTraffic":
		cm["totalGB"] = total + req.AmountBytes
	case "subTraffic":
		if total <= 0 {
			return false // unlimited: nothing to subtract
		}
		total -= req.AmountBytes
		if total < 1 {
			total = 1
		}
		cm["totalGB"] = total
	case "enable":
		if enable {
			return false
		}
		cm["enable"] = true
	case "disable":
		if !enable {
			return false
		}
		cm["enable"] = false
	}
	return true
}

// bulkNumToInt64 coerces a JSON-decoded numeric field (float64 by default) to int64.
func bulkNumToInt64(v any) int64 {
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

// cloneClient copies a settings client shallowly, which is all applyBulkClientOp
// needs: it reads and writes scalar keys only, so the nested values shared with
// the original are never reached, let alone mutated.
func cloneClient(cm map[string]any) map[string]any {
	out := make(map[string]any, len(cm))
	for k, v := range cm {
		out[k] = v
	}
	return out
}
