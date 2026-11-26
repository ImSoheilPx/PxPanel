package nftables

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/logger"
	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

// Per-account egress accounting: named nft counters fed by one rule per
// direction per client, read-and-reset atomically by the traffic job. RADIUS
// Acct-Start/Stop and the rbridge sweeper drive Add/Remove; the traffic
// collection calls CollectAndResetTraffic each tick.

// counterKey turns an accounting key into a valid nft counter-name fragment: a client IP
// ("10.0.2.5" -> "10_0_2_5"), or WireGuard's gateway block CIDR where the slash also maps
// to a letter ("10.7.8.8/29" -> "10_7_8_8m29"). CollectAndResetTraffic reverses it.
func counterKey(ipOrCIDR string) string {
	return strings.ReplaceAll(strings.ReplaceAll(ipOrCIDR, ".", "_"), "/", "m")
}

// NftAcctChain is the accounting chain name for one protocol and one direction, dir being
// "in" (uplink, jumped from prerouting) or "out" (downlink, jumped from postrouting).
//
// The static chains in ApplyNftRules are hyphen-free, but a protocol slug can hold a hyphen
// ("wg-c"): an nft chain name with a hyphen would not match the static "wgc_acct_in" chain,
// so the rules would target a missing chain and silently drop, counting nothing. Strip the
// hyphen so the dynamic accounting rules land in the real chain. Counter names deliberately
// keep the raw slug: they carry the protocol back to CollectAndResetTraffic via
// byProto[protocol].
func NftAcctChain(protocol, dir string) string {
	return strings.ReplaceAll(protocol, "-", "") + "_acct_" + dir
}

// AcctProtocols are the protocol slugs that own a pair of accounting chains, already
// hyphen-free so they match NftAcctChain's output ("wgc", not "wg-c"). Kept in one place
// so adding a protocol means adding one entry rather than editing four rule blocks.
var AcctProtocols = []string{
	"l2tp", "pptp", "openvpn", "openconnect", "sstp", "ikev2", "wgc", "awg", "gre",
}

// acctRuleHandles returns the handles of every rule in `chain` that references the named
// counter, in listing order.
//
// It keys on the counter name rather than on the address text for a reason that has bitten
// twice: nft NORMALISES an address before printing it, so a host-prefix key like
// "10.7.1.2/32" (the WireGuard single-device block CIDR) is echoed back as a bare
// "10.7.1.2". Any `strings.Contains(out, "addr "+ip+" ")` test against the original key
// therefore never matches for such a client, which silently turned the add path into
// "append unconditionally" and the remove path into "delete nothing". The counter name is
// echoed verbatim and quoted, and counterKey() already makes it unique per (protocol, ip),
// so it is the one token that survives nft's formatting.
func (s *Service) acctRuleHandles(chain, counter string) []string {
	out, err := exec.Command("nft", "-a", "list", "chain", "ip", "vpn", chain).Output()
	if err != nil {
		return nil
	}
	return acctRuleHandlesFrom(string(out), counter)
}

// acctRuleHandlesFrom is the pure half of acctRuleHandles, split out so the parse can be
// tested against real `nft -a list chain` output.
func acctRuleHandlesFrom(listing, counter string) []string {
	needle := `counter name "` + counter + `"`
	var handles []string
	for _, line := range strings.Split(listing, "\n") {
		if !strings.Contains(line, needle) {
			continue
		}
		if idx := strings.Index(line, "# handle "); idx >= 0 {
			handles = append(handles, strings.TrimSpace(line[idx+len("# handle "):]))
		}
	}
	return handles
}

// AddClientAccounting creates named nft counters and accounting rules for a VPN client.
// `ip` is a client IP, or (WireGuard gateway model) the account's block CIDR — nft matches
// either in `ip saddr`. Called by RADIUS Acct-Start / the rbridge sweep for a new session.
//
// Reconciles to EXACTLY one rule per direction. Both callers fire repeatedly for a session
// that is already live (every Acct-Start, every sweep that re-notices it), and an accounting
// chain carries no verdict, so traversal does not stop at the first match: a second copy of
// the same rule counts every packet twice and bills the account double. Extra copies are
// deleted rather than tolerated so an install that already accumulated them heals on the
// next call instead of over-billing until the session ends.
func (s *Service) AddClientAccounting(protocol, ip string) error {
	counterIP := counterKey(ip)
	upCounter := fmt.Sprintf("%s_up_%s", protocol, counterIP)
	downCounter := fmt.Sprintf("%s_down_%s", protocol, counterIP)

	// Create counters (idempotent)
	s.runCmd("nft", "add", "counter", "ip", "vpn", upCounter)
	s.runCmd("nft", "add", "counter", "ip", "vpn", downCounter)

	s.reconcileAcctRule(NftAcctChain(protocol, "in"), upCounter, "saddr", ip)
	s.reconcileAcctRule(NftAcctChain(protocol, "out"), downCounter, "daddr", ip)

	logger.Debugf("nft: added %s accounting for %s", protocol, ip)
	return nil
}

// reconcileAcctRule leaves EXACTLY one rule in `chain` feeding `counter`, matching the
// client on `match` ("saddr" or "daddr"). Anything else present is deleted first, so an
// install that already accumulated duplicates heals here instead of over-billing until the
// session ends.
func (s *Service) reconcileAcctRule(chain, counter, match, ip string) {
	handles := s.acctRuleHandles(chain, counter)
	if len(handles) == 1 {
		return // already exactly right
	}
	for _, h := range handles {
		s.runCmd("nft", "delete", "rule", "ip", "vpn", chain, "handle", h)
	}
	s.runCmd("nft", "add", "rule", "ip", "vpn", chain, "ip", match, ip, "counter", "name", counter)
}

// RemoveClientAccounting removes nft accounting rules and counters for a PPP client.
// Called by RADIUS Acct-Stop to stop traffic counting when a session ends.
func (s *Service) RemoveClientAccounting(protocol, ip string) error {
	counterIP := counterKey(ip)

	// Remove every rule feeding this client's two counters, in both direction chains.
	// Matching on the counter name (not the address text) is what makes this work for a
	// /32 block CIDR. See acctRuleHandles.
	upCounter := fmt.Sprintf("%s_up_%s", protocol, counterIP)
	downCounter := fmt.Sprintf("%s_down_%s", protocol, counterIP)
	for _, dc := range []struct{ chain, counter string }{
		{NftAcctChain(protocol, "in"), upCounter},
		{NftAcctChain(protocol, "out"), downCounter},
	} {
		for _, h := range s.acctRuleHandles(dc.chain, dc.counter) {
			s.runCmd("nft", "delete", "rule", "ip", "vpn", dc.chain, "handle", h)
		}
	}

	// Delete counters
	s.runCmd("nft", "delete", "counter", "ip", "vpn", upCounter)
	s.runCmd("nft", "delete", "counter", "ip", "vpn", downCounter)

	logger.Debugf("nft: removed %s accounting for %s", protocol, ip)
	return nil
}

// ReadAndResetClientCounters atomically reads AND zeros this client's up/down
// counters, returning the byte deltas accumulated since the last collection. Call
// this right before RemoveClientAccounting on session end so those final bytes are
// persisted rather than discarded when the counters are deleted (otherwise up to a
// full 10s collection window — more under rapid reconnects — is lost from the
// client's quota). Zeroing here also stops the periodic job from double-counting
// the same bytes.
func (s *Service) ReadAndResetClientCounters(protocol, ip string) (up, down int64) {
	counterIP := counterKey(ip)
	up = s.resetCounter(fmt.Sprintf("%s_up_%s", protocol, counterIP))
	down = s.resetCounter(fmt.Sprintf("%s_down_%s", protocol, counterIP))
	return up, down
}

// resetCounter atomically reads+zeros one named counter, returning its bytes (0 if
// missing/unparseable).
func (s *Service) resetCounter(name string) int64 {
	out, err := exec.Command("nft", "-j", "reset", "counter", "ip", "vpn", name).Output()
	if err != nil {
		return 0
	}
	var res nftCounterOutput
	if json.Unmarshal(out, &res) != nil {
		return 0
	}
	for _, raw := range res.Nftables {
		var e nftCounterEntry
		if json.Unmarshal(raw, &e) == nil && e.Counter != nil && e.Counter.Name == name {
			return e.Counter.Bytes
		}
	}
	return 0
}

// CollectAndResetTraffic atomically reads and resets all VPN traffic counters.
// Uses `nft -j reset counters` for atomic read+reset (no race between read and zero).
// byProto maps each VPN protocol id ("l2tp", "pptp", "openvpn", "openconnect", "sstp",
// "ikev2", ...) to its IP→email session map (provided by the RADIUS service). It returns one
// combined ClientTraffic slice, one record per email with its up/down bytes summed across every
// protocol and device; AddTraffic folds these into client_traffics. Protocols absent from
// byProto are ignored, so a new protocol plugs in by adding a map entry (no signature change).
// byProtoInbound carries, per protocol, which INBOUND each tunnel address belongs
// to, so the emitted record names the source of its bytes. That is what lets the
// traffic multiplier bill at the rate of the inbound the traffic actually came
// from rather than at whichever inbound the account's single client_traffics row
// happens to name. A missing or zero entry means "unknown", which the billing
// treats as "take the max across the account's memberships".
func (s *Service) CollectAndResetTraffic(byProto map[string]map[string]string, byProtoInbound map[string]map[string]int) []*xray.ClientTraffic {
	output, err := exec.Command("nft", "-j", "reset", "counters", "table", "ip", "vpn").Output()
	if err != nil {
		return nil
	}

	var result nftCounterOutput
	if err := json.Unmarshal(output, &result); err != nil {
		logger.Debug("nft: failed to parse counter JSON:", err)
		return nil
	}

	// Accumulate traffic per (protocol, inbound, email). AddTraffic sums by email
	// regardless, so the account total is the same however this is bucketed; the
	// inbound is in the key so the per-inbound breakdown is not.
	//
	// It used to be (protocol, email) with the inbound as a FIELD, first writer wins.
	// openvpn, openconnect and sstp may legitimately serve one account from two
	// inbounds at two addresses, and that shape quietly filed both addresses' bytes
	// under whichever inbound the iteration happened to reach first - a coin flip on
	// map order, re-tossed every tick.
	type acctKey struct {
		protocol, email string
		// inboundId is the inbound the tunnel address belongs to: the SOURCE of these
		// bytes. Zero means unknown, which bills at the account's own rate and is left
		// out of the breakdown rather than attributed to a guess.
		inboundId int
	}
	type trafficPair struct{ up, down int64 }
	traffic := make(map[acctKey]*trafficPair)

	for _, raw := range result.Nftables {
		var entry nftCounterEntry
		if err := json.Unmarshal(raw, &entry); err != nil || entry.Counter == nil {
			continue
		}
		c := entry.Counter
		if c.Bytes == 0 {
			continue
		}

		// Parse counter name: {protocol}_{direction}_{ip_octets_with_underscores}
		// e.g. "l2tp_up_10_0_2_10" → protocol=l2tp, dir=up, ip=10.0.2.10
		parts := strings.SplitN(c.Name, "_", 3)
		if len(parts) < 3 {
			continue
		}
		protocol := parts[0]
		direction := parts[1] // "up" or "down"
		// Reverse counterKey: "_" -> ".", and the CIDR marker "m" -> "/" (WireGuard block).
		ip := strings.ReplaceAll(strings.ReplaceAll(parts[2], "_", "."), "m", "/")

		ipMap := byProto[protocol]
		if ipMap == nil {
			continue
		}
		email, ok := ipMap[ip]
		if !ok {
			continue
		}

		key := acctKey{protocol: protocol, email: email, inboundId: byProtoInbound[protocol][ip]}
		pair := traffic[key]
		if pair == nil {
			pair = &trafficPair{}
			traffic[key] = pair
		}
		if direction == "up" {
			pair.up += c.Bytes
		} else if direction == "down" {
			pair.down += c.Bytes
		}
	}

	var out []*xray.ClientTraffic
	for key, pair := range traffic {
		if pair.up > 0 || pair.down > 0 {
			out = append(out, &xray.ClientTraffic{Email: key.email, InboundId: key.inboundId, Up: pair.up, Down: pair.down})
		}
	}
	if len(out) > 0 {
		logger.Debugf("nft: collected VPN traffic for %d client(s)", len(out))
	}
	return out
}

// nftCounterOutput represents the JSON output of `nft -j reset counters`.
type nftCounterOutput struct {
	Nftables []json.RawMessage `json:"nftables"`
}

type nftCounterEntry struct {
	Counter *nftCounter `json:"counter"`
}

type nftCounter struct {
	Family  string `json:"family"`
	Name    string `json:"name"`
	Table   string `json:"table"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
}
