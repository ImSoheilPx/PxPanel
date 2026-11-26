package nftables

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/logger"
	"github.com/vishvananda/netlink"
)

// The shared fwmark policy route.
//
// Every VPN protocol's TPROXY data plane needs the same two pieces of policy
// routing: one rule sending fwmark-1 packets at a private table, and a local
// default route in that table so the kernel delivers them to the dokodemo socket
// instead of forwarding them out of the WAN.

const (
	vpnPolicyMark  = 1
	vpnPolicyTable = 100
)

// vpnPolicyRuleTableTokens is where the old guard went wrong, and it is worth
// being precise about why, because the failure was silent and unbounded.
//
// Nine SetupRouting functions each carried their own copy of
//
//	if !strings.Contains(ipRuleShow(), "fwmark 0x1 lookup 100") { add it }
//
// The table number in that needle is not what `ip rule show` prints. iproute2
// renders the table through /etc/iproute2/rt_tables, so on a host that names
// table 100 the line reads `fwmark 0x1 lookup wanpolicy` and the substring can
// never match. Every SetupRouting call then added another identical rule: nine
// per panel start, nine more per protocol reconcile, forever. The host this was
// found on had 195 copies.
//
// So the token comparison is done against the real name set: the number itself,
// plus every alias iproute2 would print for it. Returns a set rather than a
// string so a host with several aliases for the same id is handled too.
func vpnPolicyRuleTableTokens() map[string]bool {
	tokens := map[string]bool{strconv.Itoa(vpnPolicyTable): true}
	paths, _ := filepath.Glob("/etc/iproute2/rt_tables.d/*.conf")
	for _, path := range append([]string{"/etc/iproute2/rt_tables"}, paths...) {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == strconv.Itoa(vpnPolicyTable) {
				tokens[fields[1]] = true
			}
		}
	}
	return tokens
}

// isVpnPolicyNetlinkRule reports whether r is EXACTLY the rule this helper owns:
// `from all fwmark 0x1 lookup 100`, with no other selector of any kind.
//
// An allowlist of the whole shape, not a check of the two fields we care about,
// because this predicate gates a DELETE. Every additional selector a rule could
// carry is required to be at its unset value, so an operator's
// `from 10.9.9.9 fwmark 1 lookup 100` or `fwmark 1/0xff lookup 100` is somebody
// else's rule and is left alone. It also cannot match the per-tunnel
// `oif <iface> lookup <30000+ifindex>` rules the vpnout wave installs, twice
// over: those carry an OifName and their table is not 100.
//
// Naming cannot confuse this one. A table name is an iproute2 display
// convention; the kernel only ever stores the integer, so r.Table is 100 on a
// host that names it and on a host that does not.
//
// The mask is compared against a FULL mask rather than against nil, and that
// distinction is not cosmetic: it was measured wrong first. `ip rule add fwmark
// 1` sends no FRA_FWMASK, but the kernel fills mark_mask in for any non-zero
// mark and dumps it back, so RuleList reports 0xffffffff on the rule we
// installed ourselves and Mask is never nil on a marked rule. Requiring nil
// there matched nothing at all, which would have left the duplicates in place
// AND added one more on every call — the original bug, deeper.
func isVpnPolicyNetlinkRule(r netlink.Rule) bool {
	return r.Table == vpnPolicyTable &&
		r.Mark == vpnPolicyMark &&
		(r.Mask == nil || *r.Mask == 0xffffffff) &&
		r.Src == nil && r.Dst == nil &&
		r.IifName == "" && r.OifName == "" &&
		!r.Invert &&
		r.SuppressPrefixlen < 0 && r.SuppressIfgroup < 0 &&
		r.Goto < 0 && r.Flow < 0 &&
		r.Tos == 0 && r.TunID == 0 && r.IPProto == 0 &&
		r.Dport == nil && r.Sport == nil && r.UIDRange == nil
}

// vpnPolicyCollapsePlan decides what to do about the policy rules found on the
// host, given their priorities in kernel order. Returns the index of the one to
// keep, the indices to delete, and whether one has to be added because there are
// none.
//
// N identical rules are exactly equivalent to one, which is what makes the
// collapse behaviour-preserving rather than a judgement call: a packet matching
// any of them matches the first, and if that first lookup misses (an empty table
// 100 makes the kernel fall through to the next rule) every copy behind it
// misses in the same table for the same reason.
//
// The KEPT one is the lowest priority — the first the kernel evaluates, and
// therefore the one that is deciding the host's forwarding today. Keeping that
// exact rule rather than an arbitrary copy means the surviving rule sits in the
// same place in the ordering relative to whatever else the operator has
// installed, so nothing about the live routing decision moves.
func vpnPolicyCollapsePlan(prefs []int) (keep int, drop []int, add bool) {
	if len(prefs) == 0 {
		return -1, nil, true
	}
	keep = 0
	for i, pref := range prefs {
		if pref < prefs[keep] {
			keep = i
		}
	}
	for i := range prefs {
		if i != keep {
			drop = append(drop, i)
		}
	}
	return keep, drop, false
}

// vpnPolicyRulePrefsFromOutput counts the policy rules in `ip -j rule show` or
// plain `ip rule show` output, returning their priorities.
//
// The degraded path, used only when the kernel cannot be enumerated over
// netlink. It can answer "is one already there" and so stop another duplicate
// being added, but it deliberately does not drive deletion: see
// CollapseVpnPolicyRules for why a rule has to be deleted by its enumerated
// self and never by a text-matched template.
//
// Both formats are read because `ip -j` only exists from iproute2 4.13 and the
// oldest supported targets predate it. Unrecognised shapes are treated as NOT
// ours, which fails toward adding a rule: a spurious duplicate is the bug we
// already had, whereas failing toward "it must already be there" would leave a
// host with no policy rule at all and no data plane.
func vpnPolicyRulePrefsFromOutput(out []byte, tokens map[string]bool) []int {
	trimmed := strings.TrimSpace(string(out))
	if strings.HasPrefix(trimmed, "[") {
		return vpnPolicyRulePrefsFromJSON([]byte(trimmed), tokens)
	}
	var prefs []int
	for _, line := range strings.Split(trimmed, "\n") {
		if pref, ok := vpnPolicyRuleTextMatch(line, tokens); ok {
			prefs = append(prefs, pref)
		}
	}
	return prefs
}

// vpnPolicyRuleTextMatch matches one line of `ip rule show`. The whole token
// stream has to be `from all fwmark <mark> lookup <table>` and nothing else, for
// the same allowlist reason as isVpnPolicyNetlinkRule.
func vpnPolicyRuleTextMatch(line string, tokens map[string]bool) (int, bool) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return 0, false
	}
	pref, err := strconv.Atoi(strings.TrimSpace(line[:colon]))
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(line[colon+1:])
	// `lookup` is what every iproute2 in the wild prints; `table` is accepted as
	// a synonym so a future rename does not silently reopen this bug.
	if len(fields) != 6 || fields[0] != "from" || fields[1] != "all" ||
		fields[2] != "fwmark" || (fields[4] != "lookup" && fields[4] != "table") {
		return 0, false
	}
	// Base 0 so both the modern "0x1" and a bare "1" parse. A "0x1/0xff" carries
	// a mask, fails to parse, and is correctly rejected as not ours.
	mark, err := strconv.ParseUint(fields[3], 0, 32)
	if err != nil || mark != vpnPolicyMark || !tokens[fields[5]] {
		return 0, false
	}
	return pref, true
}

// vpnPolicyRulePrefsFromJSON reads `ip -j rule show`.
//
// Decoded to a bare map rather than a struct so the KEY SET can be checked: a
// selector this code has never heard of still shows up as an unexpected key and
// disqualifies the rule, where a struct would silently drop it and call somebody
// else's rule ours.
func vpnPolicyRulePrefsFromJSON(out []byte, tokens map[string]bool) []int {
	var entries []map[string]any
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil
	}
	var prefs []int
	for _, entry := range entries {
		ok := true
		for key := range entry {
			// `protocol` is provenance (kernel/boot/static), not a selector.
			switch key {
			case "priority", "src", "fwmark", "table", "protocol":
			default:
				ok = false
			}
		}
		mark, err := strconv.ParseUint(fmt.Sprint(entry["fwmark"]), 0, 32)
		table, _ := entry["table"].(string)
		src, _ := entry["src"].(string)
		pref, isNum := entry["priority"].(float64)
		if !ok || err != nil || mark != vpnPolicyMark || !tokens[table] ||
			(src != "all" && src != "") || !isNum {
			continue
		}
		prefs = append(prefs, int(pref))
	}
	return prefs
}

// EnsureVpnPolicyRoute installs the shared `fwmark 1 lookup 100` policy rule and
// the local default route in that table, collapsing any pile of duplicate rules
// an older build left behind. Every protocol's SetupRouting calls this instead of
// carrying its own copy; nine copies of the guard is why one wrong substring
// became nine leaks per reconcile.
//
// run is the caller's runCmd, so the add is still logged against the protocol
// that asked for it.
func EnsureVpnPolicyRoute(run func(name string, args ...string) error) {
	if !CollapseVpnPolicyRules(false) {
		run("ip", "rule", "add", "fwmark", strconv.Itoa(vpnPolicyMark), "lookup", strconv.Itoa(vpnPolicyTable))
	}
	run("ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", strconv.Itoa(vpnPolicyTable))
}

// CollapseVpnPolicyRules reduces the host to at most one policy rule and reports
// whether one is left. Pass removeAll to leave none, which is what the whole-host
// uninstall wants.
//
// Deletion goes over netlink, against the rule struct read back from the kernel,
// and NOT by shelling out to `ip rule del fwmark 1 lookup 100`. That command is
// not the precise instrument it looks like. The kernel's rule_find treats every
// selector ABSENT from a delete request as a wildcard, so measured against a
// throwaway namespace holding one rule of each shape, a single
// `ip rule del pref P from all fwmark 1 lookup 100` deleted
// `from 10.9.9.9 fwmark 0x1 lookup 100`, `oif eth0 fwmark 0x1 lookup 100`,
// `iif eth0 fwmark 0x1 lookup 100` and `to 10.8.8.8 fwmark 0x1 lookup 100`
// alike: the src, oif, iif and dst on the existing rules were simply ignored,
// even with `from all` spelled out. netlink.RuleDel on an enumerated rule sends
// every field back, including the ones that make it distinct, so it can only
// match the rule that was actually looked at.
func CollapseVpnPolicyRules(removeAll bool) bool {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		// No exact enumeration means no safe deletion. Fall back to reading
		// `ip rule show` well enough to avoid adding yet another duplicate.
		return len(vpnPolicyRulePrefsFromOutput(vpnPolicyRuleShow(), vpnPolicyRuleTableTokens())) > 0
	}
	var mine []netlink.Rule
	for _, r := range rules {
		if isVpnPolicyNetlinkRule(r) {
			mine = append(mine, r)
		}
	}
	keep, drop, _ := vpnPolicyCollapsePlan(vpnPolicyRulePrefs(mine))
	if removeAll {
		keep, drop = -1, nil
		for i := range mine {
			drop = append(drop, i)
		}
	}
	for _, i := range drop {
		if err := netlink.RuleDel(&mine[i]); err != nil {
			logger.Warning("could not remove a duplicate fwmark policy rule at priority",
				mine[i].Priority, ":", err)
		}
	}
	if n := len(drop); n > 0 && !removeAll {
		logger.Infof("collapsed %d duplicate 'fwmark %d lookup %d' rules left by an earlier release, keeping the one at priority %d",
			n, vpnPolicyMark, vpnPolicyTable, mine[keep].Priority)
	}
	return keep >= 0
}

// vpnPolicyRulePrefs lifts the priorities out for the pure planner.
func vpnPolicyRulePrefs(rules []netlink.Rule) []int {
	prefs := make([]int, 0, len(rules))
	for _, r := range rules {
		prefs = append(prefs, r.Priority)
	}
	return prefs
}

// vpnPolicyRuleShow reads the rule table as text, preferring JSON.
func vpnPolicyRuleShow() []byte {
	if out, err := exec.Command("ip", "-j", "rule", "show").Output(); err == nil &&
		strings.HasPrefix(strings.TrimSpace(string(out)), "[") {
		return out
	}
	out, _ := exec.Command("ip", "rule", "show").Output()
	return out
}
