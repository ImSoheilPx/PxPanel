// Package nftables is vpn-ui's nftables layer (web/service/nftables.go) ported
// into pxpanel: table/rules management for the VPN data plane (TPROXY steering
// into the Xray dokodemo pair, NAT-era leftovers, policy routing) plus the
// per-account egress ACCOUNTING counters that RADIUS Acct-Start/Stop and the
// rbridge sweeper drive.
//
// PORT SHAPE: vpn-ui's ApplyNftRules pulled all nine protocol services
// (L2tpService, PptpService, OpenVpnService, OcservService, SstpService,
// Ikev2Service, WgcService, AwgService, GreService) to gather each inbound's
// client subnets, c2c/cross toggles and dokodemo port. The protocol stack is a
// LATER wave here, so that gathering is expressed as RulesInput/SteeringNet —
// the protocol wave maps its settings onto these and calls ApplyNftRules. The
// emitted ruleset is byte-identical for identical input; only the caller-side
// gathering moved.
package nftables

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/logger"
)

// NftConfigFile is the host path the generated ruleset is written to before
// `nft -f` loads it. PORT NOTE: vpn-ui used /etc/vpn-ui/vpn.nft; the product
// path is renamed here. Ownership-manifest tracking of the file (vpn-ui
// records it in ownership.json so uninstall can remove it) lands with the
// ownership wave — until then the file is untracked.
var NftConfigFile = "/etc/pxpanel/vpn.nft"

// vpnAddrSpace is the covering /12 (10.0.0.0-10.15.255.255) for the protocol /16s
// VPN clients live in (10.0 L2TP, 10.1 PPTP, 10.2/10.3 OpenVPN, 10.4 OpenConnect,
// 10.5 SSTP, 10.6 IKEv2, 10.7 wg-c, 10.8 AmneziaWG, 10.9 GRE — see the vpnrange
// package). Trusting the whole /12 in firewalld + using it as the routing
// blackhole backstop covers every current and future auto-expanded /24. It must
// stay a superset of every protocol base /16, so widen it when adding protocols.
const vpnAddrSpace = "10.0.0.0/12"

// SteeringNet is one enabled VPN inbound's client address space plus its
// inter-client reachability toggles, used to build the cross-inbound rules and
// the inbound's TPROXY steering. OpenVPN carries both its UDP and TCP block
// CIDRs in Subnets. PORT NOTE: this replaces the per-protocol
// GetSubnetsForInbound/parseSettings gathering in vpn-ui's ApplyNftRules.
type SteeringNet struct {
	Subnets    []string // CIDRs, e.g. "10.0.5.0/24"
	C2C        bool     // Client to Client
	Cross      bool     // Cross Inbound (UI-gated behind Client to Client)
	TproxyPort int      // the inbound's paired dokodemo port; 0 emits no TPROXY rules
}

// RulesInput is everything the static ruleset builder needs beyond the plain
// steering nets. The two filter families and the GRE anti-spoof view are the
// protocol-specific bits vpn-ui built inline from its settings structs; the
// protocol wave supplies them pre-rendered (the exact rule text is preserved
// below in the builders that consume them).
type RulesInput struct {
	// Nets are the enabled VPN inbounds (one SteeringNet each).
	Nets []SteeringNet

	// GRE anti-spoof/block view, already merged across inbounds by
	// MergeGreViews (vpn-ui GreNftView → mergeGreViews).
	GREIfaces  []string
	GREAllowed map[string][]string
	GREBlocked []string

	// ExtraInputRules are appended to the input chain after the TPROXY
	// section — the L2TP raw-vs-IPsec gate ("add rule ip vpn input udp dport
	// 1701 ...") and the GRE raw-vs-IPsec gate ("ip protocol 47 meta secpath
	// ...") are emitted this way, exact text supplied by the protocol wave.
	ExtraInputRules []string

	// ExtraPostroutingRules are appended to the postrouting chain after the
	// cross-inbound section — the IKEv2/GRE TCP MSS clamp rules, exact text
	// supplied by the protocol wave.
	ExtraPostroutingRules []string
}

// Service manages nftables rules for the VPN protocols' traffic accounting,
// TPROXY steering, and NAT-era cleanup.
type Service struct{}

// ---------------------------------------------------------------------------
// Host networking defaults
// ---------------------------------------------------------------------------

// readSysctl reads one sysctl's current value, or "" when it cannot be read (a
// key this kernel does not have).
func readSysctl(key string) string {
	out, err := exec.Command("sysctl", "-n", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// firewalldRunning reports whether firewalld is installed and active.
func firewalldRunning() bool {
	if !commandExists("firewall-cmd") {
		return false
	}
	out, _ := exec.Command("firewall-cmd", "--state").CombinedOutput()
	return strings.TrimSpace(string(out)) == "running"
}

// commandExists reports whether name resolves on PATH.
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// EnsureVpnHostNetworking relaxes the two host-level packet-filtering defaults
// that silently break VPN routing on Fedora/RHEL but not on Debian/Ubuntu — the
// reason "the VPN connects but has no internet" there:
//
//   - rp_filter: Fedora ships net.ipv4.conf.all.rp_filter=1 (strict), which drops
//     the policy-routed (fwmark → table 100) TPROXY packets on their way to the
//     Xray socket. Ubuntu defaults to loose (2); we set loose here too.
//   - firewalld: active by default on Fedora with an INPUT policy that rejects
//     everything but the explicitly opened service ports. TPROXY delivers each
//     client packet to a LOCAL socket while it still carries the client's
//     ORIGINAL destination port (e.g. 443), so firewalld's filter_INPUT drops it
//     before Xray ever sees it — control-plane auth (over the opened L2TP/PPTP/
//     OpenVPN ports) succeeds, but no data flows. Trusting the VPN source space
//     makes firewalld accept the TPROXY'd data plane.
//
// Idempotent and cheap; a no-op on hosts without an active firewalld.
//
// PORT NOTE: vpn-ui captured the pre-existing sysctl values in its ownership
// manifest (ownClaimPrev/ownSysctl) and restored them from the core uninstall
// (restoreHostSysctls). That manifest is the ownership wave; until it lands
// this relaxes without recording. Do not add untracked host mutations beyond
// these two keys without extending that wave first.
func EnsureVpnHostNetworking() {
	// rp_filter → loose. `all` is the effective-max override; set `default` too so
	// PPP/tun interfaces created later inherit loose rather than strict.
	for _, key := range []string{"net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"} {
		_ = exec.Command("sysctl", "-w", key+"=2").Run()
	}

	if !firewalldRunning() {
		return
	}
	// Only add the trusted source when it isn't already there. Add it to both the
	// runtime and permanent configs so no `firewall-cmd --reload` (which would drop
	// other runtime-only state) is needed.
	out, _ := exec.Command("firewall-cmd", "--zone=trusted", "--query-source="+vpnAddrSpace).CombinedOutput()
	if strings.TrimSpace(string(out)) == "yes" {
		return
	}
	if err := exec.Command("firewall-cmd", "--zone=trusted", "--add-source="+vpnAddrSpace).Run(); err != nil {
		logger.Warningf("firewalld: failed to trust VPN space %s: %v", vpnAddrSpace, err)
		return
	}
	_ = exec.Command("firewall-cmd", "--permanent", "--zone=trusted", "--add-source="+vpnAddrSpace).Run()
	logger.Infof("firewalld: trusted VPN space %s so the TPROXY data plane reaches Xray", vpnAddrSpace)
}

// ---------------------------------------------------------------------------
// Generic rule emission (pure)
// ---------------------------------------------------------------------------

// SubnetCIDRs turns "10.0.5" /24 prefixes into "10.0.5.0/24" CIDR strings.
func SubnetCIDRs(subnets []string) []string {
	out := make([]string, 0, len(subnets))
	for _, p := range subnets {
		out = append(out, p+".0/24")
	}
	return out
}

// WriteClientToClientRules emits the inter-client (client-to-client) rules for a
// VPN inbound's client subnet(s), placed BEFORE its TPROXY rules so they take
// effect first. Traffic where BOTH src and dst are client IPs is:
//   - accepted (kernel forwards it straight to the peer) when the toggle is ON;
//   - dropped when OFF — otherwise it would be TPROXY'd to Xray, whose direct
//     outbound would still deliver it to the other client (both live on the
//     server's tun), making the toggle a no-op.
//
// Multiple subnets (OpenVPN UDP+TCP) get every src/dst pair so cross-transport
// client-to-client is covered too.
func WriteClientToClientRules(b *strings.Builder, subnets []string, enabled bool) {
	verdict := "drop"
	if enabled {
		verdict = "accept"
	}
	for _, src := range subnets {
		for _, dst := range subnets {
			// The tunnel's own gateway address lives INSIDE the client subnet, so the
			// client-to-client deny would otherwise swallow it and a client could not
			// reach the address the panel tells it to route through. That is not
			// client-to-client traffic: it terminates on this host. Verified on a live
			// peer -- with the deny in place a gateway ping got 100% loss and worked the
			// moment the toggle flipped, which reads as a dead tunnel even though
			// forwarding was fine the whole time.
			//
			// Scoped to daddr INSIDE the subnet on purpose. A bare `fib daddr type local`
			// would also match the server's public address and divert client traffic away
			// from the TPROXY rules below, changing how every protocol egresses.
			if !enabled {
				b.WriteString(fmt.Sprintf(
					"add rule ip vpn prerouting ip saddr %s ip daddr %s fib daddr type local accept\n", src, dst))
			}
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s ip daddr %s %s\n", src, dst, verdict))
		}
	}
}

// WriteCrossInboundRules emits, for every pair of DIFFERENT inbounds, the verdict
// governing whether one inbound's client may reach another's: accept when BOTH
// opted into Cross Inbound (which requires Client to Client), drop otherwise.
//
// The drop is load-bearing: it sits before the per-inbound TPROXY rules, so a
// non-opted pair is dropped in the kernel instead of falling through to the
// sender's TPROXY rule, entering Xray, and being delivered to the peer by Xray's
// freedom outbound (both clients are local to this host) — which would bridge the
// two inbounds no matter how Cross Inbound is set. Same-inbound pairs are skipped
// here; they are governed by that inbound's own WriteClientToClientRules.
func WriteCrossInboundRules(b *strings.Builder, nets []SteeringNet) {
	for ai, a := range nets {
		for bi, bnet := range nets {
			if ai == bi {
				continue
			}
			verdict := "drop"
			if a.Cross && a.C2C && bnet.Cross && bnet.C2C {
				verdict = "accept"
			}
			for _, sa := range a.Subnets {
				for _, dst := range bnet.Subnets {
					b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s ip daddr %s %s\n", sa, dst, verdict))
				}
			}
		}
	}
}

// writeTPROXYRules emits one inbound's TPROXY steering: both transports from
// every client subnet into the inbound's dokodemo port. `meta mark != 0xff`
// keeps an already-marked packet from looping (the re-injected TPROXY socket
// path marks 0xff before re-entering).
func writeTPROXYRules(b *strings.Builder, srcs []string, port int) {
	for _, src := range srcs {
		b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol tcp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
		b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol udp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
	}
}

// ---------------------------------------------------------------------------
// Static ruleset builder
// ---------------------------------------------------------------------------

// ApplyNftRules regenerates and atomically loads the nftables config for all VPN
// inbounds described by input. Static chains (prerouting/postrouting/input) are
// flushed and rebuilt. Accounting chains (<proto>_acct_in / <proto>_acct_out)
// are NEVER flushed: their dynamic per-client rules survive across regenerations.
func (s *Service) ApplyNftRules(input RulesInput) error {
	// If no VPN inbounds at all, remove the table entirely.
	if len(input.Nets) == 0 {
		s.runCmd("nft", "delete", "table", "ip", "vpn")
		os.Remove(NftConfigFile)
		return nil
	}

	// VPN is active — make sure the host's rp_filter/firewalld defaults don't
	// silently drop the TPROXY'd data plane (the Fedora/RHEL "connects but no
	// internet" failure). No-op on Debian/Ubuntu.
	EnsureVpnHostNetworking()

	var b strings.Builder

	// Create table and chains (idempotent — 'add' doesn't error if they already exist)
	b.WriteString("add table ip vpn\n")
	for _, p := range AcctProtocols {
		b.WriteString(fmt.Sprintf("add chain ip vpn %s\n", p+"_acct_in"))
		b.WriteString(fmt.Sprintf("add chain ip vpn %s\n", p+"_acct_out"))
	}
	b.WriteString("add chain ip vpn prerouting { type filter hook prerouting priority mangle; policy accept; }\n")
	b.WriteString("add chain ip vpn postrouting { type filter hook postrouting priority mangle; policy accept; }\n")
	b.WriteString("add chain ip vpn input { type filter hook input priority filter; policy accept; }\n")

	// Flush only static chains (accounting chains are dynamic, never flushed)
	b.WriteString("flush chain ip vpn prerouting\n")
	b.WriteString("flush chain ip vpn postrouting\n")
	b.WriteString("flush chain ip vpn input\n")

	// Accounting jumps (must be before TPROXY so packets are counted before accept).
	//
	// Each direction is jumped from exactly ONE hook: uplink at prerouting, downlink at
	// postrouting. A single combined chain jumped from both hooks counts a FORWARDED
	// packet twice, because such a packet traverses prerouting AND postrouting and would
	// match its direction's rule in each. TPROXY'd TCP/UDP masked that (those packets are
	// locally delivered on the way in and locally generated on the way out, so they only
	// ever see one hook), but client-to-client, cross-inbound and every non-TCP/UDP
	// protocol are forwarded and were billed at 2x. Splitting by direction is exactly
	// once under BOTH topologies.
	for _, p := range AcctProtocols {
		b.WriteString(fmt.Sprintf("add rule ip vpn prerouting jump %s\n", p+"_acct_in"))
	}
	for _, p := range AcctProtocols {
		b.WriteString(fmt.Sprintf("add rule ip vpn postrouting jump %s\n", p+"_acct_out"))
	}

	// --- Cross-inbound pass (mutual opt-in) --------------------------------
	// Accept or drop each inter-inbound pair. See WriteCrossInboundRules for why
	// the drop is load-bearing.
	WriteCrossInboundRules(&b, input.Nets)

	// --- Protocol-wave-supplied postrouting rules (MSS clamps) -------------
	for _, rule := range input.ExtraPostroutingRules {
		b.WriteString(strings.TrimRight(rule, "\n") + "\n")
	}

	// --- GRE anti-spoofing + hard blocks -----------------------------------
	// See MergeGreViews for why the allow-set is aggregated PER NETDEV ACROSS
	// EVERY INBOUND before a single rule is emitted for it: only one unkeyed
	// catch-all may bind a given local address, so every GRE inbound on one
	// server address SHARES that netdev. Emitting one rule per inbound
	// therefore had each inbound's rule drop every other inbound's accounts,
	// which made a second GRE inbound completely unusable.
	for _, iface := range input.GREIfaces {
		addrs := input.GREAllowed[iface]
		if len(addrs) == 0 {
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting iifname \"%s\" counter drop comment \"gre-antispoof-all\"\n", iface))
			continue
		}
		b.WriteString(fmt.Sprintf(
			"add rule ip vpn prerouting iifname \"%s\" ip saddr != { %s } counter drop comment \"gre-antispoof\"\n",
			iface, strings.Join(addrs, ", ")))
	}
	// Hard block for accounts that are disabled, expired or over quota. Every other
	// protocol enforces this by refusing the handshake; here the account's route and
	// neighbour entry are withdrawn, but the promiscuous catch-all would still
	// decapsulate its packets, so the drop has to be explicit.
	for _, cidr := range input.GREBlocked {
		b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s counter drop comment \"gre-blocked\"\n", cidr))
	}

	// --- Per-inbound client-to-client gate + TPROXY steering ---------------
	for _, net := range input.Nets {
		WriteClientToClientRules(&b, net.Subnets, net.C2C)
		if net.TproxyPort != 0 {
			writeTPROXYRules(&b, net.Subnets, net.TproxyPort)
		}
	}

	// --- Protocol-wave-supplied input rules (raw-vs-IPsec gates) -----------
	for _, rule := range input.ExtraInputRules {
		b.WriteString(strings.TrimRight(rule, "\n") + "\n")
	}

	// Write and load atomically
	if err := os.MkdirAll("/etc/pxpanel", 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(NftConfigFile, []byte(b.String()), 0o644); err != nil {
		return err
	}
	if err := s.runCmd("nft", "-f", NftConfigFile); err != nil {
		return fmt.Errorf("failed to load nft rules: %w", err)
	}

	// Best-effort: drop the legacy OpenVPN NAT chain left by older versions that
	// masqueraded OpenVPN straight to the internet. OpenVPN now routes via TPROXY,
	// so the chain is obsolete. Both calls no-op once it's gone.
	s.runCmd("nft", "flush", "chain", "ip", "vpn", "nat_post")
	s.runCmd("nft", "delete", "chain", "ip", "vpn", "nat_post")

	// Best-effort: drop the pre-split combined "<proto>_acct" chains. The static chains
	// were rebuilt above without their jumps, so on an upgraded box they linger holding
	// dead rules that nothing reaches. AddClientAccounting repopulates the new direction
	// chains on the next reconcile tick. Both calls no-op once they're gone.
	for _, p := range AcctProtocols {
		s.runCmd("nft", "flush", "chain", "ip", "vpn", p+"_acct")
		s.runCmd("nft", "delete", "chain", "ip", "vpn", p+"_acct")
	}

	logger.Infof("nft: loaded VPN rules (%d steering nets)", len(input.Nets))
	return nil
}

// ---------------------------------------------------------------------------
// GRE view merging (pure)
// ---------------------------------------------------------------------------

// GreView is one GRE inbound's nft view: the netdevs it binds with their
// allowed (account) addresses, plus the accounts that must be hard-blocked.
// PORT NOTE: replaces vpn-ui's GreNftView produced by GreService.NftView —
// the GRE wave produces these.
type GreView struct {
	Allowed map[string][]string // netdev -> allowed inner addresses
	Blocked []string            // CIDRs to hard-block (disabled/expired/over-quota)
}

// MergeGreViews folds every GRE inbound's view into ONE allow-set per netdev, plus the
// combined block list. Returns the netdev names in sorted order and their sorted addresses,
// so a regenerated ruleset is byte-identical when nothing changed.
//
// Merging is REQUIRED, not cosmetic. Only one unkeyed catch-all may bind a given local
// address, so every GRE inbound on one server address shares that netdev. Emitting one
// anti-spoof rule per inbound made each inbound's rule drop every other inbound's accounts,
// which left a second GRE inbound unable to pass any traffic at all.
func MergeGreViews(views []GreView) (ifaces []string, allowed map[string][]string, blocked []string) {
	set := map[string]map[string]bool{}
	for _, v := range views {
		for iface, addrs := range v.Allowed {
			if set[iface] == nil {
				set[iface] = map[string]bool{}
			}
			for _, a := range addrs {
				set[iface][a] = true
			}
		}
		blocked = append(blocked, v.Blocked...)
	}
	allowed = make(map[string][]string, len(set))
	ifaces = make([]string, 0, len(set))
	for iface, addrSet := range set {
		ifaces = append(ifaces, iface)
		list := make([]string, 0, len(addrSet))
		for a := range addrSet {
			list = append(list, a)
		}
		sort.Strings(list)
		allowed[iface] = list
	}
	sort.Strings(ifaces)
	sort.Strings(blocked)
	return ifaces, allowed, blocked
}

// ---------------------------------------------------------------------------
// Legacy cleanup
// ---------------------------------------------------------------------------

// CleanupLegacyIptables removes old iptables rules left from the pre-nftables implementation.
// All commands are idempotent (silent failure if rules don't exist).
//
// PORT NOTE: vpn-ui also swept per-inbound TPROXY leftovers by asking
// L2tpService/PptpService for each inbound's subnet/port. That matters only on
// boxes upgraded from the pre-nftables vpn-ui; the protocol wave can re-add the
// per-inbound sweep when it lands. The chain deletions below cover the rest.
func (s *Service) CleanupLegacyIptables() {
	// Remove L2TP_ACCT chain
	s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING", "-j", "L2TP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-D", "POSTROUTING", "-j", "L2TP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-F", "L2TP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-X", "L2TP_ACCT")

	// Remove PPTP_ACCT chain
	s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING", "-j", "PPTP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-D", "POSTROUTING", "-j", "PPTP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-F", "PPTP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-X", "PPTP_ACCT")

	// Remove old raw L2TP filter
	s.runCmd("iptables", "-D", "INPUT", "-p", "udp", "--dport", "1701",
		"-m", "policy", "--dir", "in", "--pol", "none", "-j", "DROP")

	logger.Info("nft: cleaned up legacy iptables rules")
}

func (s *Service) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debugf("nft: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}
