// Steering-source registry: the seam where the per-protocol packages feed the
// shared nftables ruleset.
//
// PORT SHAPE: vpn-ui's NftService.ApplyNftRules (web/service/nftables.go:500)
// reached into all nine protocol services directly (L2tpService, PptpService,
// OpenVpnService, OcservService, SstpService, Ikev2Service, WgcService,
// AwgService, GreService) to gather each enabled inbound's client subnets,
// c2c/cross toggles, dokodemo port, MSS clamps and raw-vs-IPsec gates. Those
// services live in separate packages here (internal/vpn/<proto>/, landing wave
// by wave), so the gathering is a registration instead of a cross-package
// import: every protocol package registers one SteeringSource in its init(),
// and whoever regenerates the ruleset (each protocol's SetupRouting, verbatim
// the vpn-ui call shape) builds the input with GatherRulesInput so a
// regeneration never drops another protocol's steering.
//
// Registration order (not map order) drives rule emission order, so the
// ruleset text is stable within a process. Rules are order-independent across
// sources (disjoint src/dst verdict pairs), so wave landing order does not
// change behaviour.
//
// TODO(controllers wave): none — this registry is the final shape; new
// protocol packages just register in their own init().
package nftables

import "sync"

// SteeringSource is one protocol's contribution to the shared ruleset.
//
// The func fields (rather than values) keep the gathering lazy: ApplyNftRules
// is called on every protocol save and re-reads the DB each time, exactly like
// vpn-ui's per-service loops did.
type SteeringSource struct {
	// Nets are the protocol's enabled inbounds, one SteeringNet each (client
	// subnets as CIDRs, c2c/cross toggles, TPROXY/dokodemo port). vpn-ui:
	// the per-protocol loops in ApplyNftRules that appended vpnNet entries.
	Nets func() []SteeringNet
	// ExtraInputRules are appended to the input chain after the TPROXY
	// section — the raw-vs-IPsec gates (L2TP's udp/1701, GRE's protocol-47).
	// Exact rule text, vpn-ui shape preserved by the supplying wave.
	ExtraInputRules func() []string
	// ExtraPostroutingRules are appended to the postrouting chain after the
	// cross-inbound section — the IKEv2/GRE TCP MSS clamps.
	ExtraPostroutingRules func() []string
	// GREViews optionally supplies this protocol's per-inbound GRE anti-spoof
	// views (vpn-ui: GreService.NftView). Only the gre package sets it; the
	// merged view fills RulesInput's GREIfaces/GREAllowed/GREBlocked, which the
	// builder emits BEFORE the TPROXY section — the position that matters,
	// because a spoofed packet that looks like a valid saddr must be dropped
	// before the TPROXY accept can swallow it. (vpn-ui had this inline in the
	// same pre-TPROXY position of ApplyNftRules.)
	GREViews func() []GreView
}

var (
	steeringMu      sync.RWMutex
	steeringSources []steeringEntry
)

type steeringEntry struct {
	protocol string
	src      SteeringSource
}

// RegisterSteeringSource attaches one protocol's steering to the shared
// ruleset. Called from each protocol package's init(). Re-registration for the
// same protocol replaces the earlier entry (harmless in tests that re-import).
func RegisterSteeringSource(protocol string, src SteeringSource) {
	steeringMu.Lock()
	defer steeringMu.Unlock()
	for i := range steeringSources {
		if steeringSources[i].protocol == protocol {
			steeringSources[i].src = src
			return
		}
	}
	steeringSources = append(steeringSources, steeringEntry{protocol: protocol, src: src})
}

// GatherRulesInput collects every registered protocol's steering into the
// RulesInput ApplyNftRules consumes. Sources with no nets contribute nothing
// (vpn-ui skipped empty protocol inbound lists the same way). With no
// protocol package loaded (or none with inbounds) the input is empty and
// ApplyNftRules removes the table — matching vpn-ui's all-protocols-empty
// branch.
func GatherRulesInput() RulesInput {
	steeringMu.RLock()
	entries := make([]steeringEntry, len(steeringSources))
	copy(entries, steeringSources)
	steeringMu.RUnlock()

	var input RulesInput
	var greViews []GreView
	for _, e := range entries {
		if e.src.Nets != nil {
			input.Nets = append(input.Nets, e.src.Nets()...)
		}
		if e.src.ExtraInputRules != nil {
			input.ExtraInputRules = append(input.ExtraInputRules, e.src.ExtraInputRules()...)
		}
		if e.src.ExtraPostroutingRules != nil {
			input.ExtraPostroutingRules = append(input.ExtraPostroutingRules, e.src.ExtraPostroutingRules()...)
		}
		if e.src.GREViews != nil {
			greViews = append(greViews, e.src.GREViews()...)
		}
	}
	if len(greViews) > 0 {
		input.GREIfaces, input.GREAllowed, input.GREBlocked = MergeGreViews(greViews)
	}
	return input
}
