package nftables

// The ruleset contributor registry.
//
// vpn-ui's NftService.ApplyNftRules() gathered the steering nets inline, one
// block per protocol service (web/service/nftables.go:500+): it constructed
// every protocol's zero-value service, listed its enabled inbounds and appended
// one vpnNet per inbound. That made nftables.go depend on ALL nine protocol
// services at once.
//
// Here the builder (ApplyNftRules) takes a RulesInput supplied by the caller,
// and each protocol package registers ONE contributor that appends its own
// inbounds' SteeringNets (and any ExtraInputRules / ExtraPostroutingRules /
// GRE view it owns) to a shared RulesInput. RulesInputFor runs every registered
// contributor in registration order — byte-identical output to vpn-ui when the
// same protocols are installed, and no cross-package imports (nftables stays a
// leaf; the protocol packages close over their own services).
//
// LEGACY REGISTRY: this was the l2tp+pptp wave's seam, before the
// SteeringSource registry (steering.go) superseded it. The later protocol
// waves (sstp/ikev2/wgc/awg/gre/openvpn/ocserv) register THERE, and
// GatherRulesInput flushes BOTH registries — so a contributor registered here
// is still seen by every regeneration. l2tp and pptp themselves have since
// migrated to SteeringSource (their waves' rule text is unchanged); nothing
// new should register here — use RegisterSteeringSource — but the mechanism
// stays because third-party code or an older wave may still hold a
// contributor, and dropping it silently is exactly the regeneration bug this
// registry exists to prevent.

import "sync"

var (
	rulesMu          sync.RWMutex
	rulesContributor []func(*RulesInput)
)

// RegisterRulesContributor attaches one protocol's steering contribution. Call
// from the protocol package's init(): any binary that links the protocol gets
// its nets in the regenerated ruleset, exactly like vpn-ui where ApplyNftRules
// reached every service directly.
func RegisterRulesContributor(f func(*RulesInput)) {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	rulesContributor = append(rulesContributor, f)
}

// RulesInputFor is the legacy entry point (vpn-ui ApplyNftRules() with no
// argument — the self-gather). It now delegates to GatherRulesInput, so a
// caller using either entry point sees the SAME total ruleset: legacy
// contributors first, then every SteeringSource. l2tp/pptp kept calling this
// shape after their waves; delegating (rather than leaving the two paths
// disjoint) is what makes their regenerations keep the other protocols'
// TPROXY rules. With nothing registered the input is empty and ApplyNftRules
// removes the table — matching vpn-ui's "no VPN inbounds" branch.
func RulesInputFor() RulesInput {
	return GatherRulesInput()
}
