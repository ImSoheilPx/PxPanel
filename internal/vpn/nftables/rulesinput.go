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
// Registered so far: l2tp + pptp (this wave). TODO(<proto> waves): openvpn,
// openconnect, sstp, ikev2, wgc, awg, gre register theirs; gre also fills
// GREIfaces/GREAllowed/GREBlocked, ikev2+gre add the MSS-clamp
// ExtraPostroutingRules, and the web wave's traffic/reconcile jobs call
// RulesInputFor() wherever vpn-ui called ApplyNftRules() with no argument.

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

// RulesInputFor gathers every registered protocol's contribution into the
// RulesInput handed to ApplyNftRules. With no contributors the input is empty
// and ApplyNftRules removes the table — matching vpn-ui's "no VPN inbounds"
// branch.
func RulesInputFor() RulesInput {
	rulesMu.RLock()
	contribs := append([]func(*RulesInput){}, rulesContributor...)
	rulesMu.RUnlock()
	input := RulesInput{}
	for _, c := range contribs {
		c(&input)
	}
	return input
}
