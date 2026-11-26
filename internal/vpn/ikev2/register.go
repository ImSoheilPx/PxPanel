// Package-level registration of the seams the RADIUS foundation asks the
// protocol wave to fill, plus this protocol's steering source for the shared
// nftables ruleset. Imported by the server wire-up (the controllers wave); the
// registration happens in Register so an explicit call stays testable — the
// package does NOT register from init(), because the RADIUS server may start
// before this package's settings are readable and the readers run lazily
// anyway (they are called per-session, so late registration is harmless).
//
// PORT NOTE: vpn-ui's radius.go routed the ikev2 branches of
// KillSessionsByEmail / isIPActive / GetSubnetsForInbound straight into
// Ikev2Service; the foundation dispatches those through
// vpn.RegisterProtocolEvictor / vpn.RegisterIPProber /
// vpn.RegisterSubnetResolver, and this file is where the wave fills them.
package ikev2

import (
	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/nftables"
)

// Register attaches IKEv2's seams to the shared registries. Call once at server
// wire-up (after the DB handle is set); safe to call again.
func Register() {
	// RADIUS teardown dispatch (vpn-ui radius.go called
	// (&Ikev2Service{}).KillClientIP(nil, ip)). A single shared charon serves
	// every inbound, so eviction needs no inbound routing — terminate the IKE SA
	// holding this virtual IP via swanctl. swanctl --terminate is idempotent, so
	// a session another path already reaped is a harmless no-op.
	//
	// radius_alloc.go invokes the user-limit accept eviction through a goroutine
	// for ikev2 (swanctl --list-sas must never run inside the auth handler — see
	// killIkev2ByIP); this closure itself stays synchronous and cheap.
	vpn.RegisterProtocolEvictor("ikev2", func(ip string) error {
		killIkev2ByIP((&Ikev2Service{}).swanctlBin(), ip)
		return nil
	})
	// Liveness probe (vpn-ui radius.go isIPActive routed ikev2 to
	// Ikev2Service): charon assigns the client's virtual IP as a remote vip
	// (not a local addr), so ask whether any live IKE SA still holds it.
	vpn.RegisterIPProber("ikev2", ikev2IPActive)
	// Session→inbound attribution for the RADIUS server (vpn-ui radius.go read
	// Ikev2Service.GetSubnetsForInbound directly). ikev2 shares one daemon and
	// sends a bare NAS-Identifier, so the tunnel address is resolved against
	// each inbound's own block (radius.sessionInboundByIP).
	vpn.RegisterSubnetResolver("ikev2", func(inbound *model.Inbound) []string {
		if inbound == nil {
			return nil
		}
		return (&Ikev2Service{}).GetSubnetsForInbound(inbound)
	})
	// Shared-ruleset steering (vpn-ui nftables.go IKEv2 TPROXY + MSS-clamp
	// loops). Registering here means ANY protocol's regeneration that gathers
	// through nftables.GatherRulesInput keeps IKEv2's rules live.
	nftables.RegisterSteeringSource("ikev2", (&Ikev2Service{}).steeringSource())
}
