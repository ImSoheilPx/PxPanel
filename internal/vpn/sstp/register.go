// Package-level registration of the seams the RADIUS foundation asks the
// protocol wave to fill, plus this protocol's steering source for the shared
// nftables ruleset. Imported by the server wire-up (the controllers wave); the
// registration happens in Register so an explicit call stays testable — the
// package does NOT register from init(), because the RADIUS server may start
// before this package's settings are readable and the readers run lazily
// anyway (they are called per-session, so late registration is harmless).
//
// PORT NOTE: vpn-ui's radius.go reached SstpService.parseSettings /
// GetSubnetsForInbound directly for session→inbound attribution and called
// SstpService.KillClientIP for teardowns; the foundation routes those through
// vpn.RegisterSubnetResolver / vpn.RegisterProtocolEvictor, with the
// inbound-for-IP routing vpn-ui kept in radius.go (sstpInboundForIP) moved
// into this package (sstp.go).
package sstp

import (
	"fmt"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/nftables"
)

// Register attaches SSTP's seams to the shared registries. Call once at server
// wire-up (after the DB handle is set); safe to call again.
func Register() {
	// RADIUS teardown dispatch (vpn-ui radius.go KillSessionsByEmail /
	// radius_alloc.go user-limit accept eviction called SstpService.KillClientIP
	// directly). accel-ppp is one daemon per inbound, so the IP's /24 names the
	// daemon whose control socket takes the terminate (sstpInboundForIP).
	vpn.RegisterProtocolEvictor("sstp", func(ip string) error {
		inbound := sstpInboundForIP(ip)
		if inbound == nil {
			return fmt.Errorf("sstp: no inbound claims %s; cannot route accel-cmd terminate", ip)
		}
		return (&SstpService{}).KillClientIP(inbound, ip)
	})
	// Session→inbound attribution for the RADIUS server (vpn-ui radius.go read
	// SstpService.GetSubnetsForInbound directly). SSTP sessions carry a
	// per-inbound NAS-Identifier, but the shared pool resolution still wants
	// the inbound's /24 prefixes.
	vpn.RegisterSubnetResolver("sstp", func(inbound *model.Inbound) []string {
		if inbound == nil {
			return nil
		}
		return (&SstpService{}).GetSubnetsForInbound(inbound)
	})
	// Shared-ruleset steering (vpn-ui nftables.go per-protocol loops).
	// Registering here means ANY protocol's regeneration that gathers through
	// nftables.GatherRulesInput keeps SSTP's TPROXY rules live.
	nftables.RegisterSteeringSource("sstp", (&SstpService{}).steeringSource())
}
