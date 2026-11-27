// The no-drops guarantee, pinned: every tunnel protocol registers its
// steering, and the gather sees the legacy contributor registry too.
//
// This test links all nine protocol packages so their registrations run —
// exactly what the server binary links. It cannot assert net counts (the
// Nets funcs read the panel DB, absent here), but the FAILURE MODE it guards
// is precisely registration absence: a protocol with no SteeringSource is
// silently absent from every GatherRulesInput, so the next regeneration
// rebuilds the shared vpn table without its TPROXY rules and its clients'
// traffic bypasses Xray — routing rules and accounting stop applying to it
// with a valid config and a running core. RegisteredSteeringProtocols makes
// that absence assertable.
//
// linux-only (netlink); compiles+type-checks on any host, runs in CI.
package nftables_test

import (
	"slices"
	"testing"

	// The five init()-registering protocols are side-effect imports: linking
	// them is what runs their registration, mirroring the server binary.
	_ "github.com/ImSoheilPx/pxpanel/internal/vpn/awg"
	_ "github.com/ImSoheilPx/pxpanel/internal/vpn/gre"
	_ "github.com/ImSoheilPx/pxpanel/internal/vpn/l2tp"
	_ "github.com/ImSoheilPx/pxpanel/internal/vpn/pptp"
	_ "github.com/ImSoheilPx/pxpanel/internal/vpn/wgc"

	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ikev2"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/nftables"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ocserv"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/openvpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/sstp"
)

// TestEveryTunnelProtocolRegistersSteering pins the coverage of the steering
// registry over defaults.TunnelProtocols (the storage-contract protocol list).
// The four Register()-seam protocols are called explicitly: the server wire-up
// (controller.RegisterVpnProtocols) runs them before the first Init* — and
// therefore before the first regeneration — and they are idempotent.
func TestEveryTunnelProtocolRegistersSteering(t *testing.T) {
	// Registering here mirrors the wire-up; harmless if a later wave moves
	// these to init() (re-registration replaces by protocol id).
	openvpn.Register()
	ocserv.Register()
	sstp.Register()
	ikev2.Register()

	registered := nftables.RegisteredSteeringProtocols()
	for _, proto := range defaults.TunnelProtocols {
		if !slices.Contains(registered, proto) {
			t.Errorf("protocol %q has no nftables.SteeringSource: any regeneration through GatherRulesInput rebuilds the shared vpn table WITHOUT its TPROXY rules, so its clients' traffic bypasses Xray routing entirely", proto)
		}
	}
}

// A legacy RegisterRulesContributor must still reach every regeneration path:
// GatherRulesInput (the current entry point) AND RulesInputFor (the shape the
// early waves call). The two registries existing side by side is only safe
// while both are honoured by both paths.
func TestLegacyContributorSeenByEveryGatherPath(t *testing.T) {
	before := len(nftables.GatherRulesInput().Nets)

	nftables.RegisterRulesContributor(func(input *nftables.RulesInput) {
		input.Nets = append(input.Nets, nftables.SteeringNet{
			Subnets:    []string{"10.254.254.0/24"},
			TproxyPort: 65499,
		})
	})

	gathered := nftables.GatherRulesInput()
	if len(gathered.Nets) != before+1 {
		t.Fatalf("GatherRulesInput saw %d nets, want %d+1: the legacy contributor registry is not flushed", len(gathered.Nets), before)
	}
	if !slices.ContainsFunc(gathered.Nets, func(n nftables.SteeringNet) bool { return n.TproxyPort == 65499 }) {
		t.Errorf("GatherRulesInput = %+v, want the legacy contributor's net included", gathered.Nets)
	}

	viaLegacy := nftables.RulesInputFor()
	if len(viaLegacy.Nets) != before+1 {
		t.Fatalf("RulesInputFor saw %d nets, want %d+1: it must see the same total input as GatherRulesInput", len(viaLegacy.Nets), before)
	}
}
