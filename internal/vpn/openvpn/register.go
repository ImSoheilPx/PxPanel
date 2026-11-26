// Package-level registration of the seams the RADIUS foundation asks the
// protocol wave to fill. Imported for side effects by the server wire-up (the
// controllers wave); the registration happens in Register so an explicit call
// stays testable — the package does NOT register from init(), because the
// RADIUS server may start before this package's settings are readable and the
// resolver reads inbounds lazily anyway (it is called per-session, so late
// registration is harmless).
//
// PORT NOTE: vpn-ui's radius.go reached OpenVpnService.parseSettings directly
// for session→inbound attribution; the foundation routes per-protocol subnet
// readers through vpn.RegisterSubnetResolver. The reader here mirrors
// ovpnSubnetsOrDefault (web/service/radius.go): the UDP-side /24s, plus their
// 10.3.x TCP mirrors, because a device may hold its address on either
// transport.
package openvpn

import (
	"fmt"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	vpnrange "github.com/ImSoheilPx/pxpanel/internal/vpn/range"
)

// Register attaches OpenVPN's per-protocol readers to the shared registries.
// Call once at server wire-up (after the DB handle is set); safe to call again.
func Register() {
	// Session→inbound attribution (radius.sessionInboundByIP /
	// subnetHoldsIP): both transports' subnets, since a session's
	// Framed-IP-Address comes from whichever transport the device dialed.
	vpn.RegisterSubnetResolver("openvpn", ovpnSubnetsForInbound)
}

// ovpnSubnetsOrDefault returns the ordered /24 prefixes for an OpenVPN transport
// (udp => 10.2.x, tcp => 10.3.x mirror), falling back to the legacy id-derived
// /24 when no ranges are stored.
// (vpn-ui web/service/radius.go ovpnSubnetsOrDefault — the writeClientConfigDir
// caller came along with it into this package.)
func ovpnSubnetsOrDefault(settings *openvpnSettings, proto string, id int) []string {
	subs := vpnrange.SubnetsOf(settings.effectiveRanges())
	if len(subs) == 0 {
		second := 2
		if proto == "tcp" {
			second = 3
		}
		return []string{fmt.Sprintf("10.%d.%d", second, id)}
	}
	if proto == "tcp" {
		out := make([]string, len(subs))
		for i, s := range subs {
			out[i] = vpnrange.MirrorOvpnSubnet(s)
		}
		return out
	}
	return subs
}

// ovpnSubnetsForInbound returns the ordered /24 prefixes ("10.2.5", "10.3.5")
// the inbound's sessions may hold addresses in: its stored UDP ranges, or the
// legacy id-derived 10.2.{id}, each mirrored to its TCP 10.3.x twin.
func ovpnSubnetsForInbound(inbound *model.Inbound) []string {
	if inbound == nil {
		return nil
	}
	settings, err := (&OpenVpnService{}).parseSettings(inbound)
	if err != nil {
		return nil
	}
	subs := vpnrange.SubnetsOf(settings.effectiveRanges())
	if len(subs) == 0 {
		udp := fmt.Sprintf("10.2.%d", inbound.Id)
		return []string{udp, vpnrange.MirrorOvpnSubnet(udp)}
	}
	out := make([]string, 0, len(subs)*2)
	for _, s := range subs {
		out = append(out, s, vpnrange.MirrorOvpnSubnet(s))
	}
	return out
}
