package pptp

// PPTP's nftables contribution + the small nft/policy-route wrappers the
// service calls. vpn-ui's NftService.ApplyNftRules() self-gathered every
// protocol's steering nets; this file is PPTP's contribution — exactly the
// vpn-ui blocks for the pptp inbounds (web/service/nftables.go: the
// cross-inbound net and the TPROXY steering). PPTP adds no extra input-chain
// rules (its control port is filtered by pptpd itself; only L2TP's raw-vs-IPsec
// gate needs one).

import (
	"github.com/ImSoheilPx/pxpanel/internal/vpn/nftables"
)

// nftService mirrors vpn-ui's NftService field type: a thin handle over the
// shared nftables.Service whose ApplyNftRules now takes the gathered RulesInput.
type nftService nftables.Service

// ApplyNftRules regenerates the whole VPN ruleset from every registered
// protocol's contribution (vpn-ui NftService.ApplyNftRules() with no args — the
// gather is the steering registry now).
func (s *nftService) ApplyNftRules(input nftables.RulesInput) error {
	svc := nftables.Service(*s)
	return svc.ApplyNftRules(input)
}

// CleanupLegacyIptables drops the pre-nft iptables rules older panel versions
// installed (vpn-ui NftService.CleanupLegacyIptables).
func (s *nftService) CleanupLegacyIptables() {
	svc := nftables.Service(*s)
	svc.CleanupLegacyIptables()
}

// ensureVpnPolicyRoute is the shared fwmark policy route setup
// (nftables.EnsureVpnPolicyRoute taking the runner — same shape as vpn-ui's
// ensureVpnPolicyRoute(s.runCmd) call).
func ensureVpnPolicyRoute(run func(name string, args ...string) error) {
	nftables.EnsureVpnPolicyRoute(run)
}

// pptpSteeringNets is this protocol's SteeringSource: one net per enabled pptp
// inbound (cross-inbound pass) plus its TPROXY port (paired dokodemo). The body
// is the pptp block of vpn-ui's ApplyNftRules verbatim.
func pptpSteeringNets() []nftables.SteeringNet {
	svc := &PptpService{}
	inbounds, err := svc.GetPptpInbounds()
	if err != nil {
		return nil
	}

	var nets []nftables.SteeringNet
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		st, err := svc.parseSettings(inbound)
		if err != nil {
			continue
		}
		nets = append(nets, nftables.SteeringNet{
			Subnets:    nftables.SubnetCIDRs(svc.GetSubnetsForInbound(inbound)),
			C2C:        st.ClientToClient,
			Cross:      st.CrossInbound,
			TproxyPort: svc.GetTproxyPort(inbound),
		})
	}
	return nets
}

func init() {
	// Register PPTP's steering contribution: one net per enabled pptp inbound
	// (cross-inbound pass) plus its TPROXY port (paired dokodemo). Registered
	// into the shared SteeringSource registry so any protocol's regeneration
	// (GatherRulesInput) keeps PPTP's rules live — and PPTP's own regeneration
	// (SetupRouting) keeps everyone else's.
	nftables.RegisterSteeringSource("pptp", nftables.SteeringSource{Nets: pptpSteeringNets})
}
