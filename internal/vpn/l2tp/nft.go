package l2tp

// The nftables contribution + the small nft/policy-route wrappers the service
// calls. vpn-ui's NftService.ApplyNftRules() self-gathered every protocol's
// steering nets; here the shared builder (nftables.ApplyNftRules) takes a
// RulesInput that each protocol wave contributes to, and this file is L2TP's
// contribution — exactly the vpn-ui blocks for the l2tp inbounds
// (web/service/nftables.go: the cross-inbound net, the TPROXY steering, and the
// raw-L2TP input gate).

import (
	"github.com/ImSoheilPx/pxpanel/internal/vpn/nftables"
)

// nftService mirrors vpn-ui's NftService field type: a thin handle over the
// shared nftables.Service whose ApplyNftRules now takes the gathered RulesInput.
type nftService nftables.Service

// ApplyNftRules regenerates the whole VPN ruleset from every registered
// protocol's contribution (vpn-ui NftService.ApplyNftRules() with no args — the
// gather is the contributor registry now).
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

func init() {
	// Register L2TP's steering contribution: one net per enabled l2tp inbound
	// (cross-inbound pass), its TPROXY port (paired dokodemo), and — when any
	// inbound runs IPsec without allowing raw L2TP — the input-chain gate that
	// blocks non-IPsec L2TP on UDP 1701 (vpn-ui nftables.go "Raw L2TP filter").
	nftables.RegisterRulesContributor(func(input *nftables.RulesInput) {
		svc := &L2tpService{}
		inbounds, err := svc.GetL2tpInbounds()
		if err != nil {
			return
		}

		for _, inbound := range inbounds {
			if !inbound.Enable {
				continue
			}
			st, err := svc.parseSettings(inbound)
			if err != nil {
				continue
			}
			input.Nets = append(input.Nets, nftables.SteeringNet{
				Subnets:    nftables.SubnetCIDRs(svc.GetSubnetsForInbound(inbound)),
				C2C:        st.ClientToClient,
				Cross:      st.CrossInbound,
				TproxyPort: svc.GetTproxyPort(inbound),
			})
		}

		// Raw L2TP filter: block non-IPsec L2TP when ipsecEnable && !allowRaw
		needFilter := false
		for _, inbound := range inbounds {
			settings, err := svc.parseSettings(inbound)
			if err != nil {
				continue
			}
			if settings.IpsecEnable && !settings.AllowRaw {
				needFilter = true
				break
			}
		}
		if needFilter {
			// Accept L2TP that arrived via IPsec, drop the rest
			input.ExtraInputRules = append(input.ExtraInputRules,
				"add rule ip vpn input udp dport 1701 meta secpath exists accept",
				"add rule ip vpn input udp dport 1701 drop")
		}
	})
}
