// Paired-inbound builders: the dokodemo-door pairing for the nine tunnel
// protocols and the loopback socks pairing for the two relays. Ported from
// vpn-ui web/service/xray.go (the pairing half of GetXrayConfig) and the
// byte-identical GetDokodemoConfig bodies in l2tp.go / pptp.go / openvpn.go /
// openconnect.go / sstp.go / ikev2.go / wgc.go / awg.go / gre.go plus the
// GetSocksConfig bodies in mtproto.go / ssh.go.
package xrayplane

import (
	"encoding/json"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/util/json_util"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

// TproxyPortBase is the panel-wide "Xray-side port for inbound N" convention:
// every paired inbound (dokodemo or socks) listens on 12300+inbound.Id.
// inbound.Id is globally unique across protocols, so paired ports can never
// collide with each other or with the inbounds they front.
const TproxyPortBase = 12300

// TproxyPort returns the paired inbound's port for this inbound.
// (vpn-ui: per-protocol GetTproxyPort — nine identical bodies.)
func TproxyPort(inbound *model.Inbound) int {
	return TproxyPortBase + inbound.Id
}

// IsVpnProtocol reports whether p is one of the nine pool VPN protocols.
// (vpn-ui web/service/inbound.go isVpnProtocol.) Their raw settings must never
// reach Xray as native inbounds: Xray would reject the unknown protocol and the
// WHOLE core would fail to start, taking every other inbound down with it.
func IsVpnProtocol(p model.Protocol) bool {
	for _, tp := range defaults.TunnelProtocols {
		if string(p) == tp {
			return true
		}
	}
	return false
}

// IsRelayProtocol reports whether p is a relay: it terminates its own protocol
// outside Xray (telemt for mtproto, the in-binary gateway for ssh) and reaches
// Xray through a PAIRED socks inbound the panel builds separately
// (GetSocksConfig), sharing this inbound's tag.
// (vpn-ui web/service/inbound.go isRelayProtocol.)
func IsRelayProtocol(p model.Protocol) bool {
	return p == defaults.ProtoMTProto || p == defaults.ProtoMTProtoC || p == defaults.ProtoSSH
}

// GetDokodemoConfig builds the paired dokodemo-door inbound config for Xray.
// This config captures TPROXY-redirected tunnel traffic and feeds it into
// Xray's routing.
//
// vpn-ui carried one byte-identical body per protocol service
// (L2tpService.GetDokodemoConfig &c); the per-protocol waves keep those method
// names as one-line delegates to this builder.
func GetDokodemoConfig(inbound *model.Inbound) *xray.InboundConfig {
	port := TproxyPort(inbound)
	settings := `{"network":"tcp,udp","followRedirect":true}`
	streamSettings := `{"sockopt":{"tproxy":"tproxy","mark":255}}`
	sniffing := `{"enabled":true,"destOverride":["http","tls"]}`

	return &xray.InboundConfig{
		Listen:         json_util.RawMessage(`"0.0.0.0"`),
		Port:           port,
		Protocol:       "dokodemo-door",
		Settings:       json_util.RawMessage(settings),
		StreamSettings: json_util.RawMessage(streamSettings),
		Tag:            inbound.Tag,
		Sniffing:       json_util.RawMessage(sniffing),
	}
}

// SocksAccount is one RFC1929 identity on a paired relay socks inbound.
// (vpn-ui: the local socksAccount struct inside each GetSocksConfig.)
type SocksAccount struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

// socksSniffingMtproto / socksSniffingSsh are the paired socks inbounds'
// sniffing blobs, kept as the vpn-ui literals.
const (
	socksSniffingMtproto = `{"enabled":true,"destOverride":["tls"]}`
	socksSniffingSsh     = `{"enabled":true,"destOverride":["tls","http","quic"]}`
)

// buildSocksConfig is the converged body of the two relay GetSocksConfig
// implementations. udp toggles UDP ASSOCIATE (ssh only), sniffing is the
// per-relay literal. Nil when there is nothing to inject: a socks inbound with
// no accounts would reject every egress.
func buildSocksConfig(inbound *model.Inbound, accounts []SocksAccount, udp bool, sniffing string) *xray.InboundConfig {
	if len(accounts) == 0 {
		return nil
	}

	socksSettings, err := json.Marshal(struct {
		Auth     string         `json:"auth"`
		Accounts []SocksAccount `json:"accounts"`
		UDP      bool           `json:"udp"`
	}{Auth: "password", Accounts: accounts, UDP: udp})
	if err != nil {
		return nil
	}

	return &xray.InboundConfig{
		Listen:   json_util.RawMessage(`"127.0.0.1"`),
		Port:     TproxyPort(inbound),
		Protocol: "socks",
		Settings: json_util.RawMessage(socksSettings),
		Tag:      inbound.Tag,
		Sniffing: json_util.RawMessage(sniffing),
	}
}

// MtprotoSocksConfig builds the loopback socks inbound that telemt egresses
// through. It carries inbound.Tag, so an operator's Xray routing rules target
// this MTProto inbound exactly like any other. Nil accounts means "no routing":
// adtag (middle-proxy) mode must reach Telegram directly and gets NO socks
// inbound — the provider (RelayAccountsFor) reports that, not this builder.
//
// This is the mtproto analogue of the tunnel protocols' GetDokodemoConfig: same
// hook in the config build, different shape (a socks listener rather than TPROXY
// capture, since there is no tunnel to intercept).
//
// It also carries PER-CLIENT identity. Every other VPN protocol gives each
// device a tunnel IP and routes it with a source-IP rule; a relay has no such
// IP, so the account rides the one channel a socks hop has: the RFC1929
// username. telemt presents the authenticated account there
// (upstreams.socks_user_from_account), Xray copies it to inbound.User.Email,
// and routing rules matching `user` resolve per client: same operator-facing
// behaviour, different carrier.
//
// The password is the account name, not a secret: this listener is bound to
// 127.0.0.1 and both ends of the credential are generated by this panel, so it
// is an identity assertion between two local processes, not an auth boundary.
// Anyone who could reach the port already has local root.
func MtprotoSocksConfig(inbound *model.Inbound, accounts []SocksAccount) *xray.InboundConfig {
	return buildSocksConfig(inbound, accounts, false, socksSniffingMtproto)
}

// SshSocksConfig builds the loopback socks inbound the SSH server egresses
// through. It is the mtproto shape with UDP enabled: SSH forwards both TCP (via
// direct-tcpip channels) and UDP (via its in-process udpgw bridge), and the UDP
// path needs the socks inbound to accept UDP ASSOCIATE so Xray routes and
// accounts UDP per client too. Per-client identity rides the socks username
// (the account email). Nil when there are no usable accounts.
func SshSocksConfig(inbound *model.Inbound, accounts []SocksAccount) *xray.InboundConfig {
	return buildSocksConfig(inbound, accounts, true, socksSniffingSsh)
}

// RelaySocksConfig resolves the relay's account list through the registered
// (or default) provider and builds the matching socks inbound. Nil when the
// relay must not egress through Xray (adtag mode, or no usable account).
func RelaySocksConfig(inbound *model.Inbound) *xray.InboundConfig {
	accounts, routed := RelayAccountsFor(string(inbound.Protocol), inbound)
	if !routed {
		return nil
	}
	switch inbound.Protocol {
	case defaults.ProtoMTProto, defaults.ProtoMTProtoC:
		// Both mtproto planes share the telemt socks shape (mtproto-c IS the
		// telemt plane under its own protocol string; plain mtproto rows are
		// filtered out before InjectPairedInbounds by the caller, so this arm
		// only ever sees mtproto-c rows in practice).
		return MtprotoSocksConfig(inbound, accounts)
	case defaults.ProtoSSH:
		return SshSocksConfig(inbound, accounts)
	default:
		return nil
	}
}

// InjectPairedInbounds appends the paired Xray inbound for every enabled VPN
// inbound: a dokodemo-door for each of the nine tunnel protocols, a loopback
// socks for each relay (mtproto per inbound; ssh with UDP ASSOCIATE).
//
// This is the vpn-ui pairing half of GetXrayConfig (web/service/xray.go): the
// caller renders the Xray-native inbounds (the 3x-ui lineage path), then calls
// this with the full inbound list, then calls TranslateVpnRoutingRules LAST.
//
// Omitting a protocol here is not a no-op: its raw settings would be handed to
// Xray as a native inbound, Xray would reject the unknown protocol, and the
// WHOLE core would fail to start, taking every other inbound down with it.
// Conversely, non-VPN protocols are skipped here — they are native and already
// rendered by the caller.
func InjectPairedInbounds(cfg *xray.Config, inbounds []*model.Inbound) {
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		switch {
		case IsVpnProtocol(inbound.Protocol):
			dokodemoConfig := GetDokodemoConfig(inbound)
			cfg.InboundConfigs = append(cfg.InboundConfigs, *dokodemoConfig)
		case inbound.Protocol == defaults.ProtoMTProto, inbound.Protocol == defaults.ProtoMTProtoC, inbound.Protocol == defaults.ProtoSSH:
			// The loopback socks inbound each relay egresses through. Carries
			// inbound.Tag, so operator routing rules target the relay like any
			// other inbound. Nil for an adtag-mode mtproto inbound (middle-proxy
			// must egress directly) or an SSH inbound with no usable account.
			if socksConfig := RelaySocksConfig(inbound); socksConfig != nil {
				cfg.InboundConfigs = append(cfg.InboundConfigs, *socksConfig)
			}
		}
	}
}
