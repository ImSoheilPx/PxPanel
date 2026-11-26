package vpnout

// The client-tunnel clause of the shared charon's need-check, and the wire-up
// that installs it. vpn-ui computed vpnOutboundNeedsCharon inside the one
// `service` package, where charon.go could read VpnOutboundService.listRaw
// directly; the target splits charon's need-check between internal/vpn/ikev2
// (SetVpnOutboundNeedHook) and internal/vpn/ipsec (RegisterCharonNeeder), so
// the framework carries the clause here and hands it to both through
// WireCharonNeed at server wire-up.

import (
	"encoding/json"

	"github.com/ImSoheilPx/pxpanel/internal/vpn/ikev2"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ipsec"
)

// WireCharonNeed registers the client-side outbounds' claim on the shared
// charon with the two packages that decide its lifecycle. Call once at server
// wire-up (the same place SetNeedRestartHook / SetRestartHook are composed);
// idempotent in effect — ikev2's hook is last-wins, ipsec's needers append,
// and both end up asking this package the same pure question.
//
// Without it the exact failure ipsec/charon.go's comment predicts lands: on a
// box that dials out over IKEv2 (or GRE-IPsec, or L2TP/IPsec) but serves no
// IPsec inbound of its own, counting inbounds alone answers "not needed" and
// an unrelated inbound save stops charon out from under a live tunnel.
func WireCharonNeed() {
	ikev2.SetVpnOutboundNeedHook(vpnOutboundNeedsCharon)
	ipsec.RegisterCharonNeeder(vpnOutboundNeedsCharon)
}

// vpnOutboundNeedsCharon reports whether any enabled client tunnel rides the
// shared charon daemon: an IKEv2 outbound always does, an L2TP one does when it
// carries a PSK (which is how the L2TP/IPsec transport leg is configured on
// both sides), and a GRE one does when it is wrapped in IPsec. Ported verbatim
// from vpn-ui web/service/charon.go.
//
// Every kind whose settings decide it reads ONE field, matched against the
// driver's own json tag. Keep this switch in step with the drivers: a kind
// that rides charon and is missing here fails silently, as a tunnel that dies
// on an unrelated inbound save rather than as anything pointing at this
// function.
//
// Read off the stored tunnel list rather than asked of the drivers, because the
// answer is needed while deciding whether to STOP charon, which is exactly when
// a driver may already have been torn down and would report nothing.
func vpnOutboundNeedsCharon() bool {
	var svc VpnOutboundService
	// listRaw, not List: List masks driver-declared secrets for the panel, and the
	// psk below is exactly such a secret. Reading it through the masked view would
	// find nothing, answer "no IPsec outbound", and stop charon under a live tunnel.
	for _, c := range svc.listRaw() {
		if !c.Enable {
			continue
		}
		switch c.Kind {
		case VpnOutIKEv2:
			return true
		case VpnOutL2TP:
			// The settings blob is the driver's shape, so this looks only for the one
			// field that decides it rather than unmarshalling something this file
			// would then have to keep in step.
			//
			// The tag has to match the l2tp outbound settings' IpsecPsk exactly. A
			// near miss here does not fail loudly: the branch simply never fires, and
			// the symptom is a live L2TP/IPsec tunnel dropping when somebody saves an
			// unrelated inbound, which points nowhere near this line.
			var s struct {
				IpsecPsk string `json:"ipsecPsk"`
			}
			if len(c.Settings) > 0 && json.Unmarshal(c.Settings, &s) == nil && s.IpsecPsk != "" {
				return true
			}
		case VpnOutGre:
			// GRE-over-IPsec is ESP transport on this same daemon, exactly as the GRE
			// INBOUND clause already accounts for.
			var s struct {
				IpsecEnable bool `json:"ipsecEnable"`
			}
			if len(c.Settings) > 0 && json.Unmarshal(c.Settings, &s) == nil && s.IpsecEnable {
				return true
			}
		}
	}
	return false
}
