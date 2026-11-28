// The MTProto inbound-policy compatibility block: the connection modes, the FakeTLS
// domain and the device cap used to live on every CLIENT of an inbound, and data in
// that pre-move shape keeps arriving long after the upgrade (restored backups,
// `migrate`, API callers scripted against the old field names, a rollback binary that
// wrote and was rolled forward again). Two halves cover it, and both have to exist:
//
//   - READ: resolveMtprotoPolicy resolves the effective policy out of EITHER shape and
//     mtprotoSettings.UnmarshalJSON applies it, so nothing can read a legacy inbound as
//     "no modes at all" merely because the lift has not run on it yet.
//   - WRITE: MirrorInboundSettingsToClients copies the inbound's settled values back
//     down onto every client, so the same blob still means something to the OLD binary.
//
// Ported VERBATIM from vpn-ui web/service/mtproto.go (WAVE-2 P5). The block sits in
// this package — not in defaults — because deriveMtprotoPolicy resolves device caps
// through vpnrange's effective-user-limit math and vpnrange imports defaults, so
// defaults cannot host the trio without an import cycle. defaults.NormalizeInboundSettings
// reaches the lift through defaults.MtprotoSettingsLifter, which init() below points at
// LiftMtprotoSettingsBlob (the same registration convention as the validator hook).
package mtproto

import (
	"encoding/json"
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
	vpnrange "github.com/ImSoheilPx/pxpanel/internal/vpn/range"
)

// init registers the pre-move settings lifter with the defaults package, so the
// inbound ADD path (defaults.NormalizeInboundSettings) lifts a legacy body BEFORE
// FillSettingsDefaults stamps fresh-inbound values over it. No-op when mtproto is
// not linked into the binary at all.
func init() {
	defaults.MtprotoSettingsLifter = LiftMtprotoSettingsBlob
}

// MtprotoInboundPolicy is the inbound-level half of an MTProto inbound's settings:
// everything telemt applies process-wide (see mtprotoSettings). Exported because the
// subscription service builds tg:// links off exactly this set and must resolve it the
// same way, legacy shape included, or a subscriber gets links for transports the proxy
// refuses.
type MtprotoInboundPolicy struct {
	ModeClassic bool
	ModeSecure  bool
	ModeTls     bool
	TlsDomain   string
	// UserLimit keeps the RAW reading: nil=absent(=>1 device); 0=no limit; else 1..64.
	// Resolve it through effectiveUserLimit, never by dereferencing.
	UserLimit *int
	// ExternalProxy is the inbound's default link endpoints. An account carrying its
	// own list overrides this one outright rather than adding to it: the two are
	// alternative answers to "where do this account's links point", and merging them
	// would hand a subscriber endpoints the operator meant to replace.
	ExternalProxy []MtprotoEndpoint
}

// MtprotoEndpoint is one alternate host:port a tg:// link can advertise.
type MtprotoEndpoint struct {
	Dest   string `json:"dest"`
	Port   int    `json:"port"`
	Remark string `json:"remark"`
}

// ModeEnabled reports whether this inbound accepts one of telemt's mode names.
func (p MtprotoInboundPolicy) ModeEnabled(mode string) bool {
	switch mode {
	case "classic":
		return p.ModeClassic
	case "secure":
		return p.ModeSecure
	case "tls":
		return p.ModeTls
	}
	return false
}

// mtprotoLegacyClient is the PRE-MOVE per-client shape, alive as a read format only.
//
// adtagEnable/adtag are deliberately not here. The ad tag never moved: it is still a
// live per-client field on mtprotoClient, so there is nothing about it to resolve and
// nothing to mirror.
type mtprotoLegacyClient struct {
	ModeClassic bool   `json:"modeClassic"`
	ModeSecure  bool   `json:"modeSecure"`
	ModeTls     bool   `json:"modeTls"`
	TlsDomain   string `json:"tlsDomain"`
	UserLimit   *int   `json:"userLimit"`
}

// MtprotoInboundPolicyOf resolves an MTProto inbound's policy straight from its stored
// settings JSON, in either shape. The entry point for readers outside this package;
// inside it, parseSettings already returns a resolved mtprotoSettings.
//
// Unparseable settings resolve to the zero policy (no mode accepted), which is what
// every caller already did with a decode error: offer nothing rather than guess.
func MtprotoInboundPolicyOf(settings string) MtprotoInboundPolicy {
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(settings), &root); err != nil || root == nil {
		return MtprotoInboundPolicy{}
	}
	policy, _ := resolveMtprotoPolicy(root)
	return policy
}

// LiftMtprotoSettingsBlob rewrites a settings blob in the pre-move shape into the
// current one, with no database involved. The ADD path's entry point, registered as
// defaults.MtprotoSettingsLifter so NormalizeInboundSettings calls it ahead of
// FillSettingsDefaults.
//
// Order there is the whole reason this exists. An API body in the old shape carries its
// policy on the CLIENTS and names none of the inbound-level keys, so filling defaults
// first would stamp the fresh-inbound values (all three modes on, no device cap) over
// it. The blob would then look already-migrated to every later reader, the startup lift
// would skip it forever, and the caller's narrower set would be gone with nothing left
// to recover it from.
//
// Returns the input untouched when it is not MTProto, is not a JSON object, or is
// already in the current shape.
func LiftMtprotoSettingsBlob(protocol model.Protocol, settings string) string {
	// Both mtproto planes share the telemt settings shape, so the legacy-shape
	// lift applies to each. (The plain mtproto string is the 3x-ui mtg sidecar
	// plane; its rows simply never carry the pre-move client-level shape, and
	// running the lift over them is a no-op.)
	if protocol != defaults.ProtoMTProto && protocol != defaults.ProtoMTProtoC {
		return settings
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(settings), &raw); err != nil || raw == nil {
		return settings
	}
	policy, legacy := resolveMtprotoPolicy(raw)
	if !legacy {
		return settings
	}
	for key, value := range map[string]any{
		"modeClassic": policy.ModeClassic,
		"modeSecure":  policy.ModeSecure,
		"modeTls":     policy.ModeTls,
		"tlsDomain":   policy.TlsDomain,
		"userLimit":   *policy.UserLimit, // deriveMtprotoPolicy never leaves this nil
	} {
		bs, err := json.Marshal(value)
		if err != nil {
			return settings
		}
		raw[key] = bs
	}
	out, err := json.Marshal(raw)
	if err != nil {
		return settings
	}
	return string(out)
}

// resolveMtprotoPolicy answers what a settings blob MEANS, whichever shape it is in,
// and reports whether it had to fall back to the legacy one.
//
// The shape test is key PRESENCE at the settings root, never a value. A blob carrying
// none of modeClassic/modeSecure/modeTls predates the move: defaults seeds all three
// onto every inbound created since, and the lift stamps all three onto every one that
// existed before, so their joint absence is unambiguous. Anything else is read straight
// off the root, an explicit false included: that is an operator turning a mode off, not
// an absence to be guessed at.
//
// The legacy derivation is the MIGRATION'S, exactly, and sharing one function is the
// point: the value a pre-lift read resolves to and the value the lift will eventually
// store are the same one, so nothing an operator can observe changes when the lift
// lands. A fallback to the fresh-inbound defaults instead would have silently widened
// every legacy inbound to all three modes and no device cap for as long as the lift had
// not run, and permanently for any path that writes back what it read (the panel's own
// inbound form does exactly that).
func resolveMtprotoPolicy(root map[string]json.RawMessage) (MtprotoInboundPolicy, bool) {
	_, hasClassic := root["modeClassic"]
	_, hasSecure := root["modeSecure"]
	_, hasTls := root["modeTls"]
	if !hasClassic && !hasSecure && !hasTls {
		var clients []mtprotoLegacyClient
		if blob, ok := root["clients"]; ok {
			// A clients value that is not an array is somebody else's problem
			// (checkClients refuses it on save); derive from nothing and move on.
			_ = json.Unmarshal(blob, &clients)
		}
		return deriveMtprotoPolicy(clients), true
	}

	var policy MtprotoInboundPolicy
	get := func(key string, into any) {
		if bs, ok := root[key]; ok {
			// A value of the wrong type leaves the field at its zero value rather than
			// failing the whole inbound: one bad key must not take the other four down.
			_ = json.Unmarshal(bs, into)
		}
	}
	get("modeClassic", &policy.ModeClassic)
	get("modeSecure", &policy.ModeSecure)
	get("modeTls", &policy.ModeTls)
	get("tlsDomain", &policy.TlsDomain)
	get("userLimit", &policy.UserLimit)
	get("externalProxy", &policy.ExternalProxy)
	return policy, false
}

// deriveMtprotoPolicy seeds the inbound-level policy from a pre-move blob's accounts.
// The one place the seeding rules live; the lift, the read-side fallback and (mirrored
// by hand) the panel's own form all resolve through them.
//
//   - Modes: the UNION over the accounts, which is what the LISTENER already accepted.
//     Some accounts gain a mode they did not individually hold; that granularity is
//     what is being removed, on purpose.
//   - TlsDomain: the first FakeTLS account's domain, which is the one telemt already
//     modelled its fake certificate on for the whole process.
//   - UserLimit: the MAX across accounts, and THIS ONE CHANGES BEHAVIOUR. Two accounts
//     on one inbound really could hold different device caps, each enforced separately
//     in [access.user_max_unique_ips], and afterwards they cannot. Max is chosen
//     because it is the most permissive: nobody is locked out by the upgrade, at worst
//     an account that was capped tighter than its neighbour gains headroom.
func deriveMtprotoPolicy(clients []mtprotoLegacyClient) MtprotoInboundPolicy {
	var policy MtprotoInboundPolicy
	capEff := -1
	for _, c := range clients {
		policy.ModeClassic = policy.ModeClassic || c.ModeClassic
		policy.ModeSecure = policy.ModeSecure || c.ModeSecure
		policy.ModeTls = policy.ModeTls || c.ModeTls
		if policy.TlsDomain == "" && c.ModeTls && strings.TrimSpace(c.TlsDomain) != "" {
			policy.TlsDomain = strings.TrimSpace(c.TlsDomain)
		}
		// Compare on the EFFECTIVE cap, not the raw number: an ABSENT value means one
		// device while an explicit 0 means no limit, which is 16 here (noLimitDevices),
		// so the raw numbers are not on one scale. Storing the raw value of the winner
		// keeps the distinction intact.
		if eff := vpnrange.EffectiveUserLimit(c.UserLimit); eff > capEff {
			capEff, policy.UserLimit = eff, c.UserLimit
		}
	}
	if !policy.ModeClassic && !policy.ModeSecure && !policy.ModeTls {
		// No account held a usable mode (or there are no accounts at all), so there is
		// nothing to preserve: fall back to the same all-on default a freshly created
		// inbound gets rather than resolve to a config that grants everything (telemt
		// reads an EMPTY per-account mode entry as "no restriction").
		policy.ModeClassic, policy.ModeSecure, policy.ModeTls = true, true, true
	}
	if policy.UserLimit == nil {
		// Either there were no accounts, or every one of them predates the field. An
		// absent per-client value resolved to 1 device (effectiveUserLimit), so an
		// explicit 1 keeps the cap exactly where it was; only a truly empty inbound gets
		// the fresh-inbound default of 10 devices.
		legacy := 1
		if len(clients) == 0 {
			legacy = 10
		}
		policy.UserLimit = &legacy
	}
	if policy.TlsDomain == "" {
		policy.TlsDomain = "www.google.com"
	}
	return policy
}
