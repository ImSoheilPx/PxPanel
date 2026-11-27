// Per-protocol validation of an MTProto inbound's settings JSON — the mtproto
// slice of vpn-ui web/service/protocolvalidate.go (WAVE-2 P5), with the shared
// checkers it reaches (settingsObject / optString / optBool / optInt /
// checkClients / checkExternalProxy / checkUserLimit) carried along
// verbatim so this wave is self-contained.
//
// TODO(protocolvalidate/controllers wave): the full validator table (vpn-ui
// protocolSettingValidators, ~760 LOC across all protocols) lands as one
// dispatcher; fold these helpers back into it and register mtproto.ValidateSettings
// there (the same way defaults.MtprotoSettingsLifter is wired today).
//
// Two rules decide what is checked here, and nothing else is:
//
//  1. Anything the protocol's OWN Go struct cannot unmarshal. A `"userLimit": ""`
//     (which is what Vue's v-model.number leaves behind when the operator clears
//     the box) makes the whole json.Unmarshal fail inside the daemon config writer.
//     Nothing surfaces that: the inbound saves, the daemon comes up on zero values
//     or not at all, and the panel shows a healthy row.
//
//  2. Values that parse but cannot work: a userLimit outside 0..64, an externalProxy
//     entry whose port is not a port, a mode list telemt would silently misread.
//
// Everything else is left alone. A check that rejects a blob the panel's own form can
// produce is a regression, not a safety net: this runs on the UI's requests too.
package mtproto

import (
	"encoding/json"
	"math"
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/util/common"
)

// maxUserLimit is the panel-wide device-cap bound (vpn-ui vpnrange.go; the range
// package keeps its own copy unexported for the block math).
const maxUserLimit = 64

// ValidateSettings checks one MTProto inbound's settings JSON against its shape.
// The name mirrors the per-protocol validators the controllers wave will dispatch
// through defaults.ValidateSettings (vpn-ui: ValidateProtocolSettings(model.MTPROTO, …)).
func ValidateSettings(settings string) error {
	root, err := settingsObject(settings)
	if err != nil {
		return err
	}
	if err := checkClients(root); err != nil {
		return err
	}
	return validateMtprotoSettings(root)
}

// validateMtprotoSettings is vpn-ui protocolvalidate.go's mtproto entry.
func validateMtprotoSettings(m map[string]any) error {
	if _, _, err := optString(m, "tlsDomain"); err != nil {
		return err
	}
	// The device cap is per-ACCOUNT even though it lives on the inbound, the same
	// reading l2tp/wgc/gre/openconnect use: telemt counts distinct source IPs per
	// account against it.
	if err := checkUserLimit(m); err != nil {
		return err
	}
	// The inbound-wide link endpoints. Same shape and same checks as everywhere else;
	// an account's own list overrides it at link-generation time.
	if err := checkExternalProxy(m); err != nil {
		return err
	}
	return checkMtprotoModes(m)
}

// checkMtprotoModes refuses an inbound with every connection mode off.
//
// It is not merely useless: telemt's per-user mode map (our patch) reads an EMPTY
// entry as "no restriction", so a modeless inbound would hand every account every
// mode instead of none. The daemon refuses to start on one for that reason
// (MtprotoService.startable), and this is what keeps the state from being saved at all.
//
// An inbound with all three keys ABSENT is not judged: that is a body in the pre-move
// shape, whose modes are on its clients, and NormalizeInboundSettings resolves those
// onto the inbound (then fills whatever is still missing) before this ever runs on the
// add path, so what gets validated is the blob that will actually be stored. Judging
// their absence here would refuse a body that still works today, and the resolution
// itself can never produce a modeless inbound.
func checkMtprotoModes(m map[string]any) error {
	anyPresent, anyOn := false, false
	for _, key := range []string{"modeClassic", "modeSecure", "modeTls"} {
		on, present, err := optBool(m, key)
		if err != nil {
			return err
		}
		anyPresent = anyPresent || present
		anyOn = anyOn || (present && on)
	}
	if anyPresent && !anyOn {
		return common.NewError(`at least one connection mode ("modeClassic", "modeSecure" or "modeTls") must be enabled: an MTProto inbound with none has no usable link`)
	}
	return nil
}

// checkClients refuses a clients value that is not an array. GetClients unmarshals the
// whole settings object into map[string][]model.Client and IGNORES the error, so an
// object here yields no clients and no complaint: an inbound that listens and can
// authenticate nobody.
func checkClients(m map[string]any) error {
	v, ok := m["clients"]
	if !ok || v == nil {
		return nil
	}
	if _, ok := v.([]any); !ok {
		return common.NewError(`"clients" must be an array`)
	}
	return nil
}

// checkExternalProxy validates the advertised-endpoint override list. It never reaches
// a daemon (it only rewrites the address in generated links and configs), so the bar is
// only that each entry is an object whose port is a port.
func checkExternalProxy(m map[string]any) error {
	v, ok := m["externalProxy"]
	if !ok || v == nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return common.NewError(`"externalProxy" must be an array`)
	}
	for i, item := range list {
		entry, ok := item.(map[string]any)
		if !ok {
			return common.NewErrorf(`"externalProxy" entry %d must be an object with "dest" and "port"`, i)
		}
		if _, _, err := optString(entry, "dest"); err != nil {
			return common.NewErrorf(`"externalProxy" entry %d: %v`, i, err)
		}
		port, present, err := optInt(entry, "port")
		if err != nil {
			return common.NewErrorf(`"externalProxy" entry %d: %v`, i, err)
		}
		if present && (port < 0 || port > 65535) {
			return common.NewErrorf(`"externalProxy" entry %d has port %d outside 1-65535`, i, port)
		}
	}
	return nil
}

// checkUserLimit bounds the device cap: 0 (no limit) or 1..maxUserLimit.
func checkUserLimit(m map[string]any) error {
	k, present, err := optInt(m, "userLimit")
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	if k < 0 || k > maxUserLimit {
		return common.NewErrorf(`"userLimit" must be 0 (no limit) or 1-%d (got %d)`, maxUserLimit, k)
	}
	return nil
}

// --- typed accessors ---------------------------------------------------------------
//
// All three report "present" separately from the value, because an ABSENT field and a
// zero one are different answers everywhere in this package (a nil *int userLimit is a
// legacy single-device inbound, an explicit 0 is no limit).

// settingsObject decodes a settings blob for reading. Values keep JSON's own types, so
// numbers arrive as float64 and optInt below is what turns them back into integers.
func settingsObject(settings string) (map[string]any, error) {
	trimmed := strings.TrimSpace(settings)
	if trimmed == "" || trimmed == "null" {
		return map[string]any{}, nil
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(trimmed), &root); err != nil {
		return nil, common.NewErrorf("inbound settings must be a JSON object: %v", err)
	}
	if root == nil {
		return map[string]any{}, nil
	}
	return root, nil
}

func optString(m map[string]any, key string) (string, bool, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return "", false, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", false, common.NewErrorf("%q must be a string", key)
	}
	return s, true, nil
}

// optInt refuses a numeric-looking STRING as hard as it refuses a word. The protocols'
// own settings structs type these as int, so `"userLimit": "3"` fails their
// json.Unmarshal just as `"userLimit": ""` does, and the daemon config writer that hits
// it has nowhere to report from. Vue's v-model.number leaves the raw string behind
// whenever the box is cleared or holds something unparseable, so this is a real shape,
// not a hypothetical.
func optInt(m map[string]any, key string) (int, bool, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return 0, false, nil
	}
	f, ok := v.(float64)
	if !ok {
		return 0, false, common.NewErrorf("%q must be a number", key)
	}
	if f != math.Trunc(f) {
		return 0, false, common.NewErrorf("%q must be a whole number (got %v)", key, f)
	}
	return int(f), true, nil
}

func optBool(m map[string]any, key string) (bool, bool, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return false, false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, false, common.NewErrorf("%q must be true or false", key)
	}
	return b, true, nil
}
