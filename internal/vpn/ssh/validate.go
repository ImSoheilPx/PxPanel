// Per-protocol validation of an SSH inbound's settings JSON — the ssh slice of
// vpn-ui web/service/protocolvalidate.go (validateSshSettings, WAVE-2 P5), with
// the shared checkers it reaches carried verbatim so this wave is self-contained.
// (mtproto's validate.go carries the same helpers for the same reason; the
// convergence point is the dispatcher below.)
//
// TODO(protocolvalidate/controllers wave): the full validator table (vpn-ui
// protocolSettingValidators) lands as one dispatcher over defaults.ValidateSettings;
// fold these helpers back into it and register ssh.ValidateSettings there.
package ssh

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/util/common"
)

// maxUserLimit is the panel-wide device-cap bound (vpn-ui vpnrange.go; the range
// package keeps its own copy unexported for the block math).
const maxUserLimit = 64

// ValidateSettings checks one SSH inbound's settings JSON against its shape.
// The name mirrors the per-protocol validators the controllers wave will dispatch
// through defaults.ValidateSettings (vpn-ui: ValidateProtocolSettings(model.SSH, …)).
func ValidateSettings(settings string) error {
	root, err := settingsObject(settings)
	if err != nil {
		return err
	}
	if err := checkClients(root); err != nil {
		return err
	}
	return validateSshSettings(root)
}

// validateSshSettings is vpn-ui protocolvalidate.go's ssh entry.
func validateSshSettings(m map[string]any) error {
	if err := checkUserLimit(m); err != nil {
		return err
	}
	if err := checkUserLimitStrategy(m); err != nil {
		return err
	}
	if _, _, err := optString(m, "hostKey"); err != nil {
		return err
	}
	return checkExternalProxy(m)
}

// checkUserLimitStrategy mirrors the IPLimitStrategy guard in validateInboundConfig:
// NormUserLimitStrategy absorbs anything that is not "reject" as "accept", so a typo is
// accepted at save time and then quietly discarded.
func checkUserLimitStrategy(m map[string]any) error {
	return checkEnum(m, "userLimitStrategy", "accept", "reject")
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

// checkEnum accepts an absent or empty value (every one of these fields has a
// server-side default for exactly that case) and rejects anything outside the set.
func checkEnum(m map[string]any, key string, allowed ...string) error {
	v, present, err := optString(m, key)
	if err != nil {
		return err
	}
	v = strings.TrimSpace(v)
	if !present || v == "" {
		return nil
	}
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return common.NewErrorf("%q must be one of %s (got %q)", key, quotedList(allowed), v)
}

func quotedList(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, fmt.Sprintf("%q", v))
	}
	return strings.Join(quoted, ", ")
}

// --- typed accessors ---------------------------------------------------------------

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

// optInt refuses a numeric-looking STRING as hard as it refuses a word (Vue's
// v-model.number leaves the raw string behind when a box is cleared).
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
