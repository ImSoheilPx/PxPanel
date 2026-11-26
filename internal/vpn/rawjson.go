// Raw settings-JSON helpers shared by the daemon-less protocol services
// (vpn-ui: wgc.go/awg.go/gre.go package-level helpers jsonString/jsonBool/
// setRawString/setRawInt/userLimitPtrFromRaw).
//
// The wg family reconciles key material and GRE reconciles peer slots by
// operating on the RAW settings map rather than a typed struct, so unknown UI
// fields survive every write. The helpers were package-level in vpn-ui's single
// web/service package; here the protocols live in separate packages, so the
// shared ones live on the root (leaf-only, like infra_ports.go).
package vpn

import (
	"encoding/json"
)

// JsonString decodes a JSON string value, returning "" on any error.
// (vpn-ui wgc.go:jsonString.)
func JsonString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// JsonBool decodes a JSON bool value, returning false on any error.
// (vpn-ui wgc.go:jsonBool.)
func JsonBool(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var b bool
	if json.Unmarshal(raw, &b) != nil {
		return false
	}
	return b
}

// SetRawString stores s as a JSON string value under key.
// (vpn-ui wgc.go:setRawString.)
func SetRawString(raw map[string]json.RawMessage, key, s string) {
	b, _ := json.Marshal(s)
	raw[key] = b
}

// SetRawInt stores n as a JSON number under key.
// (vpn-ui awg.go:setRawInt.)
func SetRawInt(raw map[string]json.RawMessage, key string, n int) {
	b, _ := json.Marshal(n)
	raw[key] = b
}

// UserLimitPtrFromRaw reads the raw-JSON userLimit as the *int the range
// package's WgcEffectiveK expects, so an ABSENT field (legacy => 1 device)
// stays distinguishable from an explicit 0 (=> the max).
// (vpn-ui awg.go:userLimitPtrFromRaw.)
func UserLimitPtrFromRaw(raw map[string]json.RawMessage) *int {
	b, ok := raw["userLimit"]
	if !ok {
		return nil
	}
	var k int
	if json.Unmarshal(b, &k) != nil {
		return nil
	}
	return &k
}
