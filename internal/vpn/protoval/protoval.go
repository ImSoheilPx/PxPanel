// Package protoval is the per-protocol settings-validator framework and the
// validators for the protocols whose settings shape this wave owns (L2TP,
// PPTP), ported from vpn-ui web/service/protocolvalidate.go.
//
// WHY A SEPARATE PACKAGE: vpn-ui kept everything in its one giant service
// package. The framework needs vpnrange's ParseRange (the ipRanges grammar) and
// the range package imports defaults (for the Proto* identities), so the
// framework can live in NEITHER defaults (cycle) NOR the protocol packages
// (they would all re-import each other's helpers). protoval sits beside them:
// model + common + range in, nothing internal out.
//
// Two rules decide what is checked here, and nothing else is:
//
//  1. Anything the protocol's OWN Go struct cannot unmarshal. l2tpSettings.Mtu is an
//     int, so a `"mtu": ""` (which is what Vue's v-model.number leaves behind when the
//     operator clears the box) makes the whole json.Unmarshal fail inside the daemon
//     config writer. Nothing surfaces that: the inbound saves, the daemon comes up on
//     zero values or not at all, and the panel shows a healthy row.
//
//  2. Values that parse but cannot work: a port outside 1-65535, an ipRanges entry that
//     is not a CIDR, an enum the protocol will silently fall back from. The strategy
//     resolvers absorb an unknown value rather than complain (normUserLimitStrategy
//     turns anything that is not "reject" into "accept"), so a typo like "Accept" or
//     "evict" is accepted and then discarded, which is precisely the class of mistake
//     an API caller writing the blob by hand makes.
//
// Everything else is left alone. A check that rejects a blob the panel's own form can
// produce is a regression, not a safety net: this runs on the UI's requests too.
//
// WIRE-UP (controllers/inbound wave): defaults.ValidateSettings (the hook
// NormalizeInboundSettings calls) is assigned ONCE at boot:
//
//	defaults.ValidateSettings = protoval.Validate
//
// until then registration is inert and every protocol validates clean, exactly
// like vpn-ui where the table was compiled into the same package.
//
// TODO(protocol waves): openvpn, openconnect, sstp, ikev2, wgc, awg, gre,
// mtproto, ssh, anytls, tuic, naive port their validator from vpn-ui
// protocolvalidate.go on top of the exported checks here and register it in
// init() — the table below is the landed slice of vpn-ui's.
package protoval

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/util/common"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
	vpnrange "github.com/ImSoheilPx/pxpanel/internal/vpn/range"
)

// maxUserLimit is the device-cap ceiling (vpn-ui web/service/vpnrange.go —
// restated because the range package keeps its twin unexported).
const maxUserLimit = 64

// settingsValidator validates one protocol's settings JSON (already filled with
// defaults by defaults.FillSettingsDefaults).
type settingsValidator = func(m map[string]any) error

var validators = map[model.Protocol]settingsValidator{}

func init() {
	// The landed slice of vpn-ui protocolvalidate.go's validator table.
	validators[defaults.ProtoL2TP] = validateL2tpSettings
	validators[defaults.ProtoPPTP] = validatePptpSettings
}

// RegisterSettingsValidator attaches one protocol's validator. Call from the
// protocol package's init(); a protocol without an entry is unmistakably "not
// validated here" rather than "fell through a switch".
func RegisterSettingsValidator(protocol model.Protocol, validate settingsValidator) {
	validators[protocol] = validate
}

// Validate is the dispatcher the inbound-save path reaches through
// defaults.ValidateSettings. A protocol without an entry validates clean: the
// core owns those blobs and rejects what it cannot use itself.
func Validate(protocol model.Protocol, settings string) error {
	validate := validators[protocol]
	if validate == nil {
		return nil
	}
	root, err := SettingsObject(settings)
	if err != nil {
		return err
	}
	if err := CheckClients(root); err != nil {
		return err
	}
	return validate(root)
}

// --- per-protocol validators --------------------------------------------------------

func validateL2tpSettings(m map[string]any) error {
	if err := CheckAddressedVpnCommon(m); err != nil {
		return err
	}
	for _, key := range []string{"ipsecEnable", "allowRaw", "clientToClient", "crossInbound"} {
		if _, _, err := OptBool(m, key); err != nil {
			return err
		}
	}
	// A shared secret is the whole of L2TP/IPsec's authentication of the tunnel. With
	// the mode on and the secret empty, libreswan gets a conn with no PSK and every
	// client fails at phase 1 with an error the panel never sees.
	ipsec, _, err := OptBool(m, "ipsecEnable")
	if err != nil {
		return err
	}
	psk, _, err := OptString(m, "ipsecPsk")
	if err != nil {
		return err
	}
	if ipsec && strings.TrimSpace(psk) == "" {
		return common.NewError(`"ipsecPsk" is required when "ipsecEnable" is true`)
	}
	return CheckExternalProxy(m)
}

func validatePptpSettings(m map[string]any) error {
	if err := CheckAddressedVpnCommon(m); err != nil {
		return err
	}
	for _, key := range []string{"clientToClient", "crossInbound"} {
		if _, _, err := OptBool(m, key); err != nil {
			return err
		}
	}
	return CheckExternalProxy(m)
}

// --- shared checks -----------------------------------------------------------------

// CheckAddressedVpnCommon validates the block every protocol that hands out a tunnel
// address shares: the two resolvers, the MTU, the address pool and the device cap.
func CheckAddressedVpnCommon(m map[string]any) error {
	if err := CheckDNS(m, "dns1"); err != nil {
		return err
	}
	if err := CheckDNS(m, "dns2"); err != nil {
		return err
	}
	if err := CheckMTU(m); err != nil {
		return err
	}
	if err := CheckIPRanges(m); err != nil {
		return err
	}
	if err := CheckUserLimit(m); err != nil {
		return err
	}
	return CheckUserLimitStrategy(m)
}

// CheckTlsCertFields type-checks the Xray-style cert pair shared by ocserv, sstp and
// ikev2. Whether a cert is REQUIRED is the save path's call (it differs per
// protocol and per auth mode); this only refuses a value of the wrong type, which would
// otherwise break the daemon's own unmarshal of the same blob.
func CheckTlsCertFields(m map[string]any) error {
	for _, key := range []string{"certificateFile", "keyFile", "certificate", "key", "caCert"} {
		if _, _, err := OptString(m, key); err != nil {
			return err
		}
	}
	return nil
}

// CheckDNS accepts an empty value (the daemon falls back to its own default) and any
// literal IP. A hostname is refused: these are written verbatim into a PPP/WireGuard
// client config as a nameserver address, where a name has nothing to resolve it.
func CheckDNS(m map[string]any, key string) error {
	v, present, err := OptString(m, key)
	if err != nil {
		return err
	}
	v = strings.TrimSpace(v)
	if !present || v == "" {
		return nil
	}
	if _, err := netip.ParseAddr(v); err != nil {
		return common.NewErrorf("%q must be an IP address (got %q)", key, v)
	}
	return nil
}

// CheckMTU allows 0, which every protocol here reads as "leave it to the daemon or the
// kernel" (see awgSettings.mtu, greSettings). Past that the floor is IPv4's minimum
// reassembly buffer and the ceiling is a jumbo frame.
func CheckMTU(m map[string]any) error {
	mtu, present, err := OptInt(m, "mtu")
	if err != nil {
		return err
	}
	if !present || mtu == 0 {
		return nil
	}
	if mtu < 576 || mtu > 9216 {
		return common.NewErrorf(`"mtu" must be 0 (protocol default) or 576-9216 (got %d)`, mtu)
	}
	return nil
}

// CheckIPRanges refuses an address pool entry the allocator cannot read. These are NOT
// CIDRs: the format is the inclusive "A.B.C.s-A.B.C.e" host range (with an "A.B.C.s-e"
// last-octet shorthand) that the range package's ParseRange accepts, both ends inside
// one /24 and non-decreasing. ParseRange silently DROPS anything else, so a caller who
// writes the pool as "10.4.0.0/24" gets an inbound with no addresses and no complaint.
func CheckIPRanges(m map[string]any) error {
	ranges, present, err := OptStrings(m, "ipRanges")
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		// An empty row is what the form leaves behind between edits and the JS filters
		// it out on save, so it means "unset", not "broken".
		if r == "" {
			continue
		}
		if _, _, ok := vpnrange.ParseRange(r); !ok {
			return common.NewErrorf(`"ipRanges" entry %q is not an address range (want e.g. "10.1.0.2-10.1.0.254", both ends in one /24)`, r)
		}
	}
	return nil
}

// CheckUserLimit bounds the per-account device cap. 0 is legal and means "no limit"
// (which the allocator sizes as noLimitDevices), so only a negative or an over-cap
// value is wrong. normUserLimit would clamp both silently.
func CheckUserLimit(m map[string]any) error {
	k, present, err := OptInt(m, "userLimit")
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

// CheckUserLimitStrategy mirrors the IPLimitStrategy guard in the inbound save path:
// normUserLimitStrategy absorbs anything that is not "reject" as "accept", so a typo is
// accepted at save time and then quietly discarded.
func CheckUserLimitStrategy(m map[string]any) error {
	return CheckEnum(m, "userLimitStrategy", "accept", "reject")
}

// CheckClients refuses a clients value that is not an array. GetClients unmarshals the
// whole settings object into map[string][]model.Client and IGNORES the error, so an
// object here yields no clients and no complaint: an inbound that listens and can
// authenticate nobody.
func CheckClients(m map[string]any) error {
	v, ok := m["clients"]
	if !ok || v == nil {
		return nil
	}
	if _, ok := v.([]any); !ok {
		return common.NewError(`"clients" must be an array`)
	}
	return nil
}

// CheckExternalProxy validates the advertised-endpoint override list. It never reaches
// a daemon (it only rewrites the address in generated links and configs), so the bar is
// only that each entry is an object whose port is a port.
func CheckExternalProxy(m map[string]any) error {
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
		if _, _, err := OptString(entry, "dest"); err != nil {
			return common.NewErrorf(`"externalProxy" entry %d: %v`, i, err)
		}
		port, present, err := OptInt(entry, "port")
		if err != nil {
			return common.NewErrorf(`"externalProxy" entry %d: %v`, i, err)
		}
		if present && (port < 0 || port > 65535) {
			return common.NewErrorf(`"externalProxy" entry %d has port %d outside 1-65535`, i, port)
		}
	}
	return nil
}

// CheckOptionalPort bounds a port field that may legitimately be 0 (unset, because the
// feature owning it is off). Whether it is REQUIRED is the caller's rule.
func CheckOptionalPort(m map[string]any, key string) error {
	port, present, err := OptInt(m, key)
	if err != nil {
		return err
	}
	if !present || port == 0 {
		return nil
	}
	if port < 1 || port > 65535 {
		return common.NewErrorf("%q must be 1-65535 (got %d)", key, port)
	}
	return nil
}

// CheckEnum accepts an absent or empty value (every one of these fields has a
// server-side default for exactly that case) and rejects anything outside the set.
func CheckEnum(m map[string]any, key string, allowed ...string) error {
	v, present, err := OptString(m, key)
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
//
// All four report "present" separately from the value, because an ABSENT field and a
// zero one are different answers everywhere in this package (a nil *int userLimit is a
// legacy single-device inbound, an explicit 0 is no limit).

// SettingsObject decodes a settings blob for reading. Values keep JSON's own types, so
// numbers arrive as float64 and OptInt below is what turns them back into integers.
func SettingsObject(settings string) (map[string]any, error) {
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

func OptString(m map[string]any, key string) (string, bool, error) {
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

// OptInt refuses a numeric-looking STRING as hard as it refuses a word. The protocols'
// own settings structs type these as int, so `"mtu": "1400"` fails their json.Unmarshal
// just as `"mtu": ""` does, and the daemon config writer that hits it has nowhere to
// report from. Vue's v-model.number leaves the raw string behind whenever the box is
// cleared or holds something unparseable, so this is a real shape, not a hypothetical.
func OptInt(m map[string]any, key string) (int, bool, error) {
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

func OptBool(m map[string]any, key string) (bool, bool, error) {
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

func OptStrings(m map[string]any, key string) ([]string, bool, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return nil, false, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, false, common.NewErrorf("%q must be an array of strings", key)
	}
	out := make([]string, 0, len(list))
	for i, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, false, common.NewErrorf("%q entry %d must be a string", key, i)
		}
		out = append(out, s)
	}
	return out, true, nil
}
