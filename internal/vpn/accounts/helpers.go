// Helper functions the accounts layer shares with the protocol waves: settings
// clients parsing, identity keys, credential mapping and the shadowsocks PSK
// rules. Ported from vpn-ui web/service/migrationaccounts.go (the non-migration
// helpers), inbound.go (clientIdentityKey) and accountproject.go (shadowsocks).
package accounts

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/google/uuid"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
)

// parseSettingsClients pulls the clients array out of an inbound's settings.
// Returns ok=false for settings that cannot be parsed, which the caller must
// treat as "skip this inbound", never as "this inbound has no clients".
func parseSettingsClients(settings string) ([]map[string]any, bool) {
	var root map[string]any
	if err := json.Unmarshal([]byte(settings), &root); err != nil || root == nil {
		return nil, false
	}
	list, ok := root["clients"].([]any)
	if !ok {
		// A protocol whose settings legitimately carry no clients array.
		return nil, true
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, entry)
	}
	return out, true
}

// entrySlotOr mirrors vpnrange's slotOr for a raw settings entry.
func entrySlotOr(entry map[string]any, listIndex int) int {
	if v, has := entry["slot"]; has {
		if f, ok := v.(float64); ok && f >= 0 {
			return int(f)
		}
	}
	return listIndex
}

// clientIdentityKey is THE answer to "what field does protocol P address a
// client entry by". It was duplicated six ways across the vpn-ui write paths
// and twice more in the browser, and the copies drifted apart. One function,
// and every id-keyed path goes through it.
func clientIdentityKey(protocol model.Protocol) string {
	switch protocol {
	// Username+password VPN protocols. The password is the identity rather than the
	// username because the username is the field operators actually rename, and a key
	// that moves mid-edit cannot be matched against the one the modal opened with.
	case model.Trojan, defaults.ProtoL2TP, defaults.ProtoPPTP, defaults.ProtoOpenVPN,
		defaults.ProtoOpenConnect, defaults.ProtoSSTP, defaults.ProtoIKEv2:
		return "password"
	// Password-credential native Xray protocols. anytls authenticates on the password
	// alone. naive carries its own OPTIONAL Basic-auth username, which must not be the
	// identity: keying on it would make every account created before the field existed
	// unaddressable, and it is exactly the field an operator renames.
	case defaults.ProtoAnyTLS, defaults.ProtoNaive:
		return "password"
	case model.Shadowsocks:
		return "email"
	case model.Hysteria, defaults.ProtoHysteria2:
		return "auth"
	default:
		// vmess/vless (uuid) and the email-identity protocols (wg-c, awg, mtproto,
		// ssh), whose settings JSON carries id=email. tuic also lands here: it
		// carries BOTH a uuid and a password, and the uuid is the identity.
		return "id"
	}
}

// ClientIdentityKey is the exported form, for the write paths and the sub engine.
func ClientIdentityKey(protocol model.Protocol) string { return clientIdentityKey(protocol) }

// newAccountFromEntry builds the account row from the first client entry that
// claims an email.
func newAccountFromEntry(entry map[string]any) *model.Account {
	str := func(k string) string { v, _ := entry[k].(string); return v }
	num := func(k string) int64 {
		if f, ok := entry[k].(float64); ok {
			return int64(f)
		}
		return 0
	}
	boolean := func(k string) bool { v, _ := entry[k].(bool); return v }
	// The nullable ones cannot use num: it answers 0 for an absent key, and 0 is a real
	// value here (unlimited for a rate) that must stay distinguishable from "inherit".
	// An absent key, an explicit null and a non-number all read as nil, which is the
	// value that means inherit.
	nullableInt := func(k string) *int {
		f, ok := entry[k].(float64)
		if !ok {
			return nil
		}
		v := int(f)
		return &v
	}

	return &model.Account{
		Email:             str("email"),
		SubID:             str("subId"),
		TotalGB:           num("totalGB"),
		ExpiryTime:        num("expiryTime"),
		Enable:            boolean("enable"),
		Reset:             int(num("reset")),
		LimitIP:           int(num("limitIp")),
		TgID:              num("tgId"),
		Comment:           str("comment"),
		SpeedLimitDown:    nullableInt("speedLimitDown"),
		SpeedLimitUp:      nullableInt("speedLimitUp"),
		UserLimitOverride: nullableInt("userLimitOverride"),
	}
}

// extractAccountCredential is the inverse of applyAccountCredential: it lifts the
// credential fields a protocol keys on out of an entry and onto the account,
// FIRST-VALUE-WINS. Ported from vpn-ui migrationaccounts.go with the migration
// report stripped: on the live sync path there is nobody to report to, and the
// entry just written IS the newer truth, so the remaining behaviour is "fill
// empty fields, keep filled ones".
//
// TODO(accounts wave): port the full AccountsMigrationReport/conflict-pair
// machinery alongside the MigrationAccounts backfill if this repo adopts the
// vpn-ui import path.
func extractAccountCredential(account *model.Account, entry map[string]any, protocol model.Protocol) bool {
	str := func(k string) string { v, _ := entry[k].(string); return v }
	changed := false

	set := func(dst *string, value string) {
		if value == "" {
			return
		}
		if *dst == "" {
			*dst = value
			changed = true
		}
	}

	switch protocol {
	case model.VMESS:
		set(&account.UUID, str("id"))
		set(&account.Security, str("security"))
	case model.VLESS:
		set(&account.UUID, str("id"))
	case model.Trojan, model.Shadowsocks, defaults.ProtoAnyTLS:
		set(&account.Password, str("password"))
	case defaults.ProtoNaive:
		set(&account.Password, str("password"))
		set(&account.NaiveUser, str("username"))
	case model.TUIC:
		set(&account.UUID, str("id"))
		set(&account.Password, str("password"))
	case model.Hysteria, defaults.ProtoHysteria2:
		set(&account.Auth, str("auth"))
	case defaults.ProtoL2TP, defaults.ProtoPPTP, defaults.ProtoOpenVPN, defaults.ProtoOpenConnect,
		defaults.ProtoSSTP, defaults.ProtoIKEv2, defaults.ProtoSSH:
		set(&account.VpnUsername, str("id"))
		set(&account.Password, str("password"))
	case model.MTProto:
		set(&account.Secret, str("secret"))
	case defaults.ProtoWGC, defaults.ProtoAWG, defaults.ProtoGRE:
		// Identity is the email and nothing reads "id"; there is no credential to lift.
	default:
		set(&account.UUID, str("id"))
	}
	return changed
}

// shadowsocksKeySize is the exact PSK length the inbound's cipher requires, in
// bytes, or 0 when the cipher takes any string.
//
// Only the 2022-blake3 family constrains it; every legacy method is happy with the
// dashless uuid the other password protocols share.
func shadowsocksKeySize(inbound *model.Inbound) int {
	method := ""
	var settings map[string]any
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err == nil {
		method, _ = settings["method"].(string)
	}
	return shadowsocksMethodKeySize(method)
}

// shadowsocksMethodKeySize is the same answer for a named cipher, so a caller
// holding a per-CLIENT method (multi-user shadowsocks lets an account carry its own,
// and the inbound-level one is only the default) can ask about that instead.
func shadowsocksMethodKeySize(method string) int {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "2022-blake3-aes-128-gcm":
		return 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32
	}
	return 0
}

// validShadowsocksKey reports whether a password is a legal PSK for a cipher of
// the given key size: base64 decoding to EXACTLY that many bytes.
//
// The length is what matters and what the shared account password gets wrong. A
// 32-character dashless uuid is legal base64 by accident (it decodes to 24 bytes),
// so "does it decode" alone would call a broken PSK good.
func validShadowsocksKey(password string, keySize int) bool {
	if keySize <= 0 {
		return true
	}
	raw, err := base64.StdEncoding.DecodeString(password)
	return err == nil && len(raw) == keySize
}

// shadowsocksUserKey mints a per-user password valid for the inbound's cipher.
//
// An account on two shadowsocks inbounds of DIFFERENT 2022 key lengths is served
// on both: each membership keeps its own minted PSK in its own entry, so the
// single account password column no longer decides it.
func shadowsocksUserKey(inbound *model.Inbound) string {
	size := shadowsocksKeySize(inbound)
	if size == 0 {
		return strings.ReplaceAll(uuid.NewString(), "-", "")
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand does not fail in practice; a uuid pair is still 32 bytes of
		// unpredictable material rather than something guessable.
		copy(buf, []byte(strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")))
	}
	return base64.StdEncoding.EncodeToString(buf)
}
