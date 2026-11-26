// Routing translation tests: the vpn-ui translateVpnRoutingRules semantics,
// exercised through the pure half (no database).
package xrayplane

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/util/json_util"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
	vpnrange "github.com/ImSoheilPx/pxpanel/internal/vpn/range"
	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

func routingRule(t *testing.T, cfg *xray.Config, i int) map[string]any {
	t.Helper()
	var routing map[string]any
	if err := json.Unmarshal(cfg.RouterConfig, &routing); err != nil {
		t.Fatalf("routing decode: %v", err)
	}
	rules, _ := routing["rules"].([]any)
	if i >= len(rules) {
		t.Fatalf("rule %d missing, have %d", i, len(rules))
	}
	rule, _ := rules[i].(map[string]any)
	return rule
}

func configWithRules(t *testing.T, rules []map[string]any) *xray.Config {
	t.Helper()
	outbounds := []map[string]any{
		{"tag": "proxy-all", "protocol": "freedom"},
		{"tag": "block-vpn", "protocol": "blackhole"},
	}
	rawRules := make([]any, len(rules))
	for i, r := range rules {
		rawRules[i] = r
	}
	obs, _ := json.Marshal(outbounds)
	router, _ := json.Marshal(map[string]any{"rules": rawRules})
	return &xray.Config{
		RouterConfig:    json_util.RawMessage(router),
		OutboundConfigs: json_util.RawMessage(obs),
	}
}

// A VPN-only email moves to a source rule carrying the tunnel IPs.
func TestTranslateMovesVpnEmailsToSourceRules(t *testing.T) {
	cfg := configWithRules(t, []map[string]any{
		{"type": "field", "user": []any{"vpn@x"}, "outboundTag": "proxy-all"},
	})
	vpnMap := map[string][]string{"vpn@x": {"10.0.5.6", "10.0.5.7"}}
	native := map[string]bool{}

	translateRoutingRulesWith(cfg, vpnMap, native)

	first := routingRule(t, cfg, 0)
	if src, ok := first["source"].([]any); !ok || !reflect.DeepEqual(src, []any{"10.0.5.6", "10.0.5.7"}) {
		t.Errorf("rule 0 source = %v, want the tunnel IPs", first["source"])
	}
	if _, has := first["user"]; has {
		t.Error("the vpn rule kept its user list; vpn-ui moved those emails to source matching")
	}
	// Backstop appended last: every valid IP -> default outbound, the whole
	// /12 -> blackhole.
	second := routingRule(t, cfg, 1)
	third := routingRule(t, cfg, 2)
	if src, _ := second["source"].([]any); !reflect.DeepEqual(src, []any{"10.0.5.6", "10.0.5.7"}) || second["outboundTag"] != "proxy-all" {
		t.Errorf("backstop pass-through = %+v, want valid IPs to the default outbound", second)
	}
	if src, _ := third["source"].([]any); !reflect.DeepEqual(src, []any{VpnAddrSpace}) || third["outboundTag"] != "block-vpn" {
		t.Errorf("backstop blackhole = %+v, want %s to the blackhole tag", third, VpnAddrSpace)
	}
}

// An email Xray also authenticates natively stays in BOTH lists: the source rule
// for its tunnel addresses AND the user rule for what the core terminates.
func TestTranslateKeepsNativeEmailsInTheUserList(t *testing.T) {
	cfg := configWithRules(t, []map[string]any{
		{"type": "field", "user": []any{"both@x", "plain@x"}, "outboundTag": "proxy-all"},
	})
	vpnMap := map[string][]string{"both@x": {"10.4.9.2"}}
	native := map[string]bool{"both@x": true} // normalized key

	translateRoutingRulesWith(cfg, vpnMap, native)

	source := routingRule(t, cfg, 0)
	if src, _ := source["source"].([]any); !reflect.DeepEqual(src, []any{"10.4.9.2"}) {
		t.Errorf("source rule = %+v, want 10.4.9.2", source)
	}
	kept := routingRule(t, cfg, 1)
	if users, _ := kept["user"].([]any); !reflect.DeepEqual(users, []any{"both@x", "plain@x"}) {
		t.Errorf("kept user rule = %v, want the native both@x kept (then plain@x)", users)
	}
}

// Emails absent from the map are untouched — native and relay accounts keep
// their user rules (mtproto authenticates as the socks username). The backstop
// still fires though: vpn-ui appended it whenever the map had ANY address and a
// blackhole outbound exists, regardless of which rules matched.
func TestTranslateLeavesUnknownEmailsAlone(t *testing.T) {
	rules := []map[string]any{
		{"type": "field", "user": []any{"mt-relay@x"}, "outboundTag": "proxy-all"},
	}
	cfg := configWithRules(t, rules)
	translateRoutingRulesWith(cfg, map[string][]string{"other@x": {"10.1.2.3"}}, map[string]bool{})

	got := routingRule(t, cfg, 0)
	if users, _ := got["user"].([]any); !reflect.DeepEqual(users, []any{"mt-relay@x"}) {
		t.Errorf("rule = %+v, want the relay email kept as a user match", got)
	}
	if _, has := got["source"]; has {
		t.Errorf("the relay rule must not gain a source match: %+v", got)
	}
	// The backstop covers the other account's legit IP and blackholes the rest.
	pass := routingRule(t, cfg, 1)
	if src, _ := pass["source"].([]any); !reflect.DeepEqual(src, []any{"10.1.2.3"}) || pass["outboundTag"] != "proxy-all" {
		t.Errorf("backstop pass-through = %+v, want 10.1.2.3 to the default outbound", pass)
	}
	hole := routingRule(t, cfg, 2)
	if src, _ := hole["source"].([]any); !reflect.DeepEqual(src, []any{VpnAddrSpace}) || hole["outboundTag"] != "block-vpn" {
		t.Errorf("backstop blackhole = %+v, want %s to block-vpn", hole, VpnAddrSpace)
	}
}

// An empty map means no translation at all — including no backstop.
func TestTranslateNoopWithoutVpnClients(t *testing.T) {
	cfg := configWithRules(t, []map[string]any{
		{"type": "field", "user": []any{"a@x"}, "outboundTag": "p"},
	})
	before := cfg.RouterConfig
	translateRoutingRulesWith(cfg, map[string][]string{}, map[string]bool{})
	if string(cfg.RouterConfig) != string(before) {
		t.Error("empty vpnMap must leave the routing section untouched")
	}
}

// The backstop is skipped when the template has no blackhole outbound.
func TestTranslateBackstopNeedsABlackhole(t *testing.T) {
	cfg := &xray.Config{
		RouterConfig:    json_util.RawMessage(`{"rules":[{"type":"field","user":["vpn@x"],"outboundTag":"p"}]}`),
		OutboundConfigs: json_util.RawMessage(`[{"tag":"p","protocol":"freedom"}]`),
	}
	translateRoutingRulesWith(cfg, map[string][]string{"vpn@x": {"10.0.5.6"}}, map[string]bool{})
	if n := routingRuleCount(t, cfg); n != 1 {
		t.Errorf("rules = %d, want 1 (the source rule; no blackhole, no backstop)", n)
	}
}

func routingRuleCount(t *testing.T, cfg *xray.Config) int {
	t.Helper()
	var routing map[string]any
	if err := json.Unmarshal(cfg.RouterConfig, &routing); err != nil {
		t.Fatalf("routing decode: %v", err)
	}
	rules, _ := routing["rules"].([]any)
	return len(rules)
}

// RemoveIndex is a verbatim vpn-ui helper; pin the obvious.
func TestRemoveIndex(t *testing.T) {
	got := RemoveIndex([]any{"a", "b", "c"}, 1)
	if len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Errorf("RemoveIndex = %v, want [a c]", got)
	}
}

// The PPP-family email->IP computation: K=1 single IP, K>=2 the whole device
// block, ikev2 psk the whole /16 block CIDR, wgc gateway the aligned block CIDR.
func TestPppInboundEmailIPs(t *testing.T) {
	// l2tp, K=1 (no userLimit key): one continuous per-index IP out of 10.0.<id>.
	got := pppInboundEmailIPs(defaults.ProtoL2TP, 5, `{"clients":[{"email":"a@x"},{"email":"b@x"}]}`)
	if len(got["a@x"]) != 1 || got["a@x"][0] != "10.0.5.2" {
		t.Errorf("l2tp K=1 a@x = %v, want [10.0.5.2]", got["a@x"])
	}
	if len(got["b@x"]) != 1 || got["b@x"][0] != "10.0.5.3" {
		t.Errorf("l2tp K=1 b@x = %v, want [10.0.5.3]", got["b@x"])
	}

	// pptp, K=3: the account maps to its three device IPs so one source rule
	// covers every device.
	three := 3
	got = pppInboundEmailIPs(defaults.ProtoPPTP, 6, `{"userLimit":3,"clients":[{"email":"c@x","slot":1}]}`)
	if !reflect.DeepEqual(got["c@x"], vpnrange.VpnAccountDeviceIPs([]string{"10.1.6"}, 1, three)) {
		t.Errorf("pptp K=3 c@x = %v, want the slot-1 device block of 10.1.6", got["c@x"])
	}

	// ikev2 psk: the account maps to the whole charon pool block. With no ranges
	// stored the block falls back to the id-derived /24 (vpnBlock's fallback),
	// exactly as vpn-ui's map produced for a legacy inbound.
	got = pppInboundEmailIPs(defaults.ProtoIKEv2, 1, `{"authMode":"psk","clients":[{"email":"d@x"}]}`)
	if len(got["d@x"]) != 1 {
		t.Fatalf("ikev2 psk d@x = %v, want exactly the block CIDR", got["d@x"])
	}
	if got["d@x"][0] != "10.6.1.0/24" {
		t.Errorf("ikev2 psk d@x[0] = %q, want the id-derived 10.6.1.0/24", got["d@x"][0])
	}

	// wgc gateway model, K=2 (block size 2 -> a /31 CIDR).
	got = pppInboundEmailIPs(defaults.ProtoWGC, 8, `{"userLimit":2,"clients":[{"email":"e@x"}]}`)
	if len(got["e@x"]) != 1 || !endsWith(t, got["e@x"][0], "/31") {
		t.Errorf("wgc K=2 e@x = %v, want one aligned /31 CIDR", got["e@x"])
	}

	// Malformed settings contribute nothing.
	if got := pppInboundEmailIPs(defaults.ProtoGRE, 9, `not-json`); len(got) != 0 {
		t.Errorf("malformed settings produced %v, want nothing", got)
	}
}

func endsWith(t *testing.T, s, suffix string) bool {
	t.Helper()
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
