package mtproto

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
)

// The connection modes, the FakeTLS domain and the device cap belong to the INBOUND.
// telemt applies each of them process-wide however they are stored, so these tests pin
// that the rendered config says so, and that an inbound written before the move is
// lifted onto the new shape at startup rather than left with no modes at all (which its
// patched reader would take for "unrestricted").
//
// The ad tag is NOT one of them and never moved: telemt keys tags per user, so it stays
// a per-client field. See TestMtprotoAdtagIsPerClient in mtproto_routing_test.go.

func mtprotoInboundWithSettings(t *testing.T, settings *mtprotoSettings) *model.Inbound {
	t.Helper()
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	return &model.Inbound{Id: 3, Port: 9443, Tag: "inbound-9443", Protocol: defaults.ProtoMTProto, Settings: string(raw)}
}

// tomlSection returns the lines of one [section] of a rendered config.
func tomlSection(cfg, header string) []string {
	start := strings.Index(cfg, header+"\n")
	if start < 0 {
		return nil
	}
	rest := cfg[start+len(header)+1:]
	if end := strings.Index(rest, "\n["); end >= 0 {
		rest = rest[:end]
	}
	var out []string
	for _, line := range strings.Split(rest, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// Every account gets the inbound's modes and its device cap. telemt reads both as
// per-USER maps and treats a MISSING entry as "no restriction", so the inbound-wide
// value has to be spelled out for each account rather than written once.
func TestMtprotoInboundSettingsApplyToEveryAccount(t *testing.T) {
	cap4 := 4
	inbound := mtprotoInboundWithSettings(t, &mtprotoSettings{
		ModeClassic: true,
		ModeTls:     true,
		TlsDomain:   "www.cloudflare.com",
		UserLimit:   &cap4,
		Clients: []mtprotoClient{
			{Email: "alice@t", Secret: "00112233445566778899aabbccddeeff", Enable: true},
			{Email: "bob@t", Secret: "ffeeddccbbaa99887766554433221100", Enable: true},
		},
	})
	s := &MtprotoService{}
	settings, err := s.parseSettings(inbound)
	if err != nil {
		t.Fatal(err)
	}
	cfg := s.buildServerConfig(inbound, settings)

	for _, want := range []string{"classic = true", "secure = false", "tls = true"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("[general.modes] is missing %q; the listener would refuse a mode the inbound accepts", want)
		}
	}
	if !strings.Contains(cfg, `tls_domain = "www.cloudflare.com"`) {
		t.Error("the inbound's FakeTLS domain did not reach [censorship]")
	}

	for _, tc := range []struct{ section, want string }{
		{"[access.user_modes]", `= "classic,tls"`},
		{"[access.user_max_unique_ips]", "= 4"},
	} {
		lines := tomlSection(cfg, tc.section)
		if len(lines) != 2 {
			t.Errorf("%s has %d entries, want one per account (2): %v", tc.section, len(lines), lines)
			continue
		}
		for _, line := range lines {
			if !strings.HasSuffix(line, tc.want) {
				t.Errorf("%s entry %q does not carry the inbound value %q", tc.section, line, tc.want)
			}
		}
	}
}

// An inbound with every mode off must not be started. Its per-account mode entries
// would be EMPTY, which the telemt patch reads as "no restriction": the proxy would
// grant every account every mode, the exact opposite of what was configured.
func TestMtprotoInboundWithNoModeIsNotStartable(t *testing.T) {
	s := &MtprotoService{}
	settings := &mtprotoSettings{Clients: []mtprotoClient{
		{Email: "alice@t", Secret: "00112233445566778899aabbccddeeff", Enable: true},
	}}
	if s.startable(settings) {
		t.Error("an inbound with no connection mode reported startable")
	}
	settings.ModeSecure = true
	if !s.startable(settings) {
		t.Error("an inbound with one mode and one account should be startable")
	}
	settings.Clients = nil
	if s.startable(settings) {
		t.Error("an inbound with no usable account reported startable")
	}
}

// The mode guard is what makes the QR gate and the daemon guard reachable states
// rather than defensive noise: an inbound cannot be SAVED with every mode off.
// The mtproto slice of vpn-ui protocolvalidate.go's table. vpn-ui called
// ValidateProtocolSettings(model.MTPROTO, …) — the dispatcher lands with the
// controllers wave (defaults.ValidateSettings); this pins the mtproto rules
// at their home until then.
func TestValidateMtprotoRefusesAnInboundWithNoMode(t *testing.T) {
	err := ValidateSettings(
		`{"modeClassic":false,"modeSecure":false,"modeTls":false,"clients":[]}`)
	if err == nil {
		t.Fatal("an inbound with every connection mode off was accepted")
	}
	if err := ValidateSettings(
		`{"modeClassic":false,"modeSecure":true,"modeTls":false,"clients":[]}`); err != nil {
		t.Fatalf("one mode on was refused: %v", err)
	}
	// An old API body names none of the three. FillSettingsDefaults turns that into an
	// all-on inbound on the add path, so judging its absence here would refuse a body
	// that still works today.
	if err := ValidateSettings(`{"clients":[]}`); err != nil {
		t.Fatalf("a body with no mode keys at all was refused: %v", err)
	}
	// The device cap is bounded like every other protocol's.
	if err := ValidateSettings(
		`{"modeSecure":true,"userLimit":65,"clients":[]}`); err == nil {
		t.Error("userLimit 65 was accepted (max is 64)")
	}
}
