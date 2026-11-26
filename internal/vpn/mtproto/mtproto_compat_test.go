package mtproto

import (
	"encoding/json"
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
)

// Compatibility with the shape MTProto settings had before the modes, the FakeTLS
// domain and the device cap moved from the clients onto the inbound.
//
// Two properties, and they are what make the move safe in both directions:
//
//   - An inbound in the OLD shape means exactly what the equivalent new one means, on
//     every path it can arrive by, whether or not the lift has run on it yet.
//   - The blob the panel writes keeps satisfying the PREVIOUS binary, so a rollback does
//     not strand the accounts created since the upgrade.
//
// See the compatibility block in mtproto.go. The lift's own seeding rules are pinned in
// mtproto_settings_test.go; these tests are about the paths, the mirror and the churn.

// mtprotoLegacyBlob is one inbound in the pre-move shape. alice holds classic+secure
// and a 4-device cap, bob holds FakeTLS with a domain and a 2-device cap, so the
// resolution exercises all three rules at once: the union, the first FakeTLS domain,
// and the largest cap.
const mtprotoLegacyBlob = `{"clients":[
	{"id":"alice","email":"alice","secret":"00112233445566778899aabbccddeeff","enable":true,
	 "modeClassic":true,"modeSecure":true,"userLimit":4,"comment":"keep me"},
	{"id":"bob","email":"bob","secret":"ffeeddccbbaa99887766554433221100","enable":true,
	 "modeTls":true,"tlsDomain":"www.cloudflare.com","userLimit":2}
]}`

// mtprotoMigratedBlob is the same inbound already in the current shape: the union of
// the two accounts' modes, bob's FakeTLS domain, and the larger of the two caps.
const mtprotoMigratedBlob = `{"modeClassic":true,"modeSecure":true,"modeTls":true,
	"tlsDomain":"www.cloudflare.com","userLimit":4,"clients":[
	{"id":"alice","email":"alice","secret":"00112233445566778899aabbccddeeff","enable":true,"comment":"keep me"},
	{"id":"bob","email":"bob","secret":"ffeeddccbbaa99887766554433221100","enable":true}
]}`

func mtprotoInboundFrom(settings string) *model.Inbound {
	return &model.Inbound{Id: 3, Port: 9443, Tag: "inbound-9443", Protocol: defaults.ProtoMTProto, Settings: settings}
}

// renderMtproto is the config telemt would be handed for one inbound.
func renderMtproto(t *testing.T, inbound *model.Inbound) string {
	t.Helper()
	s := &MtprotoService{}
	settings, err := s.parseSettings(inbound)
	if err != nil {
		t.Fatalf("parseSettings: %v", err)
	}
	return s.buildServerConfig(inbound, settings)
}

// The whole contract in one assertion: reading an inbound still in the old shape must
// produce the SAME telemt config as the equivalent new-shape one, with no lift in
// between. Anything less means the daemon's behaviour changes at the moment the lift
// happens to run, which is a background pass on a 10-second timer.
func TestMtprotoLegacyShapeRendersTheSameConfig(t *testing.T) {
	legacy := renderMtproto(t, mtprotoInboundFrom(mtprotoLegacyBlob))
	migrated := renderMtproto(t, mtprotoInboundFrom(mtprotoMigratedBlob))
	if legacy != migrated {
		t.Errorf("an un-lifted inbound renders a different config than the lifted one:\n--- legacy ---\n%s\n--- migrated ---\n%s",
			legacy, migrated)
	}
}

// The read-side fallback lives on mtprotoSettings itself, so no decoder can reach the
// wrong answer. Without it the modes come out all-false, which telemt reads as "no
// restriction" rather than "no modes" and startable() refuses to run at all.
func TestMtprotoParseResolvesLegacySettings(t *testing.T) {
	s := &MtprotoService{}
	settings, err := s.parseSettings(mtprotoInboundFrom(mtprotoLegacyBlob))
	if err != nil {
		t.Fatal(err)
	}
	if !settings.ModeClassic || !settings.ModeSecure || !settings.ModeTls {
		t.Errorf("modes = %v/%v/%v, want the union of the accounts' modes",
			settings.ModeClassic, settings.ModeSecure, settings.ModeTls)
	}
	if settings.TlsDomain != "www.cloudflare.com" {
		t.Errorf("tlsDomain = %q, want the first FakeTLS account's domain", settings.TlsDomain)
	}
	if settings.UserLimit == nil || *settings.UserLimit != 4 {
		t.Errorf("userLimit = %v, want the largest cap any account held (4)", settings.UserLimit)
	}
	if !s.startable(settings) {
		t.Error("a legacy inbound reported not startable: telemt would never be launched for it")
	}
}

// A mixed inbound: alice predates the move and carries the old keys, bob was added by a
// newer binary and carries none. bob must not drag the resolution down.
//
// Documented resolution: the union is alice's set (bob contributes nothing), and the cap
// is the largest EFFECTIVE one, where bob's absent value counts as the single device it
// has always meant, so alice's explicit 3 wins.
func TestMtprotoMixedClientsResolveTheDocumentedWay(t *testing.T) {
	mixed := `{"clients":[
		{"email":"alice","secret":"00112233445566778899aabbccddeeff","enable":true,
		 "modeSecure":true,"userLimit":3},
		{"email":"bob","secret":"ffeeddccbbaa99887766554433221100","enable":true}
	]}`
	s := &MtprotoService{}
	settings, err := s.parseSettings(mtprotoInboundFrom(mixed))
	if err != nil {
		t.Fatal(err)
	}
	if settings.ModeClassic || !settings.ModeSecure || settings.ModeTls {
		t.Errorf("modes = %v/%v/%v, want only secure (the one mode any account held)",
			settings.ModeClassic, settings.ModeSecure, settings.ModeTls)
	}
	if settings.UserLimit == nil || *settings.UserLimit != 3 {
		t.Errorf("userLimit = %v, want 3: an absent per-client cap means one device, not no limit", settings.UserLimit)
	}
	// No account asked for FakeTLS, so there is no domain to preserve and the default
	// stands. It is never left empty: telemt models its fake certificate on a real one.
	if settings.TlsDomain != "www.google.com" {
		t.Errorf("tlsDomain = %q, want the default", settings.TlsDomain)
	}
}

// The API add path. FillSettingsDefaults would otherwise stamp the fresh-inbound values
// (all three modes on, no device cap) onto a body whose policy is on its clients, and
// the blob would then look already-migrated to every later reader: the values would be
// gone with nothing left to recover them from.
func TestMtprotoApiAddKeepsLegacyShapeValues(t *testing.T) {
	inbound := mtprotoInboundFrom(`{"clients":[
		{"id":"a","email":"a","secret":"00112233445566778899aabbccddeeff","enable":true,
		 "modeSecure":true,"tlsDomain":"ignored.example","userLimit":5}
	]}`)
	if err := defaults.NormalizeInboundSettings(inbound); err != nil {
		t.Fatalf("NormalizeInboundSettings: %v", err)
	}
	var got mtprotoSettings
	if err := json.Unmarshal([]byte(inbound.Settings), &got); err != nil {
		t.Fatal(err)
	}
	if got.ModeClassic || !got.ModeSecure || got.ModeTls {
		t.Errorf("modes = %v/%v/%v, want only secure: the defaults widened the caller's set",
			got.ModeClassic, got.ModeSecure, got.ModeTls)
	}
	if got.UserLimit == nil || *got.UserLimit != 5 {
		t.Errorf("userLimit = %v, want the caller's 5 rather than the default 10", got.UserLimit)
	}
	// The domain came off an account with no FakeTLS mode, which is exactly the one the
	// process was never emulating, so the default stands here too.
	if got.TlsDomain != "www.google.com" {
		t.Errorf("tlsDomain = %q, want the default", got.TlsDomain)
	}
	// And the result is a blob the validator accepts, since the add path judges the
	// filled body rather than the posted one. (vpn-ui: ValidateProtocolSettings(
	// model.MTPROTO, inbound.Settings); the dispatcher lands with the controllers
	// wave, so the package validator is called directly here.)
	if err := ValidateSettings(inbound.Settings); err != nil {
		t.Errorf("the normalized body no longer validates: %v", err)
	}
}

// A body already in the current shape must come through byte-identical: this runs on
// every add the panel makes, and a rewrite here would reorder keys on every inbound
// anyone creates.
func TestMtprotoApiAddLeavesTheCurrentShapeAlone(t *testing.T) {
	const body = `{"modeClassic":false,"modeSecure":true,"modeTls":false,"tlsDomain":"a.example","userLimit":2,"clients":[],"externalProxy":[]}`
	inbound := mtprotoInboundFrom(body)
	if err := defaults.NormalizeInboundSettings(inbound); err != nil {
		t.Fatalf("NormalizeInboundSettings: %v", err)
	}
	if inbound.Settings != body {
		t.Errorf("a current-shape body was rewritten:\n got=%s\nwant=%s", inbound.Settings, body)
	}
}
