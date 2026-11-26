package coreconfig

import (
	"strings"
	"testing"
)

// The merge-semantics tests, from vpn-ui coreconfig_test.go's pure half. These
// pin the replace/append behaviour the editor's round-trip depends on; the
// DB-backed round-trip lives in coreconfig_db_test.go (linux+cgo gate).

// TestMergeCoreConfigAppendKeepsTheRender is the property the whole append mode rests
// on: whatever the generator wrote is still there afterwards, so a new inbound or client
// keeps being served.
//
// No UI reaches this any more (the editor posts replace over the whole file), but the
// endpoint still accepts the mode and the generators still merge it, so it is still
// covered rather than left to rot.
func TestMergeCoreConfigAppendKeepsTheRender(t *testing.T) {
	rendered := "[lns default]\nip range = 10.0.2.10-10.0.2.250\n"
	out := MergeCoreConfig(rendered, ModeAppend, "flow bit = no")
	if !strings.Contains(out, "ip range = 10.0.2.10-10.0.2.250") {
		t.Fatalf("append dropped the generated body:\n%s", out)
	}
	if !strings.Contains(out, "flow bit = no\n") {
		t.Fatalf("append dropped the override:\n%s", out)
	}
	if !strings.Contains(out, coreConfigBanner) {
		t.Fatalf("append did not mark where the override starts:\n%s", out)
	}
	if strings.Index(out, "ip range") > strings.Index(out, "flow bit") {
		t.Fatalf("the override must come AFTER the render:\n%s", out)
	}
}

// TestMergeCoreConfigIsStable guards mtproto's write-only-on-change check: telemt
// watches config.toml with inotify and the traffic job regenerates it every 10s, so an
// output that differed between two identical runs would make it hot-reload forever.
func TestMergeCoreConfigIsStable(t *testing.T) {
	rendered := "[general]\nlog_level = \"normal\"\n"
	first := MergeCoreConfig(rendered, ModeAppend, "[extra]\nkey = 1")
	second := MergeCoreConfig(rendered, ModeAppend, "[extra]\nkey = 1")
	if first != second {
		t.Fatalf("merge is not deterministic:\n%q\nvs\n%q", first, second)
	}
	// Trailing-newline differences in the render must not move the result either: the
	// generators are not consistent about it.
	if MergeCoreConfig("a\n", ModeAppend, "b") != MergeCoreConfig("a\n\n\n", ModeAppend, "b") {
		t.Fatal("a differing number of trailing newlines changed the merged output")
	}
}

// TestMergeCoreConfigReplaceDropsTheRender is the dangerous half, asserted so it stays
// deliberate: replace mode really does discard everything the generator produced, and it
// is what the editor posts, which is why the modal's one warning is about being frozen at
// what you save.
func TestMergeCoreConfigReplaceDropsTheRender(t *testing.T) {
	out := MergeCoreConfig("generated body\n", ModeReplace, "mine only")
	if strings.Contains(out, "generated body") {
		t.Fatalf("replace kept the generated body:\n%s", out)
	}
	if out != "mine only\n" {
		t.Fatalf("replace should be the override verbatim, got %q", out)
	}
}

// TestMergeCoreConfigEmptyIsNoOverride: clearing the text is how "Reset to default"
// works, so blank input must leave the render untouched rather than append a banner
// over nothing.
func TestMergeCoreConfigEmptyIsNoOverride(t *testing.T) {
	rendered := "name l2tp\n"
	for _, text := range []string{"", "   ", "\n\t\n"} {
		if got := MergeCoreConfig(rendered, ModeAppend, text); got != rendered {
			t.Fatalf("blank override changed the file: %q -> %q", text, got)
		}
		if got := MergeCoreConfig(rendered, ModeReplace, text); got != rendered {
			t.Fatalf("blank replace-mode override changed the file: %q -> %q", text, got)
		}
	}
}

func TestValidateSwanctlBraces(t *testing.T) {
	ok := `connections {
    l2tp-psk {
        version = 1   # a comment with an unbalanced { in it
    }
}
`
	if err := ValidateSwanctlBraces(ok); err != nil {
		t.Fatalf("a balanced config was rejected: %v", err)
	}
	if err := ValidateSwanctlBraces("connections {\n    x {\n    }\n"); err == nil {
		t.Fatal("an unclosed section was accepted")
	}
	if err := ValidateSwanctlBraces("}\n"); err == nil {
		t.Fatal("a stray closing brace was accepted")
	}
}

// TestCoreConfigKeyDistinguishesOpenVpnTransports is why the key carries a file name on
// top of the inbound id: OpenVPN writes TWO configs for one inbound, and an override on
// the UDP one must not land on the TCP one.
func TestCoreConfigKeyDistinguishesOpenVpnTransports(t *testing.T) {
	udp := Key("openvpn", 12, "server-udp.conf")
	tcp := Key("openvpn", 12, "server-tcp.conf")
	if udp == tcp {
		t.Fatalf("both transports share the key %q", udp)
	}
	if Key("l2tp", 0, "xl2tpd.conf") == Key("pptp", 0, "xl2tpd.conf") {
		t.Fatal("two cores share a key for the same file name")
	}
}

// TestStoreOverrideRejectsUnknownModes: the storage half of the save endpoint
// refuses a mode it cannot merge, so a typo'd API call cannot plant an override
// that silently never applies.
func TestStoreOverrideRejectsUnknownModes(t *testing.T) {
	if err := StoreOverride("l2tp", 0, "xl2tpd.conf", "clobber", "x"); err == nil {
		t.Fatal("an unknown override mode was accepted")
	}
}
