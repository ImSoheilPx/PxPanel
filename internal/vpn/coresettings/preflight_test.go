package coresettings

import (
	"os"
	"path/filepath"
	"testing"
)

// Pre-flight gating tests, from vpn-ui preflight_test.go (pure half; the DB
// halves of the catalog-probe tests live in db_test.go under the linux+cgo
// gate).

// The decision table, pinned directly because the interesting row cannot be
// produced from a test host on demand.
//
// installed=true + recorded=false is the bug: the panel THINKS the core is
// installed, on the strength of the baseline guess alone, having provisioned
// nothing. The old rule was `!builtin && !installed`, which answers false there
// and skips the probe; this test fails against it. The other rows exist so a
// future simplification to "always probe" also fails, because that would warn the
// operator about the panel's own files.
func TestCoreShouldProbeConflictsDecisionTable(t *testing.T) {
	cases := []struct {
		builtin, installed, recorded bool
		want                         bool
		why                          string
	}{
		{
			installed: true, recorded: false, want: true,
			why: "the baseline GUESS said installed but nothing was provisioned: this is the hole",
		},
		{
			installed: false, recorded: false, want: true,
			why: "nothing provisioned and nothing claimed installed",
		},
		{
			installed: true, recorded: true, want: false,
			why: "genuinely installed: the artifacts are ours and the manifest is the record",
		},
		{
			installed: false, recorded: true, want: true,
			why: "recorded state, core not installed: still offered, so still probed",
		},
		{
			builtin: true, installed: false, recorded: false, want: false,
			why: "a built-in core installs nothing, so it collides with nothing",
		},
		{
			builtin: true, installed: true, recorded: true, want: false,
			why: "built-in, whatever else is true",
		},
	}
	for _, c := range cases {
		got := coreShouldProbeConflicts(c.builtin, c.installed, c.recorded)
		if got != c.want {
			t.Errorf("coreShouldProbeConflicts(builtin=%v, installed=%v, recorded=%v) = %v, want %v: %s",
				c.builtin, c.installed, c.recorded, got, c.want, c.why)
		}
	}
}

// And the probe itself does detect an existing shared file. Kept separate from
// the gating tests above because this one is about the stat, not about which
// cores reach it.
func TestPreflightProbeDetectsAnExistingFileAndDirectory(t *testing.T) {
	dir := t.TempDir()

	file := filepath.Join(dir, "ipsec.secrets")
	if err := os.WriteFile(file, []byte(": PSK \"theirs\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := preflightFile(file); c == nil {
		t.Error("an existing shared config file was not reported as a conflict")
	} else if c.Kind != kindFile || c.What != file || c.Detail == "" {
		t.Errorf("malformed conflict for a file: %+v", c)
	}
	if c := preflightFile(filepath.Join(dir, "absent.conf")); c != nil {
		t.Errorf("a file that is not there was reported as a conflict: %+v", c)
	}

	sub := filepath.Join(dir, "ocserv")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if c := preflightDir(sub); c == nil {
		t.Error("an existing config directory was not reported as a conflict")
	} else if c.Kind != kindDir {
		t.Errorf("directory conflict reported as kind %q", c.Kind)
	}
	// A plain file is not a directory conflict, so a stat that lands on the wrong
	// kind reports nothing rather than the wrong thing.
	if c := preflightDir(file); c != nil {
		t.Errorf("a regular file was reported as a directory conflict: %+v", c)
	}
}
