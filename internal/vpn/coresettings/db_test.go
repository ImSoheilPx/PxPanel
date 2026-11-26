//go:build linux && cgo

package coresettings

// The DB halves of the vpn-ui corecatalog_test.go + preflight_test.go tests:
// the provisioned-set sentinel semantics and the catalog conflict-probe gating.
// Gated to linux+cgo — the reads go through the panel database (CGO sqlite;
// see internal/database), same as the other vpn waves' _db_test.go files; CI
// runs this file.

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/database"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
)

func newCoreSettingsDB(t *testing.T) {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	vpn.SetDB(database.GetDB)
}

// The installed-core set is persisted as a string, and "" already means "this
// install predates per-core tracking, credit it with the frozen baseline". So
// recording "the operator removed everything" as "" would collide with that and
// silently resurrect the baseline cores as installed. These two tests pin the
// sentinel that keeps the two cases apart.
func TestProvisionedProtocolsRoundTrip(t *testing.T) {
	newCoreSettingsDB(t)

	if HasRecordedProvisionedProtocols() {
		t.Error("a fresh install must not claim to have recorded a core set")
	}

	if err := SetProvisionedProtocols([]string{"l2tp", "ikev2"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if got := GetProvisionedProtocols(); !slices.Equal(got, []string{"l2tp", "ikev2"}) {
		t.Errorf("got %v, want [l2tp ikev2]", got)
	}
	if !HasRecordedProvisionedProtocols() {
		t.Error("a written set must be reported as recorded")
	}
}

func TestUninstallingEveryCoreIsRecordedAsNone(t *testing.T) {
	newCoreSettingsDB(t)
	var cs CoreService

	if err := SetVpnProvisioned(true); err != nil {
		t.Fatalf("set provisioned: %v", err)
	}
	if err := SetProvisionedProtocols(nil); err != nil {
		t.Fatalf("set none: %v", err)
	}

	if got := GetProvisionedProtocols(); len(got) != 0 {
		t.Errorf("an empty set must read back empty, got %v", got)
	}
	if !HasRecordedProvisionedProtocols() {
		t.Error("recording none is still a recording")
	}
	// The regression: without the sentinel this falls through to
	// provisionBaseline and reports l2tp/pptp/openvpn/openconnect as installed.
	if set := cs.provisionedProtocolSet(); len(set) != 0 {
		t.Errorf("removing every core must leave nothing installed, got %v", set)
	}
	if got := cs.installedCoreNames(); len(got) != 0 {
		t.Errorf("installedCoreNames = %v, want none", got)
	}
}

// withStubConflictProbe swaps the pre-flight probe for one that records which
// cores were asked about and answers with a synthetic conflict for each. The real
// probe stats absolute host paths, which a test can neither create nor depend on;
// what is worth pinning is WHICH CORES get probed.
func withStubConflictProbe(t *testing.T) *[]string {
	t.Helper()
	var probed []string
	orig := coreConflictProbe
	coreConflictProbe = func(core string) []CoreHostConflict {
		probed = append(probed, core)
		return []CoreHostConflict{{Kind: kindFile, What: "/etc/" + core + ".conf", Detail: "already present"}}
	}
	t.Cleanup(func() { coreConflictProbe = orig })
	return &probed
}

func containsCore(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// The bug this pins: a panel that has provisioned NOTHING still reported zero
// conflicts for l2tp, pptp, openvpn and openconnect.
//
// IsProvisioned falls back to `ip_forward==1 && daemonInstalled("openvpn")`, and
// daemonInstalled is a PATH lookup, so a box with a distro OpenVPN and
// ip_forward=1 reads as provisioned on a fresh database. provisionedProtocolSet
// then credits the frozen baseline, and the conflict probe was skipped for a core
// the panel merely GUESSED it had installed. Those four are precisely the cores
// whose shared config files a distro install is most likely to own already, so
// the warning went missing exactly where it was worth having.
func TestConflictsAreProbedWhenNothingIsProvisioned(t *testing.T) {
	newCoreSettingsDB(t)
	probed := withStubConflictProbe(t)

	var cs CoreService
	if cs.coreInstallStateIsRecorded() {
		t.Fatal("a fresh database must not claim a recorded install state")
	}

	opts := cs.CoreCatalog()
	byName := map[string]CoreOption{}
	for _, o := range opts {
		byName[o.Name] = o
	}

	// Every baseline core, i.e. every core the guess would have marked installed.
	for _, name := range provisionBaseline {
		if !containsCore(*probed, name) {
			t.Errorf("core %q was not probed for host conflicts on a not-yet-provisioned panel", name)
		}
		if len(byName[name].Conflicts) == 0 {
			t.Errorf("core %q reported no conflicts even though the probe found one", name)
		}
	}
	// A non-baseline core was already working and must not regress.
	if !containsCore(*probed, "ikev2") {
		t.Error("ikev2 was not probed on a not-yet-provisioned panel")
	}
	// Built-in cores have nothing to install, so nothing to collide with.
	for _, name := range []string{"xray", "radius", "ssh"} {
		if containsCore(*probed, name) {
			t.Errorf("built-in core %q should never be probed", name)
		}
	}
}

// The other half of the rule: once the operator has really installed a core, its
// artifacts are ours and the manifest is the record that matters, so the probe is
// skipped. Without this the fix would just be "always probe", which would warn
// about our own files.
func TestConflictsAreNotProbedForAGenuinelyInstalledCore(t *testing.T) {
	newCoreSettingsDB(t)
	if err := SetProvisionedProtocols([]string{"l2tp", "openvpn"}); err != nil {
		t.Fatalf("SetProvisionedProtocols: %v", err)
	}
	probed := withStubConflictProbe(t)

	var cs CoreService
	if !cs.coreInstallStateIsRecorded() {
		t.Fatal("a written core set must count as a recorded install state")
	}

	opts := cs.CoreCatalog()
	byName := map[string]CoreOption{}
	for _, o := range opts {
		byName[o.Name] = o
	}
	for _, name := range []string{"l2tp", "openvpn"} {
		if containsCore(*probed, name) {
			t.Errorf("installed core %q was probed; its artifacts are ours", name)
		}
		if len(byName[name].Conflicts) != 0 {
			t.Errorf("installed core %q reported conflicts", name)
		}
	}
	// Still offered for install, so still probed.
	for _, name := range []string{"pptp", "ikev2"} {
		if !containsCore(*probed, name) {
			t.Errorf("core %q is not installed and should have been probed", name)
		}
	}
}

// A pre-tracking upgrade (vpnProvisioned set, no recorded list) is the case the
// baseline fallback exists for, and it must keep behaving charitably: those four
// cores really were installed by the old all-or-nothing setup run, so their files
// are ours and warning about them would be noise.
func TestBaselineIsTrustedOnAPreTrackingUpgrade(t *testing.T) {
	newCoreSettingsDB(t)
	if err := SetVpnProvisioned(true); err != nil {
		t.Fatalf("SetVpnProvisioned: %v", err)
	}
	probed := withStubConflictProbe(t)

	var cs CoreService
	if !cs.coreInstallStateIsRecorded() {
		t.Fatal("vpnProvisioned must count as a recorded install state")
	}
	if HasRecordedProvisionedProtocols() {
		t.Fatal("this test needs the pre-tracking shape: no recorded core list")
	}

	cs.CoreCatalog()
	for _, name := range provisionBaseline {
		if containsCore(*probed, name) {
			t.Errorf("baseline core %q was probed on a pre-tracking upgrade; its files are ours", name)
		}
	}
	if !containsCore(*probed, "ikev2") {
		t.Error("a core outside the baseline is not installed and should have been probed")
	}
}
