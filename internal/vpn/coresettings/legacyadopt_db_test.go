//go:build linux && cgo

package coresettings

// The DB halves of the legacy adoption: the run-once flag, the adopted cores
// joining the recorded provisioned set, and the status mapping that follows
// from both. Gated to linux+cgo like the other _db_test.go files (CGO sqlite;
// CI runs this file).

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"
)

// newLegacyAdoptDB opens a throwaway database and clears every piece of
// one-time state the adoption touches (the run-once guard, the legacy layout,
// the ownership manifest), restoring all of it on cleanup. It returns the
// test's legacy layout — a well-shaped but EMPTY layout rooted in a temp dir,
// so nothing is detected until the test creates files in it and nothing ever
// touches the real host paths.
func newLegacyAdoptDB(t *testing.T) *procmgr.LegacyLayout {
	t.Helper()
	newCoreSettingsDB(t)

	dir := t.TempDir()
	l := &procmgr.LegacyLayout{
		BinDirs:            []string{filepath.Join(dir, "bin")},
		AccelRoot:          filepath.Join(dir, "accel"),
		StrongswanRoot:     filepath.Join(dir, "strongswan"),
		PppdRoot:           filepath.Join(dir, "libexec"),
		SystemPppd:         filepath.Join(dir, "usr", "sbin", "pppd"),
		PptpCtrlLink:       filepath.Join(dir, "libexec", "pptpctrl"),
		StrongswanIpsecDir: filepath.Join(dir, "usr", "lib", "ipsec"),
	}
	procmgr.SetLegacyLayout(l)

	// The ownership manifest is redirected too: the adoption's link repair
	// records what it creates, and the test must not write near /etc.
	manifest.SetManifestPath(filepath.Join(dir, "ownership.json"), filepath.Join(dir, "backups"))

	ResetLegacyAdoptionForTest()
	t.Cleanup(func() {
		ResetLegacyAdoptionForTest()
		procmgr.SetLegacyLayout(procmgr.DefaultLegacyLayout())
		manifest.Reset()
	})
	return l
}

// touchLegacy creates an executable-looking file (and its parents).
func touchLegacy(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func assertRecordedSet(t *testing.T, want []string) {
	t.Helper()
	got := GetProvisionedProtocols()
	slices.Sort(got)
	w := slices.Clone(want)
	slices.Sort(w)
	if !slices.Equal(got, w) {
		t.Fatalf("recorded provisioned set = %v, want %v", got, w)
	}
}

// The full adoption: every daemon the previous install left behind becomes a
// recorded, installed core without anyone re-running Provision.
func TestLegacyAdoptionRecordsFoundCores(t *testing.T) {
	l := newLegacyAdoptDB(t)
	for _, bin := range []string{"xl2tpd", "pptpd", "openvpn", "ocserv", "telemt"} {
		touchLegacy(t, filepath.Join(l.BinDirs[0], bin))
	}
	touchLegacy(t, filepath.Join(l.AccelRoot, procmgr.LegacyAccelPppdRel))
	touchLegacy(t, filepath.Join(l.StrongswanRoot, procmgr.LegacyCharonRel))

	ensureLegacyAdoption()

	assertRecordedSet(t, []string{
		"ikev2", "l2tp", "mtproto", "openconnect", "openvpn", "pptp", "sstp",
	})
	if !GetVpnProvisioned() {
		t.Error("an adopted host must count as provisioned (the previous install set it up)")
	}
	if !HasRecordedProvisionedProtocols() {
		t.Error("the adopted set must be recorded, not guessed")
	}
	if !LegacyAdoptionDone() {
		t.Error("the run-once guard must be set after a completed scan")
	}
	// The hook seam (procmgr/manifest InstalledCoresFunc) sees the same set:
	if set := ProvisionedProtocolSet(); !set["l2tp"] || !set["sstp"] {
		t.Errorf("ProvisionedProtocolSet() missing adopted cores: %v", set)
	}
}

// Adoption is additive: cores recorded by the operator stay recorded.
func TestLegacyAdoptionPreservesExistingSet(t *testing.T) {
	l := newLegacyAdoptDB(t)
	if err := SetProvisionedProtocols([]string{"wgc", "awg"}); err != nil {
		t.Fatalf("SetProvisionedProtocols: %v", err)
	}
	touchLegacy(t, filepath.Join(l.BinDirs[0], "xl2tpd"))

	ensureLegacyAdoption()

	assertRecordedSet(t, []string{"awg", "l2tp", "wgc"})
}

// The run-once semantics: a second scan must never adopt more, even when the
// layout GREW between scans. This is what keeps an operator's later uninstall
// from being undone by a reboot.
func TestLegacyAdoptionRunsOnce(t *testing.T) {
	l := newLegacyAdoptDB(t)
	touchLegacy(t, filepath.Join(l.BinDirs[0], "xl2tpd"))

	ensureLegacyAdoption()
	assertRecordedSet(t, []string{"l2tp"})

	// The layout grows (charon appears), but the flag is already set.
	touchLegacy(t, filepath.Join(l.StrongswanRoot, procmgr.LegacyCharonRel))
	ensureLegacyAdoption()

	assertRecordedSet(t, []string{"l2tp"})
	if !GetVpnProvisioned() {
		t.Error("the first scan's provisioned flag must survive")
	}
}

// A clean host (fresh install, or the old daemons already cleaned up): the
// scan writes its flag and touches nothing else.
func TestLegacyAdoptionNoopOnCleanHost(t *testing.T) {
	newLegacyAdoptDB(t)

	ensureLegacyAdoption()

	assertRecordedSet(t, nil)
	if HasRecordedProvisionedProtocols() {
		t.Error("a clean host must not gain a recorded core set")
	}
	if GetVpnProvisioned() {
		t.Error("a clean host must not be marked provisioned")
	}
	if !LegacyAdoptionDone() {
		t.Error("the flag must be set even when nothing was found (run once)")
	}
}

// The status mapping: a core whose daemon was adopted reports installed
// (idle — installed, no inbounds) on the Core Settings page, not
// not_installed. A core whose daemon is NOT present is the control.
func TestAdoptedLegacyCoreReportsInstalled(t *testing.T) {
	l := newLegacyAdoptDB(t)
	touchLegacy(t, filepath.Join(l.BinDirs[0], "xl2tpd"))

	var cs CoreService
	states := map[string]CoreState{}
	for _, st := range cs.GetCoresStatus() {
		states[st.Name] = st.State
	}
	if got := states["l2tp"]; got != CoreIdle {
		t.Errorf("adopted l2tp state = %q, want %q (installed, no inbounds)", got, CoreIdle)
	}
	if got := states["pptp"]; got != CoreNotInstalled {
		t.Errorf("non-adopted pptp state = %q, want %q", got, CoreNotInstalled)
	}
}

// The resolution half (independent of the recorded set): once the layout is
// detected, DaemonBin resolves the adopted daemon through the bundle seam.
func TestAdoptedDaemonResolvesThroughDaemonBin(t *testing.T) {
	l := newLegacyAdoptDB(t)
	touchLegacy(t, filepath.Join(l.BinDirs[0], "openvpn"))

	got := procmgr.DaemonBin("openvpn")
	want := filepath.Join(l.BinDirs[0], "openvpn")
	if got != want {
		t.Errorf("DaemonBin(openvpn) = %q, want the adopted path %q", got, want)
	}
}
