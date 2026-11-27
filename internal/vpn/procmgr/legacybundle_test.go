package procmgr

// The legacy-layout seam: detection over a fake filesystem (injected layout +
// real files in a temp dir), the resolution order behind the BundleProvider
// seam, and the two create-only link repairs. Pure — no database, no daemon,
// no host paths: the layout is repointed at t.TempDir for every case.

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"
)

// withTempLegacyLayout repoints the legacy layout at a throwaway directory
// with the well-known shape but empty — nothing detected until the test
// creates files in it. Restored on cleanup so the other tests' lookups (and
// the next test) see the real, expect-absent defaults.
func withTempLegacyLayout(t *testing.T) *LegacyLayout {
	t.Helper()
	root := t.TempDir()
	l := &LegacyLayout{
		BinDirs:            []string{filepath.Join(root, "bin")},
		AccelRoot:          filepath.Join(root, "accel"),
		StrongswanRoot:     filepath.Join(root, "strongswan"),
		PppdRoot:           filepath.Join(root, "libexec"),
		SystemPppd:         filepath.Join(root, "usr", "sbin", "pppd"),
		PptpCtrlLink:       filepath.Join(root, "libexec", "pptpctrl"),
		StrongswanIpsecDir: filepath.Join(root, "usr", "lib", "ipsec"),
	}
	SetLegacyLayout(l)
	t.Cleanup(func() { SetLegacyLayout(DefaultLegacyLayout()) })
	return l
}

// touch creates an executable-looking file (and its parents).
func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func sortedCores(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for c := range m {
		out = append(out, c)
	}
	slices.Sort(out)
	return out
}

func TestDetectLegacyCores(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, l *LegacyLayout)
		want  []string
	}{
		{
			name:  "clean host detects nothing",
			build: func(t *testing.T, l *LegacyLayout) {},
			want:  nil,
		},
		{
			name: "flat dial-in daemons",
			build: func(t *testing.T, l *LegacyLayout) {
				touch(t, filepath.Join(l.BinDirs[0], "xl2tpd"))
				touch(t, filepath.Join(l.BinDirs[0], "pptpd"))
				touch(t, filepath.Join(l.BinDirs[0], "openvpn"))
				touch(t, filepath.Join(l.BinDirs[0], "ocserv"))
			},
			want: []string{"l2tp", "openvpn", "openconnect", "pptp"},
		},
		{
			name: "accel tree only serves sstp",
			build: func(t *testing.T, l *LegacyLayout) {
				touch(t, filepath.Join(l.AccelRoot, LegacyAccelPppdRel))
			},
			want: []string{"sstp"},
		},
		{
			name: "strongswan tree only serves ikev2",
			build: func(t *testing.T, l *LegacyLayout) {
				touch(t, filepath.Join(l.StrongswanRoot, LegacyCharonRel))
			},
			want: []string{"ikev2"},
		},
		{
			name: "full layout",
			build: func(t *testing.T, l *LegacyLayout) {
				for _, b := range []string{"xl2tpd", "pptpd", "openvpn", "ocserv", "telemt"} {
					touch(t, filepath.Join(l.BinDirs[0], b))
				}
				touch(t, filepath.Join(l.AccelRoot, LegacyAccelPppdRel))
				touch(t, filepath.Join(l.StrongswanRoot, LegacyCharonRel))
			},
			want: []string{"ikev2", "l2tp", "mtproto", "openconnect", "openvpn", "pptp", "sstp"},
		},
		{
			name: "a tree without its launcher counts for nothing",
			build: func(t *testing.T, l *LegacyLayout) {
				// Directory exists, launcher absent.
				if err := os.MkdirAll(filepath.Join(l.StrongswanRoot, "sbin"), 0o755); err != nil {
					t.Fatal(err)
				}
				touch(t, filepath.Join(l.AccelRoot, "bin", "accel-cmd"))
			},
			want: nil,
		},
		{
			name: "a directory is not a daemon",
			build: func(t *testing.T, l *LegacyLayout) {
				if err := os.MkdirAll(filepath.Join(l.BinDirs[0], "xl2tpd"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := withTempLegacyLayout(t)
			tc.build(t, l)
			// Compare as sets, in sorted order on BOTH sides: DetectLegacyCores
			// builds its answer from a map, so the observed order is
			// nondeterministic and a want written in detection order flakes.
			got := sortedCores(DetectLegacyCores())
			want := slices.Sorted(slices.Values(tc.want))
			if !slices.Equal(got, want) {
				t.Errorf("DetectLegacyCores() = %v, want %v", got, want)
			}
		})
	}
}

// overrideBundle stubs individual seam answers over the noop default, so the
// wrapper's "real provider wins" order is testable without a real bundle
// implementation.
type overrideBundle struct {
	BundleProvider
	daemonPath map[string]string
	strongswan bool
	ssRoot     string
	ssReady    bool
	ssConfDir  string
}

func (o *overrideBundle) DaemonPath(name string) string { return o.daemonPath[name] }
func (o *overrideBundle) HasStrongswanBundle() bool     { return o.strongswan }
func (o *overrideBundle) StrongswanBundleRoot() string  { return o.ssRoot }
func (o *overrideBundle) StrongswanBundleReady() bool   { return o.ssReady }
func (o *overrideBundle) StrongswanDefaultConfDir() string {
	return o.ssConfDir
}

func TestLegacyAwareBundleDaemonPath(t *testing.T) {
	l := withTempLegacyLayout(t)
	touch(t, filepath.Join(l.BinDirs[0], "xl2tpd"))
	touch(t, filepath.Join(l.BinDirs[0], "geoip.dat")) // stray non-daemon file

	// Real bundle wins even when the legacy layout has the same daemon.
	real := &overrideBundle{BundleProvider: noopBundle{}, daemonPath: map[string]string{
		"openvpn": "/new/bundle/openvpn",
	}}
	b := wrapLegacy(real)

	if got := b.DaemonPath("openvpn"); got != "/new/bundle/openvpn" {
		t.Errorf("real bundle answer overridden: got %q", got)
	}
	want := filepath.Join(l.BinDirs[0], "xl2tpd")
	if got := b.DaemonPath("xl2tpd"); got != want {
		t.Errorf("DaemonPath(xl2tpd) = %q, want legacy %q", got, want)
	}
	// A stray file in the old bin dir never satisfies a daemon lookup.
	if got := b.DaemonPath("geoip.dat"); got != "" {
		t.Errorf("DaemonPath(geoip.dat) = %q, want \"\" (not a daemon name)", got)
	}
	// Client-side artifacts never lived in the legacy bin dir; they must keep
	// falling through to PATH, not be captured by it.
	if got := b.DaemonPath("vpnc-script"); got != "" {
		t.Errorf("DaemonPath(vpnc-script) = %q, want \"\"", got)
	}
	if got := b.DaemonPath("nosuchdaemon"); got != "" {
		t.Errorf("DaemonPath(nosuchdaemon) = %q, want \"\"", got)
	}
}

func TestLegacyAwareBundleTreeLaunchers(t *testing.T) {
	l := withTempLegacyLayout(t)
	touch(t, filepath.Join(l.AccelRoot, LegacyAccelPppdRel))
	touch(t, filepath.Join(l.AccelRoot, LegacyAccelCmdRel))
	touch(t, filepath.Join(l.StrongswanRoot, LegacyCharonRel))
	touch(t, filepath.Join(l.StrongswanRoot, LegacySwanctlRel))
	touch(t, filepath.Join(l.StrongswanRoot, LegacyPkiRel))

	b := wrapLegacy(noopBundle{})
	for name, want := range map[string]string{
		"accel-pppd": filepath.Join(l.AccelRoot, LegacyAccelPppdRel),
		"accel-cmd":  filepath.Join(l.AccelRoot, LegacyAccelCmdRel),
		"charon":     filepath.Join(l.StrongswanRoot, LegacyCharonRel),
		"swanctl":    filepath.Join(l.StrongswanRoot, LegacySwanctlRel),
		"pki":        filepath.Join(l.StrongswanRoot, LegacyPkiRel),
	} {
		if got := b.AccelBinPath(name); got != want && (name == "accel-pppd" || name == "accel-cmd") {
			t.Errorf("AccelBinPath(%s) = %q, want %q", name, got, want)
		}
		if got := b.StrongswanBinPath(name); got != want && (name == "charon" || name == "swanctl" || name == "pki") {
			t.Errorf("StrongswanBinPath(%s) = %q, want %q", name, got, want)
		}
	}
	if got := b.AccelBinPath("ocserv"); got != "" {
		t.Errorf("AccelBinPath(ocserv) = %q, want \"\"", got)
	}
	if got := b.StrongswanBinPath("ocserv"); got != "" {
		t.Errorf("StrongswanBinPath(ocserv) = %q, want \"\"", got)
	}

	// A missing launcher reads as absent even though the tree dir exists.
	if err := os.Remove(filepath.Join(l.StrongswanRoot, LegacyCharonRel)); err != nil {
		t.Fatal(err)
	}
	if got := b.StrongswanBinPath("charon"); got != "" {
		t.Errorf("StrongswanBinPath(charon) after removal = %q, want \"\"", got)
	}
	if b.HasStrongswanBundle() {
		t.Error("HasStrongswanBundle must be false without the charon launcher")
	}
}

func TestLegacyStrongswanSeamRealBundleWins(t *testing.T) {
	withTempLegacyLayout(t)
	real := &overrideBundle{
		BundleProvider: noopBundle{},
		strongswan:     true,
		ssRoot:         "/new/strongswan",
		ssReady:        false, // embedded but not yet extracted
		ssConfDir:      "/new/strongswan/share/strongswan/strongswan.d",
	}
	b := wrapLegacy(real)

	if !b.HasStrongswanBundle() {
		t.Error("HasStrongswanBundle lost the real bundle's answer")
	}
	if got := b.StrongswanBundleRoot(); got != "/new/strongswan" {
		t.Errorf("StrongswanBundleRoot = %q, want the real bundle root", got)
	}
	// Not extracted yet, and no legacy tree either way on this host: the real
	// answer stands so ensureCharonRunning still extracts.
	if b.StrongswanBundleReady() {
		t.Error("StrongswanBundleReady must not claim ready before the real extract")
	}
	if got := b.StrongswanDefaultConfDir(); got != real.ssConfDir {
		t.Errorf("StrongswanDefaultConfDir = %q, want the real bundle's", got)
	}
}

func TestLegacyUsingBundledPppd(t *testing.T) {
	cases := []struct {
		name    string
		build   func(t *testing.T, l *LegacyLayout)
		want    bool
		wantPpp bool // PppdBundledPath resolves
	}{
		{
			name:    "no tree, no system pppd",
			build:   func(t *testing.T, l *LegacyLayout) {},
			want:    false,
			wantPpp: false,
		},
		{
			name: "tree and no system pppd: use the bundle",
			build: func(t *testing.T, l *LegacyLayout) {
				touch(t, filepath.Join(l.PppdRoot, LegacyPppdRel))
			},
			want:    true,
			wantPpp: true,
		},
		{
			name: "tree but a real system pppd: never shadow it",
			build: func(t *testing.T, l *LegacyLayout) {
				touch(t, filepath.Join(l.PppdRoot, LegacyPppdRel))
				touch(t, l.SystemPppd)
			},
			want:    false,
			wantPpp: true,
		},
		{
			name: "our own symlink still counts as bundled",
			build: func(t *testing.T, l *LegacyLayout) {
				bundled := filepath.Join(l.PppdRoot, LegacyPppdRel)
				touch(t, bundled)
				if err := os.MkdirAll(filepath.Dir(l.SystemPppd), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(bundled, l.SystemPppd); err != nil {
					t.Fatal(err)
				}
			},
			want:    true,
			wantPpp: true,
		},
		{
			name: "a symlink at some other pppd is a host pppd",
			build: func(t *testing.T, l *LegacyLayout) {
				touch(t, filepath.Join(l.PppdRoot, LegacyPppdRel))
				other := filepath.Join(l.PppdRoot, "other-pppd")
				touch(t, other)
				if err := os.MkdirAll(filepath.Dir(l.SystemPppd), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, l.SystemPppd); err != nil {
					t.Fatal(err)
				}
			},
			want:    false,
			wantPpp: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := withTempLegacyLayout(t)
			tc.build(t, l)
			b := wrapLegacy(noopBundle{})
			if got := b.UsingBundledPppd(); got != tc.want {
				t.Errorf("UsingBundledPppd() = %v, want %v", got, tc.want)
			}
			got := b.PppdBundledPath()
			if tc.wantPpp != (got != "") {
				t.Errorf("PppdBundledPath() = %q, wantPpp=%v", got, tc.wantPpp)
			}
		})
	}
}

func TestLegacyOpenSSLModulesDir(t *testing.T) {
	l := withTempLegacyLayout(t)
	b := wrapLegacy(noopBundle{})
	if got := b.OpenSSLModulesDir(); got != "" {
		t.Errorf("OpenSSLModulesDir without a tree = %q, want \"\"", got)
	}
	want := filepath.Join(l.PppdRoot, LegacyOsslModulesRel)
	if err := os.MkdirAll(want, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := b.OpenSSLModulesDir(); got != want {
		t.Errorf("OpenSSLModulesDir = %q, want %q", got, want)
	}
}

func TestLegacyStrongswanReadyAndConfDir(t *testing.T) {
	l := withTempLegacyLayout(t)
	b := wrapLegacy(noopBundle{})
	if b.StrongswanBundleReady() {
		t.Error("no tree: StrongswanBundleReady must be false")
	}
	touch(t, filepath.Join(l.StrongswanRoot, LegacyCharonRel))
	if !b.StrongswanBundleReady() {
		t.Error("tree with launcher: StrongswanBundleReady must be true")
	}
	if got := b.StrongswanBundleRoot(); got != l.StrongswanRoot {
		t.Errorf("StrongswanBundleRoot = %q, want %q", got, l.StrongswanRoot)
	}
	if got := b.StrongswanDefaultConfDir(); got != "" {
		t.Errorf("StrongswanDefaultConfDir without share dir = %q, want \"\"", got)
	}
	want := filepath.Join(l.StrongswanRoot, LegacySwanConfRel)
	if err := os.MkdirAll(want, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := b.StrongswanDefaultConfDir(); got != want {
		t.Errorf("StrongswanDefaultConfDir = %q, want %q", got, want)
	}
}

// The manifest is redirected so the repair tests record nowhere near /etc.
func redirectManifest(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	manifest.SetManifestPath(filepath.Join(dir, "ownership.json"), filepath.Join(dir, "backups"))
	t.Cleanup(manifest.Reset)
}

func TestLegacyLinkPptpCtrl(t *testing.T) {
	l := withTempLegacyLayout(t)
	redirectManifest(t)
	b := wrapLegacy(noopBundle{})

	// No legacy pptpctrl: nothing to do, no error.
	if err := b.LinkPptpCtrl(); err != nil {
		t.Fatalf("LinkPptpCtrl with no pptpctrl: %v", err)
	}
	if _, err := os.Lstat(l.PptpCtrlLink); err == nil {
		t.Error("a link was created without a legacy pptpctrl to point at")
	}

	target := filepath.Join(l.BinDirs[0], "pptpctrl")
	touch(t, target)
	if err := b.LinkPptpCtrl(); err != nil {
		t.Fatalf("LinkPptpCtrl: %v", err)
	}
	got, err := os.Readlink(l.PptpCtrlLink)
	if err != nil || got != target {
		t.Errorf("link = %q (err %v), want -> %q", got, err, target)
	}
	// Idempotent: the second run must not touch the existing link.
	if err := b.LinkPptpCtrl(); err != nil {
		t.Fatalf("second LinkPptpCtrl: %v", err)
	}
	if got, err := os.Readlink(l.PptpCtrlLink); err != nil || got != target {
		t.Errorf("second run changed the link: %q (err %v)", got, err)
	}
}

func TestLegacyLinkPptpCtrlNeverOverwritesARealFile(t *testing.T) {
	l := withTempLegacyLayout(t)
	redirectManifest(t)
	touch(t, filepath.Join(l.BinDirs[0], "pptpctrl"))

	touch(t, l.PptpCtrlLink)
	if err := os.WriteFile(l.PptpCtrlLink, []byte("host own file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := wrapLegacy(noopBundle{})
	if err := b.LinkPptpCtrl(); err != nil {
		t.Fatalf("LinkPptpCtrl: %v", err)
	}
	data, err := os.ReadFile(l.PptpCtrlLink)
	if err != nil || string(data) != "host own file\n" {
		t.Errorf("the host's own file at the link path was overwritten: %q (err %v)", data, err)
	}
}

func TestLegacyLinkStrongswanIpsecDir(t *testing.T) {
	l := withTempLegacyLayout(t)
	redirectManifest(t)
	b := wrapLegacy(noopBundle{})

	// No tree: nothing to do, no error.
	if err := b.LinkStrongswanIpsecDir(); err != nil {
		t.Fatalf("LinkStrongswanIpsecDir with no tree: %v", err)
	}

	mirror := filepath.Join(l.StrongswanRoot, LegacyIpsecLibRel)
	if err := os.MkdirAll(mirror, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := b.LinkStrongswanIpsecDir(); err != nil {
		t.Fatalf("LinkStrongswanIpsecDir: %v", err)
	}
	got, err := os.Readlink(l.StrongswanIpsecDir)
	if err != nil || got != mirror {
		t.Errorf("link = %q (err %v), want -> %q", got, err, mirror)
	}
	// Idempotent: the second run must leave it alone.
	if err := b.LinkStrongswanIpsecDir(); err != nil {
		t.Fatalf("second LinkStrongswanIpsecDir: %v", err)
	}
	if got, err := os.Readlink(l.StrongswanIpsecDir); err != nil || got != mirror {
		t.Errorf("second run changed the link: %q (err %v)", got, err)
	}

	// A host strongSwan's real dir at the compiled-in path is never touched.
	if err := os.Remove(l.StrongswanIpsecDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(l.StrongswanIpsecDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := b.LinkStrongswanIpsecDir(); err != nil {
		t.Fatalf("LinkStrongswanIpsecDir over a host dir: %v", err)
	}
	st, err := os.Lstat(l.StrongswanIpsecDir)
	if err != nil || st.Mode()&os.ModeSymlink != 0 {
		t.Errorf("the host's own ipsec dir was replaced (isDir=%v err=%v)", err == nil && st.IsDir(), err)
	}
}

func TestRepairLegacyLinks(t *testing.T) {
	l := withTempLegacyLayout(t)
	redirectManifest(t)

	touch(t, filepath.Join(l.BinDirs[0], "pptpctrl"))
	if err := os.MkdirAll(filepath.Join(l.StrongswanRoot, LegacyIpsecLibRel), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := RepairLegacyLinks(); err != nil {
		t.Fatalf("RepairLegacyLinks: %v", err)
	}
	if _, err := os.Readlink(l.PptpCtrlLink); err != nil {
		t.Errorf("pptpctrl link missing after repair: %v", err)
	}
	if _, err := os.Readlink(l.StrongswanIpsecDir); err != nil {
		t.Errorf("ipsec dir link missing after repair: %v", err)
	}
}

func TestSetBundleProviderKeepsLegacyFallback(t *testing.T) {
	l := withTempLegacyLayout(t)
	touch(t, filepath.Join(l.BinDirs[0], "openvpn"))

	SetBundleProvider(noopBundle{})
	t.Cleanup(func() { SetBundleProvider(noopBundle{}) })

	b := Bundles()
	if _, ok := b.(*legacyAwareBundle); !ok {
		t.Fatalf("Bundles() = %T, want a legacy-aware wrapper", b)
	}
	// Re-setting with the wrapper itself must not wrap twice.
	if again := wrapLegacy(b); again != b {
		t.Error("wrapping a legacy-aware provider must be a no-op")
	}
	if got := b.DaemonPath("openvpn"); got != filepath.Join(l.BinDirs[0], "openvpn") {
		t.Errorf("global DaemonPath(openvpn) = %q, want the legacy path", got)
	}
}
