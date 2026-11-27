// Legacy daemon adoption: resolution-level support for the daemon bundle the
// PREVIOUS panel generation installed on a host it was later upgraded on.
//
// The old generation extracted its flat daemons next to its own executable
// (/opt/pxpanel/bin) and unpacked the relocatable accel-ppp / strongSwan / pppd
// trees under /usr/libexec/pxpanel-*. On a host upgraded in place those
// binaries are all still there and still work, but neither the recorded
// provisioned-core set (coresettings) nor the bundle seam knows about them, so
// every daemon-backed core reads "not installed" and nothing can be started.
//
// The fix is resolution-side, not filesystem-side: this file describes the
// legacy layout, detects which cores it can still serve, and chains the layout
// BEHIND the active BundleProvider (real bundle → legacy layout → distro PATH,
// the same order everywhere). Nothing is copied or symlinked into the current
// install's layout — the relocatable trees are patchelf'd/loader-wrapper
// launchers whose compiled-in paths only resolve in place, so adopting them
// means pointing resolution at them, not moving them. The two symlinks the old
// provisioning itself maintained (pptpd's compiled-in pptpctrl path and
// charon's compiled-in /usr/lib/ipsec lib dir) are repaired create-only when
// they went missing, exactly as the old install maintained them.
//
// The one-time record of the scan (the settings flag + the adopted cores
// joining the provisioned set) lives in coresettings, which owns that KV;
// everything here is stateless so repeated calls are naturally idempotent.
package procmgr

import (
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/ImSoheilPx/pxpanel/internal/vpn/log"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"
)

// LegacyLayout describes one previous-generation daemon layout. Only the
// absolute roots differ between deployments; the entry points inside the
// relocatable trees are the same bundle-build contract in both generations
// (constants below).
type LegacyLayout struct {
	// BinDirs are the flat daemon directories. The old panel extracted its
	// flat binaries into the bin/ folder next to its own executable.
	BinDirs []string

	// AccelRoot / StrongswanRoot / PppdRoot are the relocatable trees
	// (accel-ppp for SSTP, strongSwan/charon for IKEv2 + L2TP/IPsec, pppd for
	// the MS-CHAP/MPPE legacy provider).
	AccelRoot      string
	StrongswanRoot string
	PppdRoot       string

	// SystemPppd is where xl2tpd/pptpd exec pppd from (compiled-in). The old
	// install symlinked it at its bundled pppd when the host had none.
	SystemPppd string

	// PptpCtrlLink is the path pptpd was compiled to exec pptpctrl from; the
	// old provisioning kept it linked at the extracted pptpctrl.
	PptpCtrlLink string

	// StrongswanIpsecDir is charon's compiled-in lib+plugin dir, which the old
	// install symlinked at the tree's mirror (StrongswanRoot/lib/ipsec).
	StrongswanIpsecDir string
}

// Entry points inside the relocatable trees. Both bundle generations used the
// same tree shapes (sbin/<daemon> launchers, lib/ module dirs), so these are
// constants of the layout contract rather than per-deployment fields.
const (
	LegacyAccelPppdRel   = "sbin/accel-pppd"
	LegacyAccelCmdRel    = "bin/accel-cmd"
	LegacyCharonRel      = "sbin/charon"
	LegacySwanctlRel     = "sbin/swanctl"
	LegacyPkiRel         = "bin/pki"
	LegacyPppdRel        = "sbin/pppd"
	LegacyOsslModulesRel = "lib/ossl-modules"
	LegacyIpsecLibRel    = "lib/ipsec"
	LegacySwanConfRel    = "share/strongswan/strongswan.d"
)

// DefaultLegacyLayout returns the well-known locations of the previous panel
// generation's daemon bundle (the layout its install lived at).
func DefaultLegacyLayout() *LegacyLayout {
	return &LegacyLayout{
		BinDirs:            []string{"/opt/pxpanel/bin"},
		AccelRoot:          "/usr/libexec/pxpanel-accel",
		StrongswanRoot:     "/usr/libexec/pxpanel-strongswan",
		PppdRoot:           "/usr/libexec/pxpanel",
		SystemPppd:         "/usr/sbin/pppd",
		PptpCtrlLink:       "/usr/libexec/pxpanel/pptpctrl",
		StrongswanIpsecDir: "/usr/lib/ipsec",
	}
}

// activeLayout holds the layout detection and resolution consult. Swapped only
// via SetLegacyLayout.
var activeLayout atomic.Pointer[LegacyLayout]

func init() { activeLayout.Store(DefaultLegacyLayout()) }

// SetLegacyLayout points legacy detection/resolution at a different layout.
// TEST-ONLY seam (the same pattern as manifest.SetManifestPath): the real
// locations are fixed at build time and product code must never call this.
// Passing nil restores the default.
func SetLegacyLayout(l *LegacyLayout) {
	if l == nil {
		l = DefaultLegacyLayout()
	}
	activeLayout.Store(l)
}

func currentLegacyLayout() *LegacyLayout { return activeLayout.Load() }

// legacyFlatDaemons are the flat daemon names the previous generation
// extracted into its bin dir. Resolution is restricted to this manifest so a
// stray file in the old directory (geo data, a leftover tarball) can never
// satisfy a daemon lookup, and client-side artifacts (which never lived there)
// keep falling through to PATH.
var legacyFlatDaemons = map[string]bool{
	"xl2tpd":         true,
	"xl2tpd-control": true,
	"openvpn":        true,
	"pptpd":          true,
	"pptpctrl":       true,
	"ocserv":         true,
	"ocserv-worker":  true,
	"occtl":          true,
	"telemt":         true,
}

// legacyFileExists reports whether path exists as a launchable file — a
// regular file or a symlink to one. A directory does not count.
func legacyFileExists(path string) bool {
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// legacyFlatBinPath resolves name inside the layout's flat bin dirs, or "".
func legacyFlatBinPath(l *LegacyLayout, name string) string {
	if !legacyFlatDaemons[name] {
		return ""
	}
	for _, dir := range l.BinDirs {
		if dir == "" {
			continue
		}
		p := filepath.Join(dir, name)
		if legacyFileExists(p) {
			return p
		}
	}
	return ""
}

// detectLegacyCores maps a layout onto the catalog cores it can still serve,
// keyed by core name. A core counts only when its PRIMARY daemon is present:
// the companion binaries (pptpctrl, ocserv-worker, occtl, xl2tpd-control) ride
// along with it and the flat resolution above serves them by name.
func detectLegacyCores(l *LegacyLayout, exists func(string) bool) map[string]bool {
	found := map[string]bool{}
	flat := func(bin, core string) {
		for _, dir := range l.BinDirs {
			if dir != "" && exists(filepath.Join(dir, bin)) {
				found[core] = true
				return
			}
		}
	}
	flat("xl2tpd", "l2tp")
	flat("pptpd", "pptp")
	flat("openvpn", "openvpn")
	flat("ocserv", "openconnect")
	flat("telemt", "mtproto")
	if exists(filepath.Join(l.AccelRoot, LegacyAccelPppdRel)) {
		found["sstp"] = true
	}
	if exists(filepath.Join(l.StrongswanRoot, LegacyCharonRel)) {
		found["ikev2"] = true
	}
	return found
}

// DetectLegacyCores reports which catalog cores the previous generation's
// daemon bundle can still serve on this host. The coresettings adoption scan
// records the answer once; the resolution layer consults the layout directly
// on every lookup, so the two can never drift.
func DetectLegacyCores() map[string]bool {
	return detectLegacyCores(currentLegacyLayout(), legacyFileExists)
}

// ---------------------------------------------------------------------------
//  The resolution seam
// ---------------------------------------------------------------------------

// legacyAwareBundle chains the legacy layout behind an active bundle provider:
// every seam answers from the real provider first and falls back to the
// previous generation's locations when the real one has nothing. The seams
// WITHOUT a legacy analogue (the libreswan/pluto bundle family, distro-unit
// knowledge) pass straight through — the confirmed upgraded hosts run the
// strongSwan tree, and claiming a libreswan bundle that was never there would
// wrongly gate the distro ipsec.service teardown.
type legacyAwareBundle struct {
	real BundleProvider
}

// wrapLegacy chains the legacy fallback behind b unless b already carries it.
func wrapLegacy(b BundleProvider) BundleProvider {
	if _, ok := b.(*legacyAwareBundle); ok {
		return b
	}
	return &legacyAwareBundle{real: b}
}

func (b *legacyAwareBundle) DaemonPath(name string) string {
	if p := b.real.DaemonPath(name); p != "" {
		return p
	}
	return legacyFlatBinPath(currentLegacyLayout(), name)
}

func (b *legacyAwareBundle) AccelBinPath(name string) string {
	if p := b.real.AccelBinPath(name); p != "" {
		return p
	}
	l := currentLegacyLayout()
	var rel string
	switch name {
	case "accel-pppd":
		rel = LegacyAccelPppdRel
	case "accel-cmd":
		rel = LegacyAccelCmdRel
	default:
		return ""
	}
	p := filepath.Join(l.AccelRoot, rel)
	if legacyFileExists(p) {
		return p
	}
	return ""
}

func (b *legacyAwareBundle) StrongswanBinPath(name string) string {
	if p := b.real.StrongswanBinPath(name); p != "" {
		return p
	}
	l := currentLegacyLayout()
	var rel string
	switch name {
	case "charon":
		rel = LegacyCharonRel
	case "swanctl":
		rel = LegacySwanctlRel
	case "pki":
		rel = LegacyPkiRel
	default:
		return ""
	}
	p := filepath.Join(l.StrongswanRoot, rel)
	if legacyFileExists(p) {
		return p
	}
	return ""
}

// legacyUsingBundledPppd mirrors the old bundle's rule: use the legacy pppd
// tree only when it is on disk AND the host has no system pppd of its own (a
// distro pppd's OpenSSL providers differ and must not be overridden) — except
// when the system path is our own symlink at the tree, which still counts.
func legacyUsingBundledPppd(l *LegacyLayout) bool {
	bundled := filepath.Join(l.PppdRoot, LegacyPppdRel)
	if !legacyFileExists(bundled) {
		return false
	}
	if dest, err := os.Readlink(l.SystemPppd); err == nil {
		return dest == bundled
	}
	_, err := os.Stat(l.SystemPppd)
	return err != nil
}

func (b *legacyAwareBundle) UsingBundledPppd() bool {
	return b.real.UsingBundledPppd() || legacyUsingBundledPppd(currentLegacyLayout())
}

func (b *legacyAwareBundle) PppdBundledPath() string {
	if p := b.real.PppdBundledPath(); p != "" {
		return p
	}
	l := currentLegacyLayout()
	p := filepath.Join(l.PppdRoot, LegacyPppdRel)
	if legacyFileExists(p) {
		return p
	}
	return ""
}

func (b *legacyAwareBundle) OpenSSLModulesDir() string {
	if p := b.real.OpenSSLModulesDir(); p != "" {
		return p
	}
	l := currentLegacyLayout()
	p := filepath.Join(l.PppdRoot, LegacyOsslModulesRel)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

func (b *legacyAwareBundle) LinkPptpCtrl() error {
	if err := b.real.LinkPptpCtrl(); err != nil {
		return err
	}
	if b.real.DaemonPath("pptpd") != "" {
		return nil // a real bundle owns the compiled-in-path link
	}
	return linkLegacyPptpCtrl(currentLegacyLayout())
}

func (b *legacyAwareBundle) DistroUnitExists(name string) bool {
	return b.real.DistroUnitExists(name)
}

func (b *legacyAwareBundle) UsingBundledIpsec() bool {
	return b.real.UsingBundledIpsec()
}

func (b *legacyAwareBundle) HasStrongswanBundle() bool {
	return b.real.HasStrongswanBundle() || b.legacyStrongswanReady()
}

func (b *legacyAwareBundle) StrongswanBundleRoot() string {
	if p := b.real.StrongswanBundleRoot(); p != "" {
		return p
	}
	if b.legacyStrongswanReady() {
		return currentLegacyLayout().StrongswanRoot
	}
	return ""
}

func (b *legacyAwareBundle) LibreswanBundleRoot() string {
	return b.real.LibreswanBundleRoot()
}

func (b *legacyAwareBundle) IpsecBundledPath() string {
	return b.real.IpsecBundledPath()
}

func (b *legacyAwareBundle) PlutoBundledPath() string {
	return b.real.PlutoBundledPath()
}

func (b *legacyAwareBundle) LibreswanNssDir() string {
	return b.real.LibreswanNssDir()
}

func (b *legacyAwareBundle) LibreswanBundleReady() bool {
	return b.real.LibreswanBundleReady()
}

func (b *legacyAwareBundle) ExtractLibreswanBundle() error {
	return b.real.ExtractLibreswanBundle()
}

// legacyStrongswanReady reports whether the legacy strongSwan tree is on disk
// with its charon launcher — the same "tree already extracted" answer the real
// provider gives for its own root.
func (b *legacyAwareBundle) legacyStrongswanReady() bool {
	return legacyFileExists(filepath.Join(currentLegacyLayout().StrongswanRoot, LegacyCharonRel))
}

func (b *legacyAwareBundle) StrongswanBundleReady() bool {
	if b.real.HasStrongswanBundle() {
		return b.real.StrongswanBundleReady()
	}
	return b.legacyStrongswanReady()
}

func (b *legacyAwareBundle) ExtractStrongswanBundle() error {
	// The legacy tree is already on disk — there is nothing to extract for it,
	// and re-extracting over a running charon would overwrite mmap'd .so files.
	return b.real.ExtractStrongswanBundle()
}

func (b *legacyAwareBundle) LinkStrongswanIpsecDir() error {
	if err := b.real.LinkStrongswanIpsecDir(); err != nil {
		return err
	}
	if b.real.HasStrongswanBundle() {
		return nil // a real bundle owns the compiled-in-path link
	}
	return linkLegacyStrongswanIpsecDir(currentLegacyLayout())
}

func (b *legacyAwareBundle) StrongswanDefaultConfDir() string {
	if p := b.real.StrongswanDefaultConfDir(); p != "" {
		return p
	}
	l := currentLegacyLayout()
	p := filepath.Join(l.StrongswanRoot, LegacySwanConfRel)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// ---------------------------------------------------------------------------
//  The two compiled-in-path symlinks the old provisioning maintained
// ---------------------------------------------------------------------------

// linkLegacyPptpCtrl points pptpd's compiled-in pptpctrl path at the legacy
// tree's pptpctrl when the link is missing. Create-only: an existing symlink
// (the old install's own, still valid) and a real file (a host pptpctrl) are
// both left exactly where they are.
func linkLegacyPptpCtrl(l *LegacyLayout) error {
	target := legacyFlatBinPath(l, "pptpctrl")
	if target == "" {
		return nil
	}
	if _, err := os.Lstat(l.PptpCtrlLink); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(l.PptpCtrlLink), 0o755); err != nil {
		return err
	}
	manifest.PrepareSymlink(l.PptpCtrlLink, target, "pptp")
	if err := os.Symlink(target, l.PptpCtrlLink); err != nil {
		return err
	}
	log.Info("legacy adoption: linked", l.PptpCtrlLink, "at the previous install's pptpctrl")
	return nil
}

// linkLegacyStrongswanIpsecDir points charon's compiled-in lib+plugin dir at
// the legacy tree's mirror when it is missing, so the absolute-path plugin
// dlopens resolve. Create-only, like the link above.
func linkLegacyStrongswanIpsecDir(l *LegacyLayout) error {
	src := filepath.Join(l.StrongswanRoot, LegacyIpsecLibRel)
	if _, err := os.Stat(src); err != nil {
		return nil // no tree (or no mirror inside it): nothing to link at
	}
	if _, err := os.Lstat(l.StrongswanIpsecDir); err == nil {
		return nil // host strongSwan's dir, or the old install's own link
	}
	if err := os.MkdirAll(filepath.Dir(l.StrongswanIpsecDir), 0o755); err != nil {
		return err
	}
	manifest.PrepareSymlink(l.StrongswanIpsecDir, src, "ikev2")
	if err := os.Symlink(src, l.StrongswanIpsecDir); err != nil {
		return err
	}
	log.Info("legacy adoption: linked", l.StrongswanIpsecDir, "at the previous install's strongSwan tree")
	return nil
}

// RepairLegacyLinks re-creates the two compiled-in-path symlinks the previous
// install relied on when they went missing. Idempotent and create-only; a
// no-op on a host with no legacy layout (and a no-op again on every later
// call, since an existing link is never touched).
func RepairLegacyLinks() error {
	l := currentLegacyLayout()
	if err := linkLegacyPptpCtrl(l); err != nil {
		return err
	}
	return linkLegacyStrongswanIpsecDir(l)
}
