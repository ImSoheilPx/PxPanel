// Wiring of the foundation seams the README reserved for this wave
// (TODO(core wave) markers in procmgr/manifest/pkgmgr):
//
//   - procmgr.InstalledCoresFunc  — the orphan-reap in MigrateFromSystemd only
//     touches units of cores this host actually installed;
//   - manifest.InstalledCoresFunc — the OwnSynthesize survey;
//   - manifest.CoreArtifactPathsFunc — per-core uninstall paths/globs for the
//     manifest's evidence-based backfill.
//
// All three read the catalog-driven provisioned set (settings.go rows +
// provisionBaseline fallback), exactly where vpn-ui read
// CoreService.provisionedProtocolSet. pkgmgr.RequiredModulesFor keeps its flat
// approximation for now — upgrading it to the per-core catalog lists is the
// pkgmgr file's edit (the catalog lists live in catalog.go here and this
// package uses them directly).
//
// Wired from init() like the ipsec wave populates pkgmgr.IpsecHooks: importing
// this package (the controllers/web wave does, alongside its other core
// settings wiring) installs the hooks; a build that does not link coresettings
// keeps the nil-hook behaviour.
package coresettings

import (
	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"
)

func init() {
	procmgr.InstalledCoresFunc = provisionedSetForHooks
	manifest.InstalledCoresFunc = provisionedSetForHooks
	manifest.CoreArtifactPathsFunc = CoreArtifactPaths
}

// provisionedSetForHooks is the hook shape of the installed set: catalog keys,
// bool values. Errors inside degrade to an empty set, which every caller
// already treats as "cannot tell" / "nothing installed" rather than fatal.
func provisionedSetForHooks() map[string]bool {
	var s CoreService // zero-value usable; the reads are stateless
	return s.provisionedProtocolSet()
}
