// Legacy daemon adoption: the one-time record that makes the previous panel
// generation's daemons count as installed. The resolution half (finding the
// daemons, answering DaemonBin/BundleProvider for them) lives in procmgr's
// legacybundle.go; this file owns the two things only the settings KV can do:
//
//   - the run-once flag (legacyDaemonsAdopted), so the scan happens exactly
//     once per install and can never resurrect a core the operator later
//     removed on purpose;
//   - the adopted cores joining the provisioned set, so the Core Settings
//     cards, the inbound-creation gate and the uninstall arithmetic all treat
//     an adopted host as what it is: set up, without a re-run of Provision.
//
// The scan runs at the first provisioned-set read after the database is wired.
// On the boot path that is the ownership survey (manifest.OwnSynthesize reads
// the installed set before any Init* runs), and on a UI-only path it is the
// first Core Settings render — either way before the operator sees a status.
// On a clean host (fresh install, or one where the new layout already ships
// every daemon) the scan finds nothing, writes the flag, and is a no-op.
package coresettings

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/log"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"
)

// keyLegacyDaemonsAdopted is the run-once flag. "true" is written after the
// first scan completes (even when it found nothing), so a clean host never
// rescans and an uninstalled core is never re-adopted on a later boot.
const keyLegacyDaemonsAdopted = "legacyDaemonsAdopted"

var (
	legacyAdoptDone atomic.Bool // set only after a scan WITH a database present
	legacyAdoptMu   sync.Mutex
)

// ensureLegacyAdoption runs the one-time legacy scan. Safe to call from every
// provisioned-set reader: cheap no-op once done, and a no-op that RETRIES
// later while the database is not wired yet (setting the flag before a scan
// could actually run would lose the adoption for good).
func ensureLegacyAdoption() {
	if legacyAdoptDone.Load() {
		return
	}
	if vpn.DB() == nil {
		return
	}
	legacyAdoptMu.Lock()
	defer legacyAdoptMu.Unlock()
	if legacyAdoptDone.Load() {
		return
	}
	adoptLegacyDaemons()
	legacyAdoptDone.Store(true)
}

// adoptLegacyDaemons performs the scan and its two writes. Best-effort: a
// failed write is logged and the scan is not retried (the resolution layer
// still resolves the adopted daemons regardless; only the recorded set would
// lag until the operator runs Provision).
func adoptLegacyDaemons() {
	found := procmgr.DetectLegacyCores()
	if len(found) == 0 {
		// Fresh install on a clean host, or a host where the old daemons were
		// already cleaned up: nothing to adopt.
		setLegacyAdoptedFlag()
		return
	}

	// The adopted cores join the recorded set ADDITIVELY: whatever the
	// operator already installed (or a pre-tracking upgrade's baseline) stays,
	// and nothing recorded is dropped. One known edge: a host where the
	// operator uninstalled a core on the NEW panel before upgrading still has
	// that core's legacy binaries on disk (the old layout is not catalog-owned
	// and uninstall leaves it alone), so it is re-adopted here. Uninstalling
	// it again removes it for good — the core is then genuinely gone.
	existing := GetProvisionedProtocols()
	union := make([]string, 0, len(existing)+len(found))
	union = append(union, existing...)
	for core := range found {
		union = append(union, core)
	}
	ordered := orderedCoreNames(union)
	if err := SetProvisionedProtocols(ordered); err != nil {
		log.Warning("legacy adoption: could not record the adopted cores:", err)
	}
	// The host WAS provisioned — by the previous install, which left working
	// daemons, loaded kernel modules and IP forwarding behind. Recording that
	// keeps the setup call-to-action from claiming otherwise.
	if err := SetVpnProvisioned(true); err != nil {
		log.Warning("legacy adoption: could not record the provisioned flag:", err)
	}
	// Re-create the two compiled-in-path symlinks the old provisioning kept,
	// in case a cleanup or partial migration removed them. Create-only.
	if err := procmgr.RepairLegacyLinks(); err != nil {
		log.Warning("legacy adoption: link repair:", err)
	}
	log.Info("legacy adoption: adopted the previous install's daemons for cores:",
		strings.Join(ordered, ", "))
	setLegacyAdoptedFlag()
}

// setLegacyAdoptedFlag writes the run-once flag. It is written LAST: a failed
// write leaves the next boot to retry the (idempotent) scan instead of
// silently skipping adoption forever.
func setLegacyAdoptedFlag() {
	if err := settingPutString(keyLegacyDaemonsAdopted, "true"); err != nil {
		log.Warning("legacy adoption: could not record the run-once flag:", err)
	}
}

// LegacyAdoptionDone reports whether the one-time scan has already run on this
// install. Exported for the tests' benefit and for any future caller that
// needs to distinguish "never scanned" from "scanned, nothing found".
func LegacyAdoptionDone() bool { return legacyAdoptDone.Load() }

// ResetLegacyAdoptionForTest clears the run-once guard so a subsequent
// ensureLegacyAdoption scans again. TEST-ONLY seam — product code must never
// call it (the guard is what keeps an uninstall from being undone).
func ResetLegacyAdoptionForTest() { legacyAdoptDone.Store(false) }
