// Per-core uninstall. Ported from vpn-ui web/service/coreuninstall.go
// (verbatim, seams swapped: ownReleasePath→manifest.ReleasePath,
// ownReleaseEntry→manifest.Entries+Release, ownRemoveEntry→manifest.RemoveEntry,
// setCoreConfigOverrides→coreconfig.SetOverrides, removeAmneziawgModule→
// awg.RemoveAmneziawgModule).
//
// The rule that makes this safe is reference counting against what REMAINS
// installed, never against what is being removed. IPsec is the case that forces
// it: L2TP and IKEv2 both stand on the one bundled strongSwan/charon, so
// removing IKEv2 while L2TP is still installed must take IKEv2's own swanctl
// connections and config root and leave the charon bundle, the /usr/lib/ipsec
// link and the daemon itself completely alone. The same arithmetic covers pppd
// (L2TP + PPTP), the PPP kernel-modules package (L2TP + PPTP), and every module
// two cores happen to share.
//
// Distro packages are never removed, matching the whole-host Uninstall policy:
// the panel cannot know whether something else on the machine depends on
// libreswan or a kernel package it installed, so it reports them as kept.
package coresettings

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/awg"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/coreconfig"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/log"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"
)

// CoreUninstallReport records what removing one or more cores actually did.
type CoreUninstallReport struct {
	// Cores is the cores that were removed.
	Cores []string `json:"cores"`
	// Steps mirrors provisioning's step stream so the same live console can
	// render an uninstall.
	Steps []ProvisionStep `json:"steps"`
	// Kept is the shared requirements deliberately left in place, each with the
	// still-installed core that needs it. This is the operator-facing proof that
	// removing IKEv2 did not break L2TP.
	Kept []string `json:"kept"`
}

// coreUninstallRun holds the single in-flight or most recent uninstall, polled
// by the Core Settings page exactly like a provisioning run.
var coreUninstallRun struct {
	mu      sync.Mutex
	running bool
	done    bool
	steps   []ProvisionStep
	kept    []string
	cores   []string
}

// CoreUninstallState is a snapshot of the background uninstall run.
type CoreUninstallState struct {
	Running bool            `json:"running"`
	Done    bool            `json:"done"`
	Steps   []ProvisionStep `json:"steps"`
	Kept    []string        `json:"kept"`
	Cores   []string        `json:"cores"`
}

// CoreUninstallStatus returns the current/most-recent uninstall run's progress.
func (s *CoreService) CoreUninstallStatus() CoreUninstallState {
	coreUninstallRun.mu.Lock()
	defer coreUninstallRun.mu.Unlock()
	steps := make([]ProvisionStep, len(coreUninstallRun.steps))
	copy(steps, coreUninstallRun.steps)
	kept := make([]string, len(coreUninstallRun.kept))
	copy(kept, coreUninstallRun.kept)
	cores := make([]string, len(coreUninstallRun.cores))
	copy(cores, coreUninstallRun.cores)
	return CoreUninstallState{
		Running: coreUninstallRun.running,
		Done:    coreUninstallRun.done,
		Steps:   steps,
		Kept:    kept,
		Cores:   cores,
	}
}

// Inbound dispositions for a core uninstall. A core's inbounds cannot simply be
// ignored: the daemon serving them is about to be removed.
const (
	// InboundsBlock is the default and the only one that refuses. It exists so a
	// caller that never asked the question (the CLI, an old client) still cannot
	// silently strand inbounds.
	InboundsBlock = ""
	// InboundsDelete removes the core's inbounds along with it.
	InboundsDelete = "delete"
	// InboundsKeep leaves them in the database, deliberately non-functional, so
	// the operator can reinstall the core later and have them work again.
	InboundsKeep = "keep"
)

// InboundDeleteFunc is the seam for the full inbound deletion flow (vpn-ui:
// InboundService.DelInbound — per-protocol teardown, settings.clients mirror
// sync, xray config rebuild). It belongs to the inbound/controllers wave, which
// wires it at start-up. Unwired, the InboundsDelete disposition refuses rather
// than silently stranding half-torn-down state.
var InboundDeleteFunc func(id int) error

// CanUninstallCores reports whether the selection can be removed, given what the
// caller decided to do with any inbounds those cores still serve.
func (s *CoreService) CanUninstallCores(names []string, inbounds string) error {
	selected := validCoreNames(names)
	if len(selected) == 0 {
		return fmt.Errorf("no installable core selected")
	}
	installed := s.provisionedProtocolSet()
	counts := s.inboundCountsByCore()
	for _, n := range selected {
		if !installed[n] {
			return fmt.Errorf("%s is not installed", coreDisplayName(n))
		}
		// Only an undecided caller is refused. Once the operator has been shown
		// the choice and made it, both answers are legitimate: delete the
		// inbounds, or keep them and accept that they stop working until the
		// core is reinstalled.
		if counts[n] > 0 && inbounds != InboundsDelete && inbounds != InboundsKeep {
			return fmt.Errorf("%s still has %d inbound(s); choose whether to delete them or keep them",
				coreDisplayName(n), counts[n])
		}
	}
	return nil
}

// coreOwnedInbounds loads every inbound served by the given cores.
func coreOwnedInbounds(wanted map[string]bool) ([]model.Inbound, error) {
	db := vpn.DB()
	if db == nil {
		return nil, fmt.Errorf("no database")
	}
	var all []model.Inbound
	if err := db.Find(&all).Error; err != nil {
		return nil, err
	}
	var out []model.Inbound
	for _, in := range all {
		if wanted[protocolCoreName(string(in.Protocol))] {
			out = append(out, in)
		}
	}
	return out, nil
}

// deleteCoreInbounds removes every inbound served by the given cores. Used for
// the InboundsDelete disposition, before the daemons go away.
//
// PORT NOTE: vpn-ui went through InboundService.DelInbound, which also runs each
// protocol's own teardown and the accounts mirror sync. That flow is the
// inbound/controllers wave's; until it wires InboundDeleteFunc this refuses
// (see above) instead of leaving rows gone and mirror/config state behind.
func (s *CoreService) deleteCoreInbounds(names []string) (int, error) {
	if InboundDeleteFunc == nil {
		return 0, fmt.Errorf("inbound deletion is not wired yet (inbound/controllers wave); uninstall with inbounds=\"keep\" or delete them from the inbounds page first")
	}
	wanted := map[string]bool{}
	for _, n := range validCoreNames(names) {
		wanted[n] = true
	}
	all, err := coreOwnedInbounds(wanted)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, in := range all {
		if err := InboundDeleteFunc(in.Id); err != nil {
			return removed, fmt.Errorf("deleting inbound %q: %w", in.Remark, err)
		}
		removed++
	}
	return removed, nil
}

// StartCoreUninstall removes the given cores in the background, returning false
// if a provisioning or uninstall run is already in flight (they touch the same
// files, so they must not overlap).
func (s *CoreService) StartCoreUninstall(names []string, inbounds string) (bool, error) {
	if err := s.CanUninstallCores(names, inbounds); err != nil {
		return false, err
	}
	// EVERY refusal has to come before the first destructive act. Deleting the
	// inbounds used to happen up here, above these two checks, so a request that
	// arrived during a setup run (or alongside another uninstall) was refused AFTER
	// the inbounds were already gone: nothing was uninstalled and the operator's
	// inbounds were destroyed anyway.
	provisionRun.mu.Lock()
	provisioning := provisionRun.running
	provisionRun.mu.Unlock()
	if provisioning {
		return false, fmt.Errorf("setup is running; wait for it to finish")
	}

	coreUninstallRun.mu.Lock()
	if coreUninstallRun.running {
		coreUninstallRun.mu.Unlock()
		return false, fmt.Errorf("an uninstall is already running")
	}
	// Claim the run before deleting anything, so a second request cannot slip in
	// between the deletion and the flag being set.
	selected := validCoreNames(names)
	coreUninstallRun.running = true
	coreUninstallRun.mu.Unlock()

	// Delete BEFORE the daemons go, so the normal delete path still has a live
	// backend to tear each inbound's own state down with.
	if inbounds == InboundsDelete {
		if n, err := s.deleteCoreInbounds(names); err != nil {
			coreUninstallRun.mu.Lock()
			coreUninstallRun.running = false
			coreUninstallRun.mu.Unlock()
			return false, err
		} else if n > 0 {
			log.Info("core uninstall: deleted", n, "inbound(s) belonging to", names)
		}
	}

	coreUninstallRun.mu.Lock()
	coreUninstallRun.running = true
	coreUninstallRun.done = false
	coreUninstallRun.steps = nil
	coreUninstallRun.kept = nil
	coreUninstallRun.cores = selected
	coreUninstallRun.mu.Unlock()

	go func() {
		var cs CoreService
		kept := cs.runCoreUninstall(selected, func(st ProvisionStep) {
			coreUninstallRun.mu.Lock()
			coreUninstallRun.steps = append(coreUninstallRun.steps, st)
			coreUninstallRun.mu.Unlock()
		})
		coreUninstallRun.mu.Lock()
		coreUninstallRun.running = false
		coreUninstallRun.done = true
		coreUninstallRun.kept = kept
		coreUninstallRun.mu.Unlock()
	}()
	return true, nil
}

// UninstallCores removes cores synchronously and returns the full report. This
// is the collected form of StartCoreUninstall, for the CLI and for tests.
func (s *CoreService) UninstallCores(names []string, inbounds string) (*CoreUninstallReport, error) {
	if err := s.CanUninstallCores(names, inbounds); err != nil {
		return nil, err
	}
	selected := validCoreNames(names)
	rep := &CoreUninstallReport{Cores: selected}
	rep.Kept = s.runCoreUninstall(selected, func(st ProvisionStep) {
		rep.Steps = append(rep.Steps, st)
	})
	return rep, nil
}

// runCoreUninstall does the work and streams a step per action. It returns the
// shared requirements that were kept, each annotated with who still needs them.
//
// Order matters: stop the daemons before deleting the binaries and configs they
// are running from, and only then rewrite the host-level state (module persist,
// provisioned list) that describes what is left.
func (s *CoreService) runCoreUninstall(selected []string, emit func(ProvisionStep)) []string {
	removing := map[string]bool{}
	for _, n := range selected {
		removing[n] = true
	}
	// What survives. Every "may I remove this shared thing?" question is asked
	// of THIS set, which is the whole safety property.
	var remaining []string
	for _, n := range s.installedCoreNames() {
		if !removing[n] {
			remaining = append(remaining, n)
		}
	}
	// Everything deliberately left in place, from any step, with the reason. The
	// manifest-driven steps below add to it as well as the shared-feature step, so
	// an operator can see in one list both "IPsec stayed because L2TP needs it" and
	// "your /etc/ocserv stayed because it was here before pxpanel was".
	var kept []string

	// 1. Stop the daemons first, so nothing is executing from a path about to be
	//    unlinked and no supervisor restarts it mid-teardown.
	//
	//    Except where the daemon is SHARED and a surviving core still needs it.
	//    IKEv2 and L2TP/IPsec are one charon process, so StopCore("ikev2") would
	//    drop live L2TP tunnels as a side effect of removing IKEv2. In that case
	//    the daemon is left running and step 7 reloads it without the removed
	//    core's connections instead.
	for _, n := range selected {
		if keeper := sharedDaemonKeeper(n, remaining); keeper != "" {
			emit(ProvisionStep{
				Name: "stop " + coreDisplayName(n), OK: true,
				Msg: "left running: the same daemon still serves " + coreDisplayName(keeper),
			})
			continue
		}
		if err := s.StopCore(n); err != nil {
			// A core with nothing running reports an error here, which is the
			// normal case for an idle core: note it and carry on.
			emit(ProvisionStep{Name: "stop " + coreDisplayName(n), OK: true, Warn: true, Msg: err.Error()})
			continue
		}
		emit(ProvisionStep{Name: "stop " + coreDisplayName(n), OK: true, Msg: "stopped"})
	}

	// 2. The cores' own config files and per-inbound directories.
	//
	//    The catalog names the paths; the OWNERSHIP MANIFEST decides what may happen
	//    to each one. That split is the fix for the worst thing this function did:
	//    /etc/ocserv was removed wholesale, so uninstalling OpenConnect on a host
	//    with a distro ocserv deleted that ocserv's ocserv.conf, its certificates and
	//    its ocpasswd; /etc/openvpn/server, the distro's own server-config directory
	//    on Debian/Ubuntu/Fedora, went the same way even though the panel only ever
	//    mkdir's it and writes nothing inside. Both are now kept unless the manifest
	//    says we created them, and a shared file we overwrote is restored from its
	//    backup rather than deleted. See manifest.ReleasePath.
	handled := map[string]bool{}
	for _, n := range selected {
		spec := coreSpecFor(n)
		if spec == nil {
			continue
		}
		var removed []string
		release := func(p string) {
			if handled[p] {
				return // a path two cores both list is released once, by the first
			}
			handled[p] = true
			gone, left := manifest.ReleasePath(p, selected)
			if gone != "" {
				removed = append(removed, gone)
			}
			if left != "" {
				kept = append(kept, left)
			}
		}
		// Globs first: the per-inbound directories are OURS even when the root that
		// holds them is the distro's, so clearing them is what lets a shared root be
		// pruned (when we created it) or left tidy (when we did not).
		for _, g := range spec.globs {
			matches, _ := filepath.Glob(g)
			for _, m := range matches {
				release(m)
			}
		}
		for _, p := range spec.paths {
			release(p)
		}
		// The operator's config-editor overrides go with the files they applied to.
		// Keeping them would re-apply an edit written against THIS install's inbound
		// ids to whatever inbound reuses an id after a reinstall, silently.
		coreconfig.ClearCoreConfigOverrides(n)
		emit(ProvisionStep{
			Name: "remove " + coreDisplayName(n) + " config", OK: true,
			Msg: pathsMsg(removed),
		})
	}

	// 2b. The host files the removed cores OVERWROTE rather than created.
	//
	//     These are not in the catalog because they are not ours to own:
	//     /etc/ipsec.conf and /etc/ipsec.secrets belong to a host libreswan (whose
	//     PSKs we replaced), /etc/swanctl/swanctl.conf we truncated to a single
	//     `include` line, /etc/strongswan.conf we rewrote outright. Uninstall used to
	//     leave our render behind (or delete the file), so the operator's own IPsec
	//     never worked again. Each one was copied to the manifest's backups/ before
	//     the first overwrite; this puts the copy back.
	var restored []string
	for _, p := range sharedHostFilePaths() {
		core := coreForHostPath(p)
		if handled[p] || core == "" || !removing[core] {
			continue
		}
		handled[p] = true
		gone, left := manifest.ReleasePath(p, selected)
		if gone != "" {
			restored = append(restored, gone)
		}
		if left != "" {
			kept = append(kept, left)
		}
	}
	if len(restored) > 0 {
		emit(ProvisionStep{Name: "restore shared host config", OK: true, Msg: pathsMsg(restored)})
	}

	// 2c. Reversible host state that is not a file: the systemd units we disabled to
	//     take a daemon over, and the NIC offload GRE's FOU mode turned off. Both
	//     were one-way changes with nothing recorded, so a host that had its own
	//     xl2tpd or ocserv running before pxpanel never got it back.
	if line := restoreDisabledUnits(selected, emit); line != "" {
		kept = append(kept, line)
	}
	restoreEthtoolState(selected, emit)

	// 3. Bundled daemon binaries, minus anything a surviving core still runs
	//    (pptpctrl belongs to PPTP alone, but the principle is the same).
	//    PORT NOTE: binary removal is the bundle layer's (vpn-ui
	//    backend.RemoveDaemons); the seam has no removal half yet, so the step
	//    reports what WOULD go rather than pretending it did.
	keepBins := map[string]bool{}
	for _, d := range daemonsFor(remaining) {
		keepBins[d] = true
	}
	var dropBins []string
	for _, d := range daemonsFor(selected) {
		if !keepBins[d] {
			dropBins = append(dropBins, d)
		}
	}
	if len(dropBins) > 0 {
		emit(ProvisionStep{
			Name: "remove bundled binaries", OK: true, Warn: true,
			Msg: "bundle layer has no removal seam yet (bundle/build wave); " + pathsMsg(dropBins),
		})
	}

	// 4. Shared features. Each is undone only when NO surviving core claims it.
	//    This is the ipsec case the whole design exists for.
	for _, feat := range []string{featPppd, featPptpCtrl, featAccel, featStrongswan, featKernelMods, featAmneziawg} {
		if !needsFeature(selected, feat) {
			continue
		}
		if needsFeature(remaining, feat) {
			kept = append(kept, fmt.Sprintf("%s (still needed by %s)",
				featureLabel(feat), strings.Join(coreDisplayNames(coresNeeding(remaining, feat)), ", ")))
			emit(ProvisionStep{
				Name: "keep " + featureLabel(feat), OK: true,
				Msg: "still required by " + strings.Join(coreDisplayNames(coresNeeding(remaining, feat)), ", "),
			})
			continue
		}
		emit(removeFeature(feat))
	}

	// 5. Rewrite the module-persist file for what is left, so the removed cores'
	//    modules stop being auto-loaded on boot. Loaded modules are deliberately
	//    NOT rmmod'd: unloading a live module can drop unrelated traffic, and it
	//    buys nothing that the next boot does not.
	if len(remaining) == 0 {
		removed := removeIfPresent(modulesLoadConf)
		emit(ProvisionStep{
			Name: "persist " + modulesLoadConf, OK: true,
			Msg: removedMsg(removed),
		})

		// 5b. The last core is gone, so the host-wide data-plane settings have nobody
		//     left to serve. Neither of these was ever undone by a per-core uninstall,
		//     so a host kept a pxpanel sysctl drop-in and loose rp_filter forever after
		//     the last protocol was removed.
		if gone, left := manifest.ReleasePath(sysctlDropIn, selected); gone != "" {
			emit(ProvisionStep{Name: "remove " + sysctlDropIn, OK: true, Msg: gone})
		} else if left != "" {
			kept = append(kept, left)
		}
		if restored := restoreHostSysctls(); len(restored) > 0 {
			emit(ProvisionStep{Name: "restore host sysctls", OK: true, Msg: strings.Join(restored, ", ")})
		}
	} else {
		mods := requiredModulesFor(remaining)
		for _, m := range optionalModulesFor(remaining) {
			if moduleAvailable(m) {
				mods = append(mods, m)
			}
		}
		err := os.WriteFile(modulesLoadConf, []byte(strings.Join(dedupe(mods), "\n")+"\n"), 0o644)
		emit(ProvisionStep{
			Name: "persist " + modulesLoadConf, OK: err == nil,
			Msg: msgOrOK(err),
		})
	}

	// 6. Record what the host is now installed for. Done last: everything above
	//    reads the old set, and a crash part-way leaves the core still listed as
	//    installed, which is the safe direction to fail in (re-running the
	//    uninstall finishes the job; the alternative silently strands files).
	if err := SetProvisionedProtocols(orderedCoreNames(remaining)); err != nil {
		log.Warning("core uninstall: failed to persist provisionedProtocols:", err)
		emit(ProvisionStep{Name: "record installed cores", OK: false, Msg: err.Error()})
	} else {
		emit(ProvisionStep{Name: "record installed cores", OK: true, Msg: installedMsg(remaining)})
	}

	// 7. Reconcile the survivors that shared something with what was removed:
	//    regenerate their configs and bring their daemon back to the right state.
	//    This is what makes the charon case correct end to end. The removed
	//    core's swanctl connection files are gone by now, so re-initialising L2TP
	//    reloads charon with only L2TP's own configuration.
	//
	//    Scoped to the affected cores on purpose: restarting every daemon on the
	//    host to remove one unrelated core would be an outage nobody asked for.
	if affected := coresSharingWith(selected, remaining); len(affected) > 0 {
		s.reinitCores(affected)
		emit(ProvisionStep{
			Name: "reconcile shared cores", OK: true,
			Msg: strings.Join(coreDisplayNames(affected), ", "),
		})
	}

	// Nftables/routing are shared by the whole data plane and stay put; the
	// removed cores simply stop having inbounds in them.
	return kept
}

// restoreDisabledUnits hands back the systemd units provisioning disabled so the
// panel could run those daemons itself.
//
// procmgr.MigrateFromSystemd runs `systemctl disable --now` on openvpn-server@*,
// xl2tpd, pptpd and ipsec, and nothing distinguished the units WE generated from
// the distro's own. On a host that was already running its own xl2tpd, installing
// any core stopped it for good: uninstalling pxpanel afterwards did not bring it
// back because nothing had recorded that it was ever running. Each disable is now
// recorded with the unit's enabled/active state; this replays it.
//
// Returns a single summary line for the "kept" report, or "".
func restoreDisabledUnits(selected []string, emit func(ProvisionStep)) string {
	if !commandExists("systemctl") {
		return ""
	}
	var restored []string
	for _, unit := range manifest.IDsOfKind(kindUnit) {
		// Release first (drops this uninstall's claims), then read the record: a
		// non-empty remaining Cores means a SURVIVING core still needs it.
		manifest.Release(kindUnit, unit, selected)
		snap, ok := releaseSnapshot(kindUnit, unit)
		if !ok {
			continue
		}
		if len(snap.Cores) > 0 {
			continue // a surviving core still needs it out of the way
		}
		if snap.WasEnabled == nil {
			continue
		}
		if *snap.WasEnabled {
			_ = exec.CommandContext(context.Background(), "systemctl", "enable", unit).Run()
		}
		if snap.WasActive != nil && *snap.WasActive {
			_ = exec.CommandContext(context.Background(), "systemctl", "start", unit).Run()
		}
		if *snap.WasEnabled || (snap.WasActive != nil && *snap.WasActive) {
			restored = append(restored, unit)
		}
		manifest.RemoveEntry(kindUnit, unit)
	}
	if len(restored) == 0 {
		return ""
	}
	_ = exec.CommandContext(context.Background(), "systemctl", "daemon-reload").Run()
	emit(ProvisionStep{Name: "restore host services", OK: true, Msg: strings.Join(restored, ", ")})
	return "re-enabled the host's own " + strings.Join(restored, ", ")
}

// restoreEthtoolState puts back the NIC offload settings a core turned off. Today
// that is GRE's FOU mode disabling GRO on the WAN interface, which was documented
// as deliberately permanent and left the host's NIC changed forever, including
// after the core that needed it was removed.
func restoreEthtoolState(selected []string, emit func(ProvisionStep)) {
	for _, id := range manifest.IDsOfKind(manifest.KindEthtool) {
		// Same release-then-read order as the units above.
		manifest.Release(manifest.KindEthtool, id, selected)
		snap, ok := releaseSnapshot(manifest.KindEthtool, id)
		if !ok || len(snap.Cores) > 0 || snap.Prev == "" {
			continue
		}
		iface, setting, found := strings.Cut(id, "/")
		if !found || setting != "gro" {
			continue
		}
		err := restoreGro(iface, snap.Prev)
		emit(ProvisionStep{
			Name: "restore GRO on " + iface, OK: err == nil, Warn: err != nil,
			Msg: msgOrOK(err),
		})
		if err == nil {
			manifest.RemoveEntry(manifest.KindEthtool, id)
		}
	}
}

// releaseSnapshot is the read half of vpn-ui's ownReleaseEntry: the artifact's
// recorded state, taken BEFORE manifest.Release drops this uninstall's claims
// (manifest.Release's exported Action carries the verdict but not the snapshot).
func releaseSnapshot(kind, id string) (manifest.OwnedArtifact, bool) {
	for _, e := range manifest.Entries() {
		if e.Kind == kind && e.ID == id {
			return e, true
		}
	}
	return manifest.OwnedArtifact{}, false
}

// restoreGro puts an interface's GRO setting back to what it was before FOU
// needed it off. Mirror of gre/gre.go's unexported probe of the same name —
// gre records the Prev value; this replays it.
func restoreGro(iface, prev string) error {
	if prev != "on" && prev != "off" {
		return fmt.Errorf("no usable previous GRO setting (%q)", prev)
	}
	return exec.CommandContext(context.Background(), "ethtool", "-K", iface, "gro", prev).Run()
}

// sharedDaemonKeeper returns the first remaining core that runs the SAME daemon
// process as `name`, or "" when stopping `name` affects nothing else.
//
// Today strongSwan/charon is the only shared daemon: one process serves both
// IKEv2 and L2TP/IPsec. pppd and accel-ppp are per-core processes, so removing
// one of those cores stops only its own.
func sharedDaemonKeeper(name string, remaining []string) string {
	if !coreHasFeature(name, featStrongswan) {
		return ""
	}
	for _, r := range coresNeeding(remaining, featStrongswan) {
		return r
	}
	return ""
}

// coreHasFeature reports whether one core claims a feature.
func coreHasFeature(name, feat string) bool {
	return needsFeature([]string{name}, feat)
}

// coresSharingWith returns the cores in `remaining` that claim at least one
// feature with any of the `removed` cores, i.e. exactly those whose host state
// the removal could have disturbed.
func coresSharingWith(removed, remaining []string) []string {
	var out []string
	for _, r := range specsFor(remaining) {
		for _, d := range specsFor(removed) {
			if sharesAnyFeature(r, d) {
				out = append(out, r.name)
				break
			}
		}
	}
	return out
}

// reinitCores regenerates configuration and restarts the daemons for the given
// cores, using the very same Init* entry points a completed setup run calls.
func (s *CoreService) reinitCores(names []string) {
	for _, n := range names {
		switch n {
		case "l2tp":
			s.l2tp.InitL2tp()
		case "pptp":
			s.pptp.InitPptp()
		case "openvpn":
			s.openvpn.InitOpenVpn()
		case "openconnect":
			s.ocserv.InitOcserv()
		case "sstp":
			s.sstp.InitSstp()
		case "ikev2":
			s.ikev2.InitIkev2()
		}
	}
}

// coresNeeding lists which of the given cores claim a feature.
func coresNeeding(names []string, feat string) []string {
	var out []string
	for _, c := range specsFor(names) {
		for _, f := range c.feats {
			if f == feat {
				out = append(out, c.name)
				break
			}
		}
	}
	return out
}

// removeFeature undoes one provisioning feature. Only reached when no installed
// core still needs it.
//
// PORT NOTE vs vpn-ui: the pppd / accel-ppp / strongSwan bundle-tree removals
// (backend.RemoveDaemons-adjacent path cleanup over the bundle roots) are the
// bundle/build wave's — its extractor owns the roots and this package cannot
// name them, so those features report what is deliberately left for now. The
// manifest-released host files and the AWG DKMS module still go.
func removeFeature(feat string) ProvisionStep {
	switch feat {
	case featPppd, featAccel:
		return ProvisionStep{
			Name: "remove " + featureLabel(feat), OK: true, Warn: true,
			Msg: "the bundle tree is the bundle layer's (bundle/build wave); it stays until that wave's removal half lands",
		}

	case featPptpCtrl:
		// procmgr.LinkPptpCtrl delegated to the bundle provider; the provider's
		// link target is not named here, so the unlink is the bundle wave's too.
		return ProvisionStep{
			Name: "remove pptpctrl link", OK: true, Warn: true,
			Msg: "the bundle tree is the bundle layer's (bundle/build wave); it stays until that wave's removal half lands",
		}

	case featStrongswan:
		// Reached only when neither L2TP nor IKEv2 is installed any more, so the
		// shared charon has no user left.
		var removed []string
		// /etc/strongswan.conf is a HOST file: the charon writer rewrites it wholesale,
		// so on a box with its own strongSwan we replaced their configuration. Released
		// through the manifest, which restores their copy from backups/ instead of
		// deleting the file.
		if gone, _ := manifest.ReleasePath("/etc/strongswan.conf", []string{"ikev2", "l2tp"}); gone != "" {
			removed = append(removed, gone)
		}
		// charon's control socket. Removed HERE rather than from the ikev2 catalog
		// entry precisely because charon is shared: this branch only runs once
		// neither L2TP nor IKEv2 is left, so deleting the socket cannot pull it out
		// from under a still-running charon that L2TP is using.
		if removeIfPresent("/var/run/charon.vici") {
			removed = append(removed, "/var/run/charon.vici")
		}
		// The shared charon config root. Named after IKEv2 for historical reasons
		// but written for L2TP too, so it can only go once neither remains.
		if removeIfPresent(ikev2ConfigRoot) {
			removed = append(removed, ikev2ConfigRoot)
		}
		return ProvisionStep{Name: "remove strongSwan (IPsec) bundle", OK: true, Msg: pathsMsg(removed)}

	case featKernelMods:
		// The distro kernel package is never removed: it is the host's kernel,
		// and something else may well depend on it now.
		return ProvisionStep{
			Name: "kernel-modules package", OK: true,
			Msg: "kept (a distro package; remove it yourself if nothing else needs it)",
		}

	case featAmneziawg:
		return awg.RemoveAmneziawgModule()
	}
	return ProvisionStep{Name: "remove " + feat, OK: true, Msg: "nothing to do"}
}

// ikev2ConfigRoot is the shared charon config root (ikev2/ikev2.go's
// ikev2ConfigRoot const; the value is storage identity — keep byte-identical).
const ikev2ConfigRoot = "/etc/pxpanel-ikev2"

// featureLabel names a feature for the operator.
func featureLabel(feat string) string {
	switch feat {
	case featPppd:
		return "pppd bundle"
	case featPptpCtrl:
		return "pptpctrl link"
	case featAccel:
		return "accel-ppp bundle"
	case featStrongswan:
		return "strongSwan/IPsec (charon)"
	case featKernelMods:
		return "PPP kernel-modules package"
	case featAmneziawg:
		return "AmneziaWG kernel module"
	}
	return feat
}

func removeIfPresent(path string) bool {
	if path == "" {
		return false
	}
	if _, err := os.Lstat(path); err != nil {
		return false
	}
	if err := os.RemoveAll(path); err != nil {
		log.Warning("core uninstall: remove", path, err)
		return false
	}
	return true
}

func pathsMsg(paths []string) string {
	if len(paths) == 0 {
		return "nothing to do"
	}
	if len(paths) <= 3 {
		return strings.Join(paths, ", ")
	}
	return fmt.Sprintf("%d path(s): %s, ...", len(paths), strings.Join(paths[:3], ", "))
}

func removedMsg(removed bool) string {
	if removed {
		return "removed"
	}
	return "nothing to do"
}

func installedMsg(remaining []string) string {
	if len(remaining) == 0 {
		return "no cores installed"
	}
	return strings.Join(coreDisplayNames(remaining), ", ")
}

// --------------------------------------------------------------------------- //
//  Shared host files — the mirror of manifest.go's sharedHostFiles map
//  (manifest keeps the map unexported; uninstall's step 2b needs the list and
//  each entry's owning core). THE TWO MAPS MUST STAY IN SYNC: the manifest one
//  decides what gets backed up before an overwrite, this one decides what gets
//  restored on uninstall.
// --------------------------------------------------------------------------- //

var sharedHostFiles = map[string]string{
	"/etc/xl2tpd/xl2tpd.conf":       "l2tp",
	"/etc/ppp/options.xl2tpd":       "l2tp",
	"/etc/ipsec.conf":               "l2tp",
	"/etc/ipsec.secrets":            "l2tp",
	"/etc/pptpd.conf":               "pptp",
	"/etc/ppp/pptpd-options":        "pptp",
	"/etc/strongswan.conf":          "ikev2",
	"/etc/swanctl/swanctl.conf":     "ikev2",
	"/etc/default/grub":             "",
	"/etc/sysctl.d/99-pxpanel.conf": "",
}

func sharedHostFilePaths() []string {
	out := make([]string, 0, len(sharedHostFiles))
	for p := range sharedHostFiles {
		out = append(out, p)
	}
	return out
}

// coreForHostPath names the core that writes a shared host file, or "" for the
// host-wide ones (grub, our sysctl drop-in) that belong to no single core and
// are only released when the last core goes.
func coreForHostPath(path string) string { return sharedHostFiles[path] }

// restoreHostSysctls puts back the host-wide sysctls the data plane relaxed
// (vpn-ui nftables.go:restoreHostSysctls; the manifest records them under the
// "sysctl" kind — manifest.KIND-literal mirror, see preflight.go's kind consts).
func restoreHostSysctls() []string {
	const kindSysctl = "sysctl"
	var done []string
	for _, key := range manifest.IDsOfKind(kindSysctl) {
		prev, found := manifest.PrevOf(kindSysctl, key)
		if !found || prev == "" {
			continue
		}
		if err := exec.CommandContext(context.Background(), "sysctl", "-w", key+"="+prev).Run(); err != nil {
			log.Warning("could not restore sysctl", key, "to", prev, err)
			continue
		}
		manifest.RemoveEntry(kindSysctl, key)
		done = append(done, key+"="+prev)
	}
	return done
}
