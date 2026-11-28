// Provisioning: the host/kernel preparation no bundled binary can do — load +
// persist the required kernel modules, enable + persist IP forwarding, relax
// rp_filter, install nftables/iproute2, the distro kernel-modules package with
// bootloader pinning, the DKMS AmneziaWG build, and (through the bundle seam)
// the daemon/strongSwan extraction. Ported from vpn-ui web/service/core.go
// (control + provisioning half), with provisioning features resolved against
// the catalog and the AWG step delegated to awg.EnsureAmneziawgModule.
package coresettings

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/vpn/awg"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ipsec"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/log"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/nftables"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/pkgmgr"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/xrayplane"
)

// ProvisionStep is one action taken by Provision(), for reporting to the UI/CLI.
// It IS pkgmgr.ProvisionStep — the type the pkgmgr/ipsec/awg waves' step
// producers (EnsureLibreswan, EnsureCommand, EnsureAmneziawgModule, …) already
// speak — so a run's stream composes with them unchanged.
type ProvisionStep = pkgmgr.ProvisionStep

// Persisted host-file names (vpn-ui /etc/modules-load.d/vpn-ui.conf and
// /etc/sysctl.d/99-vpn-ui.conf under the product rename; the sysctl drop-in is
// listed in the manifest's sharedHostFiles map under the pxpanel name — keep
// the two in sync).
const (
	modulesLoadConf = "/etc/modules-load.d/pxpanel.conf"
	sysctlDropIn    = "/etc/sysctl.d/99-pxpanel.conf"
)

// Provision performs the host/kernel preparation that no bundled binary can do:
// load + persist the required kernel modules and enable + persist IP forwarding.
// It is idempotent and safe to run repeatedly. This is the in-binary replacement
// for the legacy host-prep shell script. It collects and returns all
// steps; use StartProvision for the streamed, non-blocking variant.
//
// cores selects which VPN cores to provision for; a nil/empty selection means
// every installable core, which is what the CLI and the legacy all-in-one setup
// path want.
func (s *CoreService) Provision(cores []string) []ProvisionStep {
	var steps []ProvisionStep
	s.runProvisionSteps(func(st ProvisionStep) { steps = append(steps, st) }, cores)
	return steps
}

// runProvisionSteps performs each provisioning action and invokes emit after
// every step, so callers can stream progress to a live log. It is idempotent.
// It returns the kernel modules that will only load after a reboot (empty when
// none) together with the package that provides them, so the caller can prompt
// the operator to reboot.
//
// `cores` scopes the run, along two axes that are deliberately different.
//
//   - The WORK is scoped to the selection. Host-wide steps (forwarding,
//     rp_filter, firewalld, nftables, iproute2) always run because they are the
//     data plane every core shares, but the expensive per-core features (the
//     pppd / accel-ppp / strongSwan bundles, the kernel-modules package, the
//     AmneziaWG build) run only for the cores being installed. Adding one core
//     therefore does not re-extract every bundle an already-installed core owns.
//   - The PERSISTED STATE is scoped to the union of the selection and what is
//     already installed, so "install WireGuard" cannot quietly un-persist L2TP's
//     kernel modules or delete its daemon binaries.
//
// Re-run Setup is what repairs an existing core: it passes the installed set as
// the selection, which puts both axes back together.
func (s *CoreService) runProvisionSteps(emit func(ProvisionStep), cores []string) (rebootModules []string, rebootPkg string) {
	selected := cores
	if len(selected) == 0 {
		selected = installableCores()
	}
	target := dedupe(append(append([]string{}, s.installedCoreNames()...), selected...))

	requiredModules := requiredModulesFor(target)
	optionalModules := optionalModulesFor(target)

	for _, m := range requiredModules {
		if moduleLoaded(m) {
			emit(ProvisionStep{Name: "module " + m, OK: true, Msg: "already loaded"})
			continue
		}
		out, err := exec.CommandContext(context.Background(), "modprobe", m).CombinedOutput()
		if err == nil {
			emit(ProvisionStep{Name: "modprobe " + m, OK: true, Msg: "loaded"})
		} else {
			// Not present in the running kernel. Expected on minimal/cloud images;
			// the kernel-modules step below installs it (rebooting into a fuller
			// kernel when the module only ships there). Flag as a warning, not an
			// error, so the console doesn't look broken mid-run.
			emit(ProvisionStep{
				Name: "modprobe " + m, OK: true, Warn: true,
				Msg: "not in the running kernel — resolving below", Log: strings.TrimSpace(string(out)),
			})
		}
	}

	// Optional modules: load where the kernel ships them; a kernel that dropped one
	// (af_key on RHEL 10+) is fine — IPsec uses XFRM — so report it as OK info, not
	// a failure, and never let it drive the kernel-modules install/reboot below.
	var loadableOptional []string
	for _, m := range optionalModules {
		if moduleLoaded(m) {
			loadableOptional = append(loadableOptional, m)
			emit(ProvisionStep{Name: "module " + m, OK: true, Msg: "already loaded (optional)"})
			continue
		}
		if !moduleAvailable(m) {
			// amneziawg is the one entry here that no kernel ships: it is built from the
			// vendored source by the AWG feature step later in THIS same pass, so on a
			// first run it is legitimately absent at this point. Saying "IPsec uses XFRM
			// instead" would be simply wrong for it.
			msg := "not on this kernel, optional: IPsec uses XFRM instead"
			if m == moduleAmneziawg {
				// Deliberately neutral: on a supported host the AmneziaWG step below builds
				// it, on an unsupported one that step explains why it cannot. Promising a
				// build here would contradict the very next line on Fedora/Arch/RHEL.
				msg = "not built yet, see the AmneziaWG step below"
			}
			emit(ProvisionStep{Name: "module " + m, OK: true, Msg: msg})
			continue
		}
		if exec.CommandContext(context.Background(), "modprobe", m).Run() == nil {
			loadableOptional = append(loadableOptional, m)
			emit(ProvisionStep{Name: "modprobe " + m, OK: true, Msg: "loaded (optional)"})
		}
	}

	// Persist only the modules present on this kernel, so systemd-modules-load
	// doesn't log a failure each boot for an optional module the kernel dropped.
	modConf := strings.Join(append(append([]string{}, requiredModules...), loadableOptional...), "\n") + "\n"
	manifest.PrepareHostFile(modulesLoadConf, "")
	err := os.WriteFile(modulesLoadConf, []byte(modConf), 0o644)
	emit(ProvisionStep{Name: "persist " + modulesLoadConf, OK: err == nil, Msg: msgOrOK(err)})

	err = exec.CommandContext(context.Background(), "sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	emit(ProvisionStep{Name: "sysctl net.ipv4.ip_forward=1", OK: err == nil, Msg: msgOrOK(err)})

	// Persist ip_forward plus loose rp_filter. Fedora/RHEL default rp_filter to
	// strict (1), which drops the policy-routed TPROXY packets carrying VPN client
	// traffic into Xray; loose (2, Ubuntu's default) fixes it. This 99-*.conf sorts
	// after Fedora's 50-default.conf, so it wins on boot.
	const sysctlConf = "net.ipv4.ip_forward=1\n" +
		"net.ipv4.conf.all.rp_filter=2\n" +
		"net.ipv4.conf.default.rp_filter=2\n"
	// Recorded before the write so uninstall knows to take it away again (per-core
	// uninstall used to leave this drop-in behind forever, so a host kept loose
	// rp_filter across every reboot long after the last VPN core was removed).
	manifest.PrepareHostFile(sysctlDropIn, "")
	err = os.WriteFile(sysctlDropIn, []byte(sysctlConf), 0o644)
	emit(ProvisionStep{Name: "persist " + sysctlDropIn, OK: err == nil, Msg: msgOrOK(err)})

	// Apply loose rp_filter now and, when firewalld is active (Fedora/RHEL), trust
	// the VPN address space so its default-drop INPUT policy doesn't block the
	// TPROXY'd data plane. No-op on Debian/Ubuntu.
	nftables.EnsureVpnHostNetworking()
	emit(ProvisionStep{Name: "relax rp_filter + trust VPN in firewalld", OK: true, Msg: firewallStepMsg()})

	// The bundled daemon/strongSwan extraction (vpn-ui: backend.Available() →
	// ExtractOnly + the per-feature bundle extracts). The target's bundle layer
	// is the procmgr.BundleProvider seam; extraction of the flat daemons and the
	// pppd/accel trees has no seam yet (TODO bundle/build wave), so the steps the
	// provider does offer run and the rest honest-skip rather than pretend.
	b := procmgr.Bundles()
	wanted := daemonsFor(target)
	if len(wanted) > 0 && b.DaemonPath(wanted[0]) != "" {
		emit(ProvisionStep{
			Name: "extract bundled daemons", OK: true,
			Msg: fmt.Sprintf("%d daemon(s) resolvable via the bundle layer", len(wanted)),
		})
	} else if len(wanted) > 0 {
		emit(ProvisionStep{
			Name: "extract bundled daemons", OK: true, Warn: true,
			Msg: "no bundle layer wired (bundle/build wave); daemons resolve from PATH — install them or wire the bundle provider",
		})
	}

	// strongSwan (IKEv2 + L2TP/IPsec): extract the relocatable tree and link
	// /usr/lib/ipsec at it so charon's absolute-path plugin dlopens resolve to the
	// bundled .so's. The provider owns both the extract and the link; the manifest
	// claim for the /usr/lib/ipsec symlink belongs to the provider's link half
	// (it knows the bundle-relative target this package cannot name).
	if needsFeature(selected, featStrongswan) && b.HasStrongswanBundle() {
		if !b.StrongswanBundleReady() {
			swErr := b.ExtractStrongswanBundle()
			emit(ProvisionStep{Name: "extract strongswan (IKEv2) bundle", OK: swErr == nil, Msg: msgOrOK(swErr)})
		}
		swlErr := b.LinkStrongswanIpsecDir()
		emit(ProvisionStep{Name: "link strongswan ipsec dir", OK: swlErr == nil, Msg: msgOrOK(swlErr)})
	}

	// pptpd execs pptpctrl from a fixed compiled-in path; point it at the
	// extracted bundle so pptpd works from any install dir. procmgr.LinkPptpCtrl
	// delegates to the bundle provider (no-op until the bundle wave lands).
	if needsFeature(selected, featPptpCtrl) {
		procmgr.LinkPptpCtrl()
		emit(ProvisionStep{Name: "link pptpctrl", OK: true, Msg: "ok"})
	}

	// The bundled daemons run as child processes of the panel (not systemd),
	// so any leftover units from the old design are torn down here.
	procmgr.MigrateFromSystemd()
	emit(ProvisionStep{Name: "run daemons as child processes", OK: true, Msg: "ok"})

	// The VPN data plane needs nftables (TPROXY steering + traffic accounting) and
	// iproute2 (the fwmark → table 100 policy route). They're present on almost
	// every host, but minimal cloud/container images can omit them — without them
	// clients connect but no traffic routes. Install when missing (no-op if present).
	emit(pkgmgr.EnsureCommand("nftables", "nft", pkgmgr.NftablesPackage))
	emit(pkgmgr.EnsureCommand("iproute2 (ip)", "ip", pkgmgr.IproutePackage))

	// IPsec for L2TP/IPsec: on the bundled path (amd64) the extracted strongSwan/charon
	// serves the IKEv1 transport layer alongside IKEv2 on one daemon, so no host package
	// is needed. Only fall back to host libreswan on arches without the strongSwan bundle.
	if needsFeature(selected, featStrongswan) && !ipsec.HasStrongswanBundle() {
		emit(pkgmgr.EnsureLibreswan())
	}

	// L2TP/PPTP need PPP kernel modules that minimal/cloud kernels omit. Best-
	// effort install of the distro's full kernel-modules package. When the modules
	// ship only in a newer kernel, this reports that a reboot is needed to load them.
	var mods []string
	var pkg string
	if needsFeature(selected, featKernelMods) {
		mods, pkg = s.provisionKernelModules(emit, requiredModules)
	}

	// AmneziaWG: DKMS-build + load the out-of-tree `amneziawg` module from the vendored
	// source (the project's only on-host compile). Warn-and-degrade on failure.
	//
	// This MUST run AFTER provisionKernelModules. That step can install a fuller kernel on
	// a cut-down cloud image (Debian's "cloud" flavour ships no PPP/L2TP) and ask for a
	// reboot, so the kernel this host will actually boot is not the one running now.
	// Building first meant the module was compiled for the kernel being left behind, and
	// AmneziaWG came back "module not found" after the reboot until setup was run a second
	// time. Running here, the incoming kernel and its headers are already on disk, so the
	// `dkms autoinstall` inside this step covers it too.
	if needsFeature(selected, featAmneziawg) {
		emit(awg.EnsureAmneziawgModule())
	}

	// Clear any distro deny-list/disable for our modules (and their dependencies) so
	// systemd-modules-load auto-loads them on boot (Fedora/RHEL blacklist the L2TP
	// modules; CIS-hardened hosts may `install <mod> /bin/false` others). This MUST
	// run after the kernel-modules install above: on Fedora/RHEL the blacklist files
	// ship WITH kernel-modules-extra, so they don't exist until that package is
	// installed — clearing earlier would find nothing and the module would stay
	// deny-listed after the reboot. Especially important on the reboot-required path,
	// where the modules only load on the next boot and must not be deny-listed then.
	if cleared, ulog := pkgmgr.UnblacklistVpnModules(); len(cleared) > 0 {
		emit(ProvisionStep{
			Name: "enable VPN modules", OK: true,
			Msg: "cleared distro deny-list/disable for " + strings.Join(cleared, ", ") + " (auto-loads on boot)", Log: ulog,
		})

		// An `install <mod> /bin/false` rule blocks even the explicit modprobe run
		// earlier in this function, so a just-freed module isn't loaded yet. Load any
		// that are available now; `blacklist`-only modules already loaded above.
		var loaded []string
		for _, m := range requiredModules {
			if moduleLoaded(m) {
				continue
			}
			if exec.CommandContext(context.Background(), "modprobe", m).Run() == nil && moduleLoaded(m) {
				loaded = append(loaded, m)
			}
		}
		if len(loaded) > 0 {
			emit(ProvisionStep{Name: "load freed VPN modules", OK: true, Msg: "loaded " + strings.Join(loaded, ", ")})
		}
	}

	return mods, pkg
}

// missingOf filters a wanted-module list down to the ones this kernel cannot
// provide (vpn-ui: missingModules — pkgmgr keeps the flat installed-cores
// variant, so the catalog-scoped form lives here).
func missingOf(want []string) []string {
	var missing []string
	for _, m := range want {
		if !moduleAvailable(m) {
			missing = append(missing, m)
		}
	}
	return missing
}

// provisionKernelModules makes the VPN PPP/L2TP kernel modules available when the
// running kernel lacks them. It is best-effort and non-interactive: it installs
// the right package for the distro, loads what it can into the running kernel,
// and — when the modules only ship in a fuller kernel it had to install — pins
// that kernel in the bootloader and reports that a reboot is needed (rather than
// rebooting). It returns the modules that only load after a reboot and the
// package that was installed.
//
// Per-distro behaviour (see pkgmgr.KernelModulesPackage / InstallKernelModules):
//   - Ubuntu: linux-modules-extra-<running> adds modules to the RUNNING kernel →
//     no reboot. Cut-down flavours (kvm) fall back to linux-generic → reboot.
//   - Debian: cloud images omit PPP/L2TP, so the generic linux-image-<arch> is
//     installed → reboot, and the bootloader is pinned to it (a same-version
//     cloud kernel would otherwise stay the GRUB default).
//   - Fedora/RHEL/Alma/CentOS: kernel-modules-extra-<running> → no reboot.
//   - Arch: stock kernel already ships the modules → nothing to do.
//
// `want` is the module set the current selection needs, so a run that installed
// only WireGuard never installs a kernel package for PPP it will not use.
func (s *CoreService) provisionKernelModules(emit func(ProvisionStep), want []string) (rebootModules []string, rebootPkg string) {
	missing := missingOf(want)
	if len(missing) == 0 {
		return nil, ""
	}
	distro := pkgmgr.DistroPretty()

	pkg := pkgmgr.KernelModulesPackage()
	if pkg == "" {
		emit(ProvisionStep{
			Name: "kernel modules", OK: false,
			Msg: "missing " + strings.Join(missing, ", ") + " on " + distro +
				" — no kernel-modules package known for this distro; load them manually",
		})
		return nil, ""
	}

	emit(ProvisionStep{
		Name: "kernel modules (" + distro + ")", OK: true,
		Msg: "missing " + strings.Join(missing, ", ") + " — installing " + pkg,
	})

	installed, still, newKernel, ulog, err := pkgmgr.InstallKernelModules(want)
	if err != nil {
		emit(ProvisionStep{Name: "install " + pkg, OK: false, Msg: err.Error(), Log: ulog})
		return nil, ""
	}
	if len(still) == 0 {
		emit(ProvisionStep{
			Name: "install " + installed, OK: true,
			Msg: "modules loaded into the running kernel — no reboot needed", Log: ulog,
		})
		return nil, ""
	}

	// Whatever is still missing only exists in a freshly installed kernel that
	// isn't booted yet. Report it and make the bootloader boot that kernel.
	if newKernel == "" {
		emit(ProvisionStep{
			Name: "install " + installed, OK: true, Warn: true,
			Msg: "installed; " + strings.Join(still, ", ") + " load after a reboot into the new kernel", Log: ulog,
		})
		return still, installed
	}

	emit(ProvisionStep{
		Name: "install " + installed, OK: true, Warn: true,
		Msg: "installed kernel " + newKernel + "; " + strings.Join(still, ", ") + " load after reboot", Log: ulog,
	})

	bootMsg, bootErr := ensureBootloaderBootsKernel(newKernel)
	emit(ProvisionStep{Name: "set default boot kernel", OK: bootErr == nil, Msg: bootStepMsg(bootMsg, bootErr)})

	return still, installed
}

func bootStepMsg(msg string, err error) string {
	if err != nil {
		return err.Error()
	}
	return msg
}

// provisionRun holds the state of the single, in-progress or most-recent
// background provisioning run, so the Core Settings page can poll a live log.
// Provisioning is single-admin and one-at-a-time, so one global run suffices.
var provisionRun struct {
	mu             sync.Mutex
	running        bool
	done           bool
	steps          []ProvisionStep
	rebootRequired bool
	rebootModules  []string
	rebootPkg      string
}

// StartProvision launches provisioning for the given cores in the background and
// returns true, or returns false without starting a second run if one is already
// in progress. On completion it persists the provisioned flag so the setup gate
// clears, and records the cores the host is now set up for.
//
// A nil/empty selection means every installable core, which keeps the CLI and any
// caller that predates the picker working exactly as before.
func (s *CoreService) StartProvision(cores []string) bool {
	provisionRun.mu.Lock()
	if provisionRun.running {
		provisionRun.mu.Unlock()
		return false
	}
	provisionRun.running = true
	provisionRun.done = false
	provisionRun.steps = nil
	provisionRun.rebootRequired = false
	provisionRun.rebootModules = nil
	provisionRun.rebootPkg = ""
	provisionRun.mu.Unlock()

	selected := validCoreNames(cores)
	if len(selected) == 0 {
		selected = installableCores()
	}
	// Captured BEFORE the run: runProvisionSteps provisions for the union of this
	// and the selection, and the same union is what gets persisted below.
	already := s.installedCoreNames()

	go func() {
		var cs CoreService // CoreService is zero-value usable and stateless
		mods, pkg := cs.runProvisionSteps(func(st ProvisionStep) {
			provisionRun.mu.Lock()
			provisionRun.steps = append(provisionRun.steps, st)
			provisionRun.mu.Unlock()
		}, selected)
		if err := SetVpnProvisioned(true); err != nil {
			log.Warning("failed to persist vpnProvisioned flag:", err)
		}
		// Record the cores this host is now set up for: what it already had plus
		// what this run added. Additive, so "add one core" never drops the rest,
		// and a core absent from the list is what makes the Core Settings page
		// offer it under "Add core".
		if err := SetProvisionedProtocols(orderedCoreNames(append(already, selected...))); err != nil {
			log.Warning("failed to persist provisionedProtocols:", err)
		}

		// With provisioning finished and no reboot pending, actively bring the VPN
		// stack up so a completed setup leaves everything running — the operator
		// shouldn't have to reboot or re-run setup to get services started. Init*
		// regenerate configs and (re)start the daemons for whatever inbounds already
		// exist (a no-op when there are none, e.g. provision-then-add-inbound), and
		// a forced xray restart binds the per-inbound dokodemo ports. When a reboot
		// IS required (kernel modules only load into the freshly booted kernel) this
		// is skipped: the post-reboot panel start runs the same Init* path.
		if len(mods) == 0 {
			cs.l2tp.InitL2tp()
			cs.pptp.InitPptp()
			cs.openvpn.InitOpenVpn()
			cs.ocserv.InitOcserv()
			cs.sstp.InitSstp()
			cs.ikev2.InitIkev2()
			if err := xrayplane.RequestRestart(true); err != nil {
				log.Warning("provision: failed to restart xray after setup:", err)
			}
		}

		provisionRun.mu.Lock()
		provisionRun.running = false
		provisionRun.done = true
		provisionRun.rebootRequired = len(mods) > 0
		provisionRun.rebootModules = mods
		provisionRun.rebootPkg = pkg
		provisionRun.mu.Unlock()
	}()
	return true
}

// ProvisionRunState is a snapshot of the background provisioning run, returned to
// the Core Settings page as it polls for live progress.
type ProvisionRunState struct {
	Running        bool            `json:"running"`
	Done           bool            `json:"done"`
	Steps          []ProvisionStep `json:"steps"`
	RebootRequired bool            `json:"rebootRequired"`
	RebootModules  []string        `json:"rebootModules"`
	RebootPkg      string          `json:"rebootPkg"`
}

// ProvisionState returns the current/most-recent provisioning run's progress: a
// copy of the steps emitted so far, whether it is running or done, and whether a
// reboot is needed to finish (kernel modules that only load on a fresh boot).
func ProvisionState() ProvisionRunState {
	provisionRun.mu.Lock()
	defer provisionRun.mu.Unlock()
	steps := make([]ProvisionStep, len(provisionRun.steps))
	copy(steps, provisionRun.steps)
	mods := make([]string, len(provisionRun.rebootModules))
	copy(mods, provisionRun.rebootModules)
	return ProvisionRunState{
		Running:        provisionRun.running,
		Done:           provisionRun.done,
		Steps:          steps,
		RebootRequired: provisionRun.rebootRequired,
		RebootModules:  mods,
		RebootPkg:      provisionRun.rebootPkg,
	}
}

// Reboot restarts the host machine after a short delay so the in-flight HTTP
// response is delivered first. It is used to load kernel modules that a
// provisioning package added but that only become active in a freshly booted
// kernel (L2TP/PPTP on minimal cloud images).
func (s *CoreService) Reboot() error {
	if !commandExists("systemctl") && !commandExists("reboot") && !commandExists("shutdown") {
		return fmt.Errorf("no reboot command available on this host")
	}
	go func() {
		time.Sleep(1500 * time.Millisecond)
		if commandExists("systemctl") {
			if err := exec.CommandContext(context.Background(), "systemctl", "reboot").Run(); err == nil {
				return
			}
		}
		if commandExists("reboot") {
			if err := exec.CommandContext(context.Background(), "reboot").Run(); err == nil {
				return
			}
		}
		_ = exec.CommandContext(context.Background(), "shutdown", "-r", "now").Run()
	}()
	return nil
}

// firewallStepMsg summarizes what EnsureVpnHostNetworking did, for the setup output.
// firewalldRunning / vpnAddrSpace mirror nftables' unexported probes of the same
// names (nftables/nftables.go:30,40,99) — the strings must stay in sync.
func firewallStepMsg() string {
	if firewalldRunning() {
		return "firewalld active — trusted " + vpnAddrSpace
	}
	return "rp_filter set loose; no active firewalld"
}

const vpnAddrSpace = "10.0.0.0/12"

func firewalldRunning() bool {
	out, err := exec.CommandContext(context.Background(), "firewall-cmd", "--state").CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) == "running"
}

func msgOrOK(err error) string {
	if err != nil {
		return err.Error()
	}
	return "ok"
}
