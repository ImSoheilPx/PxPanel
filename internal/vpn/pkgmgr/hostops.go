// Exported wrappers over pkgmgr's host-probing internals, for the protocol
// services that live outside this package (the AmneziaWG DKMS builder needs
// every one of these; wgc/awg/gre ask whether a kernel module is available).
//
// vpn-ui kept all of this in one web/service package, so the helpers were
// package-level. The port keeps the internals unexported (pkgmgr owns them) and
// exposes the thin read-only surface the protocol wave actually calls. Nothing
// here changes behaviour: each wrapper is a one-line pass-through.
package pkgmgr

// ModuleAvailable reports whether a kernel module can be used on the running
// kernel — already loaded, built into the kernel, or loadable on demand
// (vpn-ui: moduleAvailable).
func ModuleAvailable(name string) bool { return moduleAvailable(name) }

// RunningKernel returns the running kernel's release string (`uname -r`),
// or "" when it cannot be read.
func RunningKernel() string { return runningKernel() }

// CommandExists reports whether name resolves on PATH.
func CommandExists(name string) bool { return commandExists(name) }

// FileExists reports whether path exists (vpn-ui pkgmgr.go:fileExists).
func FileExists(path string) bool { return fileExists(path) }

// OSReleaseField reads one field from /etc/os-release ("ID", "ID_LIKE",
// "VERSION_ID", ...), or "" when absent.
func OSReleaseField(key string) string { return osReleaseField(key) }

// DistroPretty returns the human-readable distro name for setup messages.
func DistroPretty() string { return distroPretty() }

// IsUbuntu reports whether the apt-get host is Ubuntu (vs Debian).
func IsUbuntu() bool { return isUbuntu() }

// DebKernelArch returns the Debian kernel-package arch suffix (amd64, arm64...).
func DebKernelArch() string { return debKernelArch() }

// PackagesSupported reports whether the host has a package manager this panel
// knows how to drive. false means "install the prerequisites manually".
func PackagesSupported() bool { return detectPackageManager() != nil }

// PackageManagerName returns the detected package manager's display name
// ("apt", "dnf", ...), or "" when none is supported. Used for step labels.
func PackageManagerName() string {
	if pm := detectPackageManager(); pm != nil {
		return pm.name
	}
	return ""
}

// InstallPackage installs one distro package through the host package manager
// and returns the combined command output (for the setup console's per-step
// log). Refresh + non-interactive env are the manager's own. (vpn-ui:
// pm.installPackage; the manager is re-detected per call, which is cheap and
// keeps this seam stateless.)
func InstallPackage(pkg string) (log string, err error) {
	pm := detectPackageManager()
	if pm == nil {
		return "", ErrNoPackageManager
	}
	return pm.installPackage(pkg)
}

// ErrNoPackageManager is returned by InstallPackage on a host without a
// supported package manager.
var ErrNoPackageManager = &pkgMgrError{}

type pkgMgrError struct{}

func (e *pkgMgrError) Error() string {
	return "no supported package manager — install the package manually"
}

// SwanctlConfDir returns the swanctl connection drop-in directory the shared
// IPsec daemon reads (/etc/swanctl/conf.d, or the bundled-layout override once
// the ipsec wave populates IpsecHooks.SwanctlConfDir).
func SwanctlConfDir() string { return swanctlConf() }
