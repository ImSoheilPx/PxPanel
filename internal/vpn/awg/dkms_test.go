package awg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/vpn/awg/awgsrc"
)

// PORT NOTE: vpn-ui's awg_support_test.go, verbatim (parseKernelVersion is a
// package-local copy here, fed by pkgmgr.RunningKernel through
// runningKernelVersion).

// runningKernelVersion feeds the compatibility gate, so its parsing has to survive the
// real-world shapes of `uname -r` across the supported matrix.
func TestRunningKernelVersionParsing(t *testing.T) {
	cases := []struct {
		in       string
		maj, min int
		ok       bool
	}{
		{"6.8.0-136-generic", 6, 8, true},             // ubuntu 24
		{"7.0.0-28-generic", 7, 0, true},              // ubuntu 26
		{"6.1.0-51-amd64", 6, 1, true},                // debian 12
		{"6.12.95+deb13-amd64", 6, 12, true},          // debian 13 (note the +deb13)
		{"6.12.86+deb13-cloud-amd64", 6, 12, true},    // debian 13 cloud flavour
		{"7.1.3-arch2-2", 7, 1, true},                 // arch
		{"7.1.3-101.fc43.x86_64", 7, 1, true},         // fedora 43
		{"5.14.0-687.26.1.el9_8.x86_64", 5, 14, true}, // alma/rocky/centos 9
		{"6.12.0-246.el10.x86_64", 6, 12, true},       // el10
		{"", 0, 0, false},
		{"garbage", 0, 0, false},
	}
	for _, c := range cases {
		maj, min, ok := parseKernelVersion(c.in)
		if ok != c.ok || (ok && (maj != c.maj || min != c.min)) {
			t.Errorf("parseKernelVersion(%q) = %d,%d,%v; want %d,%d,%v",
				c.in, maj, min, ok, c.maj, c.min, c.ok)
		}
	}
}

// Kernel 7.1 removed ipv6_stub and the module has not adapted, so 7.1+ must be refused
// whatever the distro is. Verified on the matrix: fedora 43/44 and arch all fail there.
func TestAwgUnsupportedOnKernel71Plus(t *testing.T) {
	for _, k := range []string{"7.1.3-arch2-2", "7.1.3-101.fc43.x86_64", "8.0.0-1-generic"} {
		maj, min, ok := parseKernelVersion(k)
		if !ok {
			t.Fatalf("could not parse %q", k)
		}
		if maj < 7 || (maj == 7 && min < 1) {
			t.Errorf("%q parsed as %d.%d, which the gate would wrongly allow", k, maj, min)
		}
	}
	// and the kernels that DID build must not be caught by the same rule
	for _, k := range []string{"6.8.0-136-generic", "7.0.0-28-generic", "6.12.95+deb13-amd64"} {
		maj, min, _ := parseKernelVersion(k)
		if maj > 7 || (maj == 7 && min >= 1) {
			t.Errorf("%q (%d.%d) would be refused, but it builds fine", k, maj, min)
		}
	}
}

// The refusal message has to name the distros that actually work, or it is not actionable.
func TestAwgSupportedDistrosNamed(t *testing.T) {
	for _, want := range []string{"Debian 12", "Debian 13", "Ubuntu 24.04", "Ubuntu 26.04"} {
		if !strings.Contains(awgSupportedDistros, want) {
			t.Errorf("awgSupportedDistros is missing %q; operators would not know what to switch to", want)
		}
	}
}

// The embedded module source must really be there: Extract is what a Core Settings
// DKMS build runs, and an empty embed would fail only on the host, months later.
func TestAwgsrcEmbedCarriesTheModuleTree(t *testing.T) {
	dir := t.TempDir()
	if err := awgsrc.Extract(dir); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	for _, f := range []string{"Makefile", "dkms.conf", "device.c", "netlink.c", "allowedips.c"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("embedded source tree missing %s: %v", f, err)
		}
	}
}
