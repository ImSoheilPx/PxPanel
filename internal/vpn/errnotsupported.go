// Kernel-feature errno classification shared by the three daemon-less protocol
// services (vpn-ui wgc.go:isNotSupported, used by wgc/awg/gre ensureLink).
package vpn

import (
	"errors"
	"strings"
	"syscall"
)

// ErrNotSupported reports whether err is the "operation not supported" errno the
// kernel returns for `ip link add type wireguard|amneziawg` (and the GRE encap
// paths) when the module is missing. Callers turn it into a targeted warning
// instead of a generic netlink failure.
func ErrNotSupported(err error) bool {
	if errors.Is(err, syscall.EOPNOTSUPP) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "not supported")
}
