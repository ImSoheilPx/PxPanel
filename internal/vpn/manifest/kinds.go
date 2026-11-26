// Exported artifact-kind constants + the mayDelete probe, for the protocol
// packages that record host state in the ownership manifest from outside this
// one (vpn-ui: ownIface / ownFouPort / ownEthtool + ownState.mayDelete, all
// package-level in web/service).
//
// Restated as constants (the values must stay byte-identical to the manifest
// file's kinds) rather than reaching into the unexported names.
package manifest

// Kind constants for the artifacts the protocol services claim directly:
// network interfaces, FOU (UDP-encapsulation) receive ports, and ethtool
// offload settings.
const (
	KindIface   = ownIface   // "iface"
	KindFouPort = ownFouPort // "fouport"
	KindEthtool = ownEthtool // "ethtool"
)

// MayDelete reports whether the recorded artifact (kind, id) is one the panel
// created itself, i.e. safe to withdraw. Unrecorded or pre-existing artifacts
// answer false: the whole point of the manifest is that a record nobody wrote
// is never deleted. (vpn-ui: ownStateOf + ownState.mayDelete.)
func MayDelete(kind, id string) bool {
	state, found := StateOf(kind, id)
	return found && state.mayDelete()
}
