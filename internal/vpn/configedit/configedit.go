// Package configedit is now a THIN ALIAS over internal/vpn/coreconfig.
//
// It began (P1) as the ported storage+merge+apply half of vpn-ui
// web/service/coreconfig.go, its own package so the per-protocol generators
// could merge an operator's stored edit without importing the web layer. The
// core wave (P3) then landed internal/vpn/coreconfig with the same machinery
// and a SECOND cache over the same settings row — a write through one left the
// other stale until process restart. The consolidation keeps coreconfig as the
// single home (one cache, one merge, one invalidation point) and turns this
// package into aliases so the existing callers — l2tp, pptp, ipsec — keep
// compiling untouched. New code should import coreconfig directly.
//
// Provenance of the machinery: vpn-ui (Sir-MmD/vpn-ui, 3x-ui v2.9.3 fork)
// web/service/coreconfig.go, verbatim except that SettingService
// getString/setString became direct reads/writes of the model.Setting KV row
// (the settings service lands in a later wave) and the panel brand in the
// banner is pxpanel.
package configedit

import (
	"github.com/ImSoheilPx/pxpanel/internal/vpn/coreconfig"
)

// Override modes (vpn-ui coreconfig.go:37-53; semantics documented in
// coreconfig — append is stored and accepted, replace is what the editor posts).
const (
	ModeAppend  = coreconfig.ModeAppend
	ModeReplace = coreconfig.ModeReplace
)

// Banner marks where the panel's render stops and the operator's text starts.
const Banner = coreconfig.Banner

// Override is one stored edit.
type Override = coreconfig.CoreConfigOverride

// Key is the key one override is stored under: the core, the owning inbound
// (0 for a file the whole protocol shares), and a file discriminator.
func Key(core string, inboundId int, file string) string {
	return coreconfig.Key(core, inboundId, file)
}

// Overrides returns every stored override.
//
// A corrupt blob degrades to "no overrides" rather than an error. The
// generators call this on every run, so failing here would leave the panel
// unable to write ANY config until the row was fixed by hand, and overrides
// are an opt-in extra.
func Overrides() map[string]Override { return coreconfig.Overrides() }

// SetOverrides stores the whole map and refreshes the single shared cache.
func SetOverrides(m map[string]Override) error { return coreconfig.SetOverrides(m) }

// CopyOverrides returns a map a caller may mutate without racing the cache.
func CopyOverrides() map[string]Override { return coreconfig.CopyOverrides() }

// StoreOverride validates the mode and stores one override (the storage half
// of vpn-ui's SaveCoreConfigOverride; the endpoint flow is the controllers
// wave's).
func StoreOverride(core string, inboundId int, file, mode, text string) error {
	return coreconfig.StoreOverride(core, inboundId, file, mode, text)
}

// ClearCoreConfigOverrides drops every override belonging to one core.
// Uninstalling a core has to call this.
func ClearCoreConfigOverrides(core string) { coreconfig.ClearCoreConfigOverrides(core) }

// ApplyOverride merges the stored override into the body a generator just
// rendered. This is THE apply point: every hooked generator calls it as the
// last thing before writing.
//
// APPEND SEMANTICS ARE NOT UNIFORM ACROSS DAEMONS (the full per-daemon
// rationale lives on ApplyCoreConfigOverride in coreconfig); the editor posts
// replace over the whole file, so what the operator sees is what lands.
func ApplyOverride(core string, inboundId int, file, rendered string) string {
	return coreconfig.ApplyCoreConfigOverride(core, inboundId, file, rendered)
}

// Merge is the merge itself, with the values passed in rather than read from
// the database, so a save can check the exact bytes BEFORE storing them.
func Merge(rendered, mode, text string) string {
	return coreconfig.MergeCoreConfig(rendered, mode, text)
}
