// Core-config override APPLY shim (the consolidation of the former
// package-local copy of vpn-ui web/service/coreconfig.go's apply half).
//
// openvpn used to carry its own cache + settings read + merge here — a third
// copy of the same code, with the same stale-cache hazard that had: a write
// through the shared package never refreshed this package's private cache.
// The whole implementation now lives in internal/vpn/coreconfig (the single
// home: one cache, one merge, one invalidation point) and this file keeps only
// the package-local name the generator call sites use, delegating to it.
//
// PORT NOTE: ocserv still carries the same package-local copy it was written
// alongside (ocserv/coreconfig.go); migrating it is the ocserv wave's edit.
//
// The settings read happens inside coreconfig, through the root package's
// injected DB handle (vpn.DB) against model.Setting (key
// "coreConfigOverrides") — vpn-ui went through its SettingService.
package openvpn

import (
	"github.com/ImSoheilPx/pxpanel/internal/vpn/coreconfig"
)

// applyCoreConfigOverride merges the stored override into the body a generator
// just rendered (vpn-ui coreconfig.go:applyCoreConfigOverride, via the shared
// coreconfig package). This is THE apply point: the generator calls it as the
// last thing before writing, so the set of files an operator can override is
// the set of call sites of this function and nothing else.
//
// APPEND SEMANTICS ARE NOT UNIFORM ACROSS DAEMONS: OpenVPN keeps the FIRST
// occurrence of a directive and ignores later ones, so an appended line here
// can only ADD an option the generated body never sets. The editor posts
// replace over the whole file, so what the operator sees is what lands.
func applyCoreConfigOverride(core string, inboundId int, file, rendered string) string {
	return coreconfig.ApplyCoreConfigOverride(core, inboundId, file, rendered)
}
