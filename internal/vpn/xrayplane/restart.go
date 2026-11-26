// Restart-request seams. Ported from vpn-ui web/service/xray.go's restart
// surface, reshaped as hooks: the target's internal/web already ships the
// Xray restart machinery for its own lineage (XrayService.RestartXray /
// SetToNeedRestart), and internal/vpn cannot import internal/web (cycle) — so
// the web wave wires the hooks at start-up and every vpn-side package raises
// them through here.
package xrayplane

import (
	"sync"

	"github.com/ImSoheilPx/pxpanel/internal/vpn/log"
)

var (
	restartHooksMu sync.RWMutex
	// restartHook is the web layer's RestartXray(force). Nil until wired.
	restartHook func(force bool) error
	// needRestartHook is the web layer's SetToNeedRestart (the debounced
	// request). Nil until wired.
	needRestartHook func()
)

// SetRestartHook wires RequestRestart to the web layer's XrayService.RestartXray.
// TODO(controllers wave): call at server start-up:
//
//	xrayplane.SetRestartHook(theXrayService.RestartXray)
//	xrayplane.SetNeedRestartHook(theXrayService.SetToNeedRestart)
func SetRestartHook(fn func(force bool) error) {
	restartHooksMu.Lock()
	restartHook = fn
	restartHooksMu.Unlock()
}

// SetNeedRestartHook wires RequestNeedRestart to the web layer's debounced
// restart request.
func SetNeedRestartHook(fn func()) {
	restartHooksMu.Lock()
	needRestartHook = fn
	restartHooksMu.Unlock()
}

// RequestRestart rebuilds the core config and restarts Xray now (force=true
// even when the built config is unchanged). Unwired, this is a logged no-op —
// the vpn waves must stay usable in tooling and tests where no core is managed.
func RequestRestart(force bool) error {
	restartHooksMu.RLock()
	fn := restartHook
	restartHooksMu.RUnlock()
	if fn == nil {
		log.Warning("xrayplane: restart requested but no restart hook is wired (web layer not up)")
		return nil
	}
	return fn(force)
}

// RequestNeedRestart marks that Xray needs a (debounced) restart.
//
// Why a REQUEST rather than a direct restart for account edits: the relay
// protocols (mtproto, ssh) egress through a paired Xray socks inbound and
// authenticate as the account's email. Xray's socks inbound has no AddUser API,
// so that account list is fixed at config time and ONLY a restart applies it.
// A relay client add therefore MUST raise this — otherwise the new client is
// created, telemt/SSH accept it, and Xray silently drops its egress until some
// unrelated edit restarts the core. vpn-ui also kept a debounce on the fire
// side (2s settle / 30s max) so a burst of edits collapses into one restart;
// the target's web layer owns that side.
func RequestNeedRestart() {
	restartHooksMu.RLock()
	fn := needRestartHook
	restartHooksMu.RUnlock()
	if fn == nil {
		log.Warning("xrayplane: need-restart requested but no hook is wired (web layer not up)")
		return
	}
	fn()
}
