// Speed-limit sidecar surface, ported from vpn-ui xray/process.go
// (GetSpeedLimitPath + the XRAY_SPEEDLIMIT_FILE env contract).
package xrayplane

import (
	"os"
	"path/filepath"

	vpnconfig "github.com/ImSoheilPx/pxpanel/internal/vpn/config"
)

// SpeedLimitFilename is the sidecar file name beside config.json.
const SpeedLimitFilename = "speedlimits.json"

// SpeedLimitEnvVar is the environment variable the patched core reads to find
// the sidecar (an env var rather than a config section because Xray's app
// configs are protobuf Any values, so a plain JSON side-channel there would
// drag infra/conf and codegen into the fork patch, and because anything in
// the config restarts Xray on every change).
const SpeedLimitEnvVar = "XRAY_SPEEDLIMIT_FILE"

// GetSpeedLimitPath returns the path to the per-account speed limit sidecar file.
//
// The rates live BESIDE config.json rather than in it: they change whenever an
// account crosses its "Limit After" threshold, and anything inside the Config graph
// makes Config.Equals report a change, which restarts Xray and drops every live
// connection on the box. The patched core watches this file's mtime instead, so a
// rate change costs a reload of one small JSON document.
func GetSpeedLimitPath() string {
	return vpnconfig.GetBinFolderPath() + "/" + SpeedLimitFilename
}

// SpeedLimitEnv returns the KEY=VALUE environment entry to hand the core process
// so it finds the sidecar. The path is resolved to an absolute one: the core's
// cmd.Dir is never set, so it inherits whatever cwd the panel was started with,
// and GetBinFolderPath is RELATIVE ("bin") unless PXPANEL_BIN_FOLDER overrides
// it. Resolving here pins the path to the cwd the panel itself resolves "bin"
// against, instead of trusting Xray to resolve it the same way.
//
// TODO(speedlimit wave): internal/xray's Start has no env hook yet — attach
// this entry to the core process env at wire-up, and keep rate changes out of
// the xray.Config graph so a rate edit never restarts the core.
func SpeedLimitEnv() string {
	p := GetSpeedLimitPath()
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	return SpeedLimitEnvVar + "=" + p
}

// WriteSpeedLimitSidecar is the minimal writer the sidecar wave replaces: it
// persists one JSON document (already marshalled by the caller) to
// GetSpeedLimitPath. Kept beside the path helper so the file's location has
// exactly one definition even before the sidecar wave lands.
func WriteSpeedLimitSidecar(data []byte) error {
	return os.WriteFile(GetSpeedLimitPath(), data, 0o644)
}
