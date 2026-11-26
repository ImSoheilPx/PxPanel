// Package config is the VPN layer's view of the panel configuration.
//
// vpn-ui carried its own config package (embedded version/name, env handling,
// bin/log/db folder resolution). The pxpanel target already provides every one
// of those surfaces through internal/config under the PXPANEL_* environment
// names, so this package does not re-implement them: it delegates, and holds
// only the pieces that are genuinely VPN-layer-specific (the fixed /etc host
// directory the VPN daemons and the ownership manifest share, which the core
// panel never touches).
//
// Keep the delegation one-way: vpn/* packages import THIS, never
// internal/config directly, so a later rename or a policy change (e.g. moving
// the daemon bin dir) stays a one-file edit.
package config

import (
	targetconfig "github.com/ImSoheilPx/pxpanel/internal/config"
)

// VPNDir is the panel's own /etc directory. vpn-ui used /etc/vpn-ui; the
// pxpanel port uses /etc/pxpanel. The ownership manifest (internal/vpn/manifest)
// treats everything under this prefix as panel-private.
const VPNDir = "/etc/pxpanel"

// GetBinFolderPath resolves the shared binary-extraction directory (env
// PXPANEL_BIN_FOLDER, default "bin"). The Xray core AND the VPN daemons extract
// here — one folder is the contract that lets the daemons and the core find
// each other's helpers.
func GetBinFolderPath() string { return targetconfig.GetBinFolderPath() }

// GetLogFolder resolves the log directory (env PXPANEL_LOG_FOLDER).
func GetLogFolder() string { return targetconfig.GetLogFolder() }

// IsDebug reports debug mode (env PXPANEL_DEBUG=true).
func IsDebug() bool { return targetconfig.IsDebug() }

// GetLogLevel returns the configured log level, defaulting to info.
func GetLogLevel() targetconfig.LogLevel { return targetconfig.GetLogLevel() }
