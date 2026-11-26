// The provisioned-core record: the settings-KV rows vpn-ui's SettingService
// kept under "vpnProvisioned" and "provisionedProtocols" (setting.go:400-540),
// ported as direct model.Setting KV reads/writes through the root package's
// injected DB handle — the settings service is a later wave, and the row shape
// is identical.
//
// These two rows are the authoritative "is it installed" answer for everything
// downstream: the status cards, the inbound-creation gate, and the
// shared-requirement arithmetic that decides what an uninstall may remove.
package coresettings

import (
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
)

// provisionedNone is what SetProvisionedProtocols stores when the list is
// empty, so "never recorded" (empty string) stays distinguishable from
// "recorded as none" (vpn-ui setting.go:504).
const provisionedNone = "none"

// settings rows (the vpn-ui keys, kept so a migrated DB keeps working).
const (
	keyVpnProvisioned       = "vpnProvisioned"
	keyProvisionedProtocols = "provisionedProtocols"
)

// settingGetString returns a settings-KV row's raw value.
func settingGetString(key string) (string, bool) {
	db := vpn.DB()
	if db == nil {
		return "", false
	}
	var row model.Setting
	if err := db.Where(model.Setting{Key: key}).First(&row).Error; err != nil {
		return "", false
	}
	return row.Value, true
}

// settingPutString writes a settings-KV row. model.Setting.key carries a PLAIN
// index (idx_settings_key), not a unique one, so an ON CONFLICT upsert has no
// target — do the read-then-write manually (same semantics as vpn-ui's
// SettingService.setString).
func settingPutString(key, value string) error {
	db := vpn.DB()
	if db == nil {
		return errNoDatabase
	}
	setting := model.Setting{Key: key, Value: value}
	var existing model.Setting
	if err := db.Where(model.Setting{Key: key}).First(&existing).Error; err == nil {
		return db.Model(&model.Setting{}).Where("id = ?", existing.Id).Update("value", value).Error
	}
	return db.Create(&setting).Error
}

func settingGetBool(key string) (bool, error) {
	raw, ok := settingGetString(key)
	if !ok {
		return false, errNoDatabase
	}
	v := strings.TrimSpace(raw)
	if v == "" {
		return false, nil
	}
	return v == "true" || v == "1", nil
}

func settingPutBool(key string, value bool) error {
	if value {
		return settingPutString(key, "true")
	}
	return settingPutString(key, "false")
}

// errNoDatabase is what the KV helpers answer when no DB handle is wired
// (tests, GOOS builds) — the same degrade-the-callers-already-handle shape the
// root package's seam uses.
var errNoDatabase = errorString("no database")

type errorString string

func (e errorString) Error() string { return string(e) }

// GetVpnProvisioned reports whether the VPN backend has been provisioned via
// the Core Settings "Initialize Setup" flow. Any error (missing key, parse) is
// treated as not-provisioned so a fresh install shows the setup call-to-action.
func GetVpnProvisioned() bool {
	v, err := settingGetBool(keyVpnProvisioned)
	if err != nil {
		return false
	}
	return v
}

// SetVpnProvisioned persists whether the VPN backend has been provisioned.
func SetVpnProvisioned(value bool) error {
	return settingPutBool(keyVpnProvisioned, value)
}

// GetProvisionedProtocols returns the VPN cores the host is provisioned for, as
// recorded by SetProvisionedProtocols. Empty both when never recorded and when
// recorded as none; use HasRecordedProvisionedProtocols to tell those apart.
func GetProvisionedProtocols() []string {
	v, ok := settingGetString(keyProvisionedProtocols)
	if !ok || strings.TrimSpace(v) == provisionedNone {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// HasRecordedProvisionedProtocols reports whether this install has ever recorded
// its core set, that is, whether the empty result above means "none, and we know
// it" rather than "we have no idea".
func HasRecordedProvisionedProtocols() bool {
	v, ok := settingGetString(keyProvisionedProtocols)
	return ok && strings.TrimSpace(v) != ""
}

// SetProvisionedProtocols records (comma-separated) the VPN cores the host is
// provisioned for. Called after a setup run and after an uninstall, so the two
// always agree on what is installed.
func SetProvisionedProtocols(list []string) error {
	joined := strings.Join(list, ",")
	if strings.TrimSpace(joined) == "" {
		joined = provisionedNone
	}
	return settingPutString(keyProvisionedProtocols, joined)
}
