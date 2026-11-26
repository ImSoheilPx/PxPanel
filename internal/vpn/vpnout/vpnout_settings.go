package vpnout

// Settings seams over vpn.DB() (vpn-ui reached SettingService from the one
// `service` package). Same shape as the ssh package's seams in
// internal/vpn/ssh/sshoutbound.go — including its TODO(settings wave): re-point
// at the settings service so reads share its caching and error paths.

import (
	"errors"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	vpn "github.com/ImSoheilPx/pxpanel/internal/vpn"

	"gorm.io/gorm"
)

// settingsGetString reads one settings KV row (vpn-ui SettingService.getString).
// The `vpnOutbounds` row has no entry in any defaults map that matters here — an
// absent or unreadable row simply means "no tunnels configured", which is what
// vpn-ui's load() treated an error as too.
func settingsGetString(key string) (string, error) {
	db := vpn.DB()
	if db == nil {
		return "", nil
	}
	var setting model.Setting
	err := db.Where("key = ?", key).First(&setting).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", err
	}
	return setting.Value, nil
}

// settingsSetString upserts one settings KV row (vpn-ui
// SettingService.setString/saveSetting: Create on absent, Save on present).
func settingsSetString(key, value string) error {
	db := vpn.DB()
	if db == nil {
		return errors.New("vpn outbound: no database handle wired (vpn.SetDB)")
	}
	var setting model.Setting
	err := db.Where("key = ?", key).First(&setting).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return db.Create(&model.Setting{Key: key, Value: value}).Error
		}
		return err
	}
	setting.Key = key
	setting.Value = value
	return db.Save(&setting).Error
}

// vpnOutTemplateConfig reads the operator's stored Xray template
// (vpn-ui SettingService.GetXrayConfigTemplate; the target keeps the template
// in the same `xrayTemplateConfig` settings row the database layer fixes up).
// A missing or unreadable row returns "" and the caller treats it as "no
// template", which is how vpn-ui behaved.
func vpnOutTemplateConfig() (string, error) {
	return settingsGetString("xrayTemplateConfig")
}
