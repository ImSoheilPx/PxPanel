// Core-config override APPLY half, ported from vpn-ui web/service/coreconfig.go
// (see internal/vpn/openvpn/coreconfig.go for the full provenance note).
//
// The ocserv.conf generator needs the read+merge half today; the editor catalog
// and its endpoints are a later controllers wave. Carried package-locally here
// AND in openvpn — TODO(controllers wave): hoist into the shared coreconfig
// package and have every protocol call it, replacing both copies.
//
// One daemon-specific fact preserved from vpn-ui: ocserv (like pppd/xl2tpd/
// pptpd/accel-ppp) keeps the LAST occurrence of a directive, so an appended
// override line genuinely wins — unlike OpenVPN, which keeps the first.
package ocserv

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
)

// Override modes (vpn-ui coreconfig.go — shared with the openvpn package copy).
const (
	// CoreConfigModeAppend puts the override after the generated body. NO UI
	// offers this any more (the editor posts replace), but it is still stored,
	// merged and accepted by the endpoint, so an override written through the
	// API keeps working. Do not delete it as dead code.
	CoreConfigModeAppend = "append"
	// CoreConfigModeReplace makes the override the whole file.
	CoreConfigModeReplace = "replace"
)

// coreConfigBanner marks where the panel's render stops and the operator's text
// starts. ocserv.conf takes `#` as a line comment.
const coreConfigBanner = "# ---- pxpanel: operator override (Core Settings -> Edit config) ----"

// CoreConfigOverride is one stored edit.
type CoreConfigOverride struct {
	Mode string `json:"mode"`
	Text string `json:"text"`
}

// coreConfigCache memoizes the parsed override map (see the openvpn copy for why).
var coreConfigCache struct {
	sync.RWMutex
	loaded bool
	m      map[string]CoreConfigOverride
}

// coreConfigKey is the key one override is stored under: the core, the owning
// inbound (0 for a file the whole protocol shares), and a file discriminator.
func coreConfigKey(core string, inboundId int, file string) string {
	return fmt.Sprintf("%s:%d:%s", core, inboundId, file)
}

// getCoreConfigOverrides returns every stored override. A corrupt blob degrades
// to "no overrides" rather than an error (see the openvpn copy).
func getCoreConfigOverrides() map[string]CoreConfigOverride {
	coreConfigCache.RLock()
	if coreConfigCache.loaded {
		m := coreConfigCache.m
		coreConfigCache.RUnlock()
		return m
	}
	coreConfigCache.RUnlock()

	coreConfigCache.Lock()
	defer coreConfigCache.Unlock()
	coreConfigCache.m = map[string]CoreConfigOverride{}
	coreConfigCache.loaded = true

	db := vpn.DB()
	if db == nil {
		return coreConfigCache.m
	}
	var s model.Setting
	if err := db.Where("key = ?", "coreConfigOverrides").First(&s).Error; err != nil {
		return coreConfigCache.m
	}
	raw := s.Value
	if strings.TrimSpace(raw) == "" {
		return coreConfigCache.m
	}
	parsed := map[string]CoreConfigOverride{}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return coreConfigCache.m
	}
	coreConfigCache.m = parsed
	return coreConfigCache.m
}

// applyCoreConfigOverride merges the stored override into the body a generator
// just rendered. THE apply point (see the openvpn copy for the full comment).
func applyCoreConfigOverride(core string, inboundId int, file, rendered string) string {
	ov, ok := getCoreConfigOverrides()[coreConfigKey(core, inboundId, file)]
	if !ok {
		return rendered
	}
	return mergeCoreConfig(rendered, ov.Mode, ov.Text)
}

// mergeCoreConfig is the merge itself, with the values passed in rather than read
// from the database, so a save can check the exact bytes BEFORE storing them.
func mergeCoreConfig(rendered, mode, text string) string {
	if strings.TrimSpace(text) == "" {
		return rendered
	}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	if mode == CoreConfigModeReplace {
		return text
	}
	return strings.TrimRight(rendered, "\n") + "\n\n" + coreConfigBanner + "\n" + text
}
