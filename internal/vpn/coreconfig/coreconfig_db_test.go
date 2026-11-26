//go:build linux && cgo

package coreconfig

// The DB-backed round-trip, from vpn-ui coreconfig_test.go's database half. An
// override the editor stores has to come back out of the settings row and into
// the generator's output, keyed to the right file. Gated to linux+cgo like the
// other vpn waves' _db_test.go files (CGO sqlite; CI runs this file).

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/op/go-logging"

	"github.com/ImSoheilPx/pxpanel/internal/database"
	"github.com/ImSoheilPx/pxpanel/internal/logger"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
)

// The corrupt-JSON warning path logs unconditionally, and logger.Warning
// dereferences a package global that is nil until InitLogger runs.
var cfgTestLoggerOnce sync.Once

func newCoreConfigDB(t *testing.T) {
	t.Helper()
	cfgTestLoggerOnce.Do(func() { logger.InitLogger(logging.ERROR) })
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	vpn.SetDB(database.GetDB)
}

// resetCoreConfigCacheForTest forces the next read to go back to the database.
func resetCoreConfigCacheForTest() {
	coreConfigCache.Lock()
	coreConfigCache.loaded = false
	coreConfigCache.m = nil
	coreConfigCache.Unlock()
}

// TestApplyCoreConfigOverrideRoundTrip closes the loop the unit tests only cover
// halfway: an override the editor stores has to come back out of the settings row
// and into the generator's output, keyed to the right file.
func TestApplyCoreConfigOverrideRoundTrip(t *testing.T) {
	newCoreConfigDB(t)

	// A fresh install has never written the row. This must read as "no overrides",
	// not as a failure that leaves the generators unable to write anything.
	resetCoreConfigCacheForTest()
	if got := ApplyCoreConfigOverride("l2tp", 0, "xl2tpd.conf", "body\n"); got != "body\n" {
		t.Fatalf("an unset override changed the render: %q", got)
	}

	if err := SetOverrides(map[string]CoreConfigOverride{
		Key("openvpn", 7, "server-udp.conf"): {Mode: ModeAppend, Text: "verb 4"},
		Key("mtproto", 3, "config.toml"):     {Mode: ModeReplace, Text: "[general]\n"},
	}); err != nil {
		t.Fatalf("store: %v", err)
	}
	// Drop the cache so this really re-reads the row rather than the map just written.
	resetCoreConfigCacheForTest()

	udp := ApplyCoreConfigOverride("openvpn", 7, "server-udp.conf", "port 1194\n")
	if !strings.Contains(udp, "port 1194") || !strings.Contains(udp, "verb 4") {
		t.Fatalf("the openvpn override did not round-trip:\n%s", udp)
	}
	// The other transport of the SAME inbound must be untouched.
	if tcp := ApplyCoreConfigOverride("openvpn", 7, "server-tcp.conf", "port 1194\n"); tcp != "port 1194\n" {
		t.Fatalf("the override leaked onto the other transport:\n%s", tcp)
	}
	// And another inbound of the same core.
	if other := ApplyCoreConfigOverride("openvpn", 8, "server-udp.conf", "port 1194\n"); other != "port 1194\n" {
		t.Fatalf("the override leaked onto another inbound:\n%s", other)
	}
	if toml := ApplyCoreConfigOverride("mtproto", 3, "config.toml", "generated\n"); toml != "[general]\n" {
		t.Fatalf("replace mode did not round-trip: %q", toml)
	}

	ClearCoreConfigOverrides("openvpn")
	resetCoreConfigCacheForTest()
	if got := ApplyCoreConfigOverride("openvpn", 7, "server-udp.conf", "port 1194\n"); got != "port 1194\n" {
		t.Fatalf("uninstall did not clear the openvpn override:\n%s", got)
	}
	if got := ApplyCoreConfigOverride("mtproto", 3, "config.toml", "generated\n"); got != "[general]\n" {
		t.Fatal("clearing one core's overrides took another core's with it")
	}
}
