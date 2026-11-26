package wgc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/manifest"
)

// PORT NOTE: vpn-ui's wgc_test.go also carried TestWgcConfigFetchDB and
// TestWgcXrayConfig (real sqlite DB + the bundled xray binary + XrayService)
// and wgc_multi_inbound_test.go (NormalizeVpnRanges/AutoExpandVpnRanges over a
// seeded DB). Those exercise the inbound-save/normalize path and the Xray
// config assembly, which belong to the controllers/config waves; they are
// re-landed there. wgc_client_roundtrip_test.go guards the FRONTEND's
// inbound.js model against the Go struct — a frontend-wave contract test.
// The tests below cover the pure service logic (key reconcile, block math,
// config rendering) exactly as vpn-ui's did.

// TestWgcRenderDiag mirrors the E2E harness wg-c inbound (2 clients, userLimit 6, no keys
// sent) to check that ReconcileKeys mints keys and RenderClientConfigs returns a config.
func TestWgcRenderDiag(t *testing.T) {
	settings := `{"dns1":"1.1.1.1","dns2":"8.8.8.8","mtu":1420,"pskEnable":false,` +
		`"clientToClient":true,"crossInbound":true,"userLimit":6,"ipRanges":["10.7.7.2-10.7.7.254"],` +
		`"clients":[{"email":"wg-ca@t","enable":true,"id":"wg-ca"},` +
		`{"email":"wg-cb@t","enable":true,"id":"wg-cb"}]}`
	ib := &model.Inbound{Id: 12, Port: 51820, Protocol: defaults.ProtoWGC, Enable: true, Tag: "inbound-51820", Settings: settings}
	s := &WgcService{}

	changed, err := s.ReconcileKeys(ib)
	if err != nil {
		t.Fatalf("ReconcileKeys err: %v", err)
	}
	t.Logf("ReconcileKeys changed=%v", changed)
	cfgs, err := s.RenderClientConfigs(ib, "wg-ca@t", "1.2.3.4")
	t.Logf("RenderClientConfigs -> %d configs, err=%v", len(cfgs), err)
	if len(cfgs) == 0 {
		t.Fatalf("EXPECTED >=1 config for wg-ca@t, got 0")
	}
}

// The fixtures below carry an explicit ipRanges. They used to write it as a CIDR
// ("10.7.7.0/24"), which parseRange rejects outright (a range needs a hyphen), so
// subnetsOf saw nothing, vpnBlock silently fell back to the id-derived 10.7.{id}
// and the tests exercised the fallback while appearing to cover stored ranges.
// That gap matters now that an inbound KEEPS its stored block instead of
// re-deriving it (keepOwnedBlock in vpnrange.go).
//
// The inbound id here is deliberately 12 while the stored block is 10.7.7, so this
// can only pass if the STORED range is the one being honoured.
func TestWgcHonoursItsStoredRangeNotTheIdFallback(t *testing.T) {
	settings := `{"mtu":1420,"userLimit":6,"ipRanges":["10.7.7.2-10.7.7.254"],` +
		`"clients":[{"email":"wg-ca@t","enable":true,"id":"wg-ca"}]}`
	ib := &model.Inbound{Id: 12, Port: 51820, Protocol: defaults.ProtoWGC, Enable: true, Settings: settings}
	s := &WgcService{}

	parsed, err := s.parseSettings(ib)
	if err != nil {
		t.Fatalf("parseSettings: %v", err)
	}
	if got := parsed.effectiveRanges(); len(got) != 1 {
		t.Fatalf("stored ranges did not survive parsing: %v", got)
	}
	netAddr, prefix := wgcBlockFor(ib, parsed)
	if netAddr.String() != "10.7.7.0" || prefix != 24 {
		t.Errorf("block = %s/%d, want 10.7.7.0/24 (10.7.12.x means the stored range was ignored)",
			netAddr, prefix)
	}
	if got := s.GetSubnetForInbound(ib); got != "10.7.7.0/24" {
		t.Errorf("GetSubnetForInbound = %q, want 10.7.7.0/24", got)
	}
}

// wg-c carries the SAME per-device contract as awg (it had the identical collision: one
// keypair per account meant two devices got one config, one IP, and could not both stay
// online). User Limit K must yield K SEPARATE configs: K keypairs and K distinct /32s.
func TestWgcUserLimitYieldsOneConfigPerDevice(t *testing.T) {
	inb := &model.Inbound{
		Id: 21, Protocol: defaults.ProtoWGC, Port: 51820, Enable: true,
		Settings: `{"ipRanges":["10.7.21.2-10.7.21.254"],"userLimit":2,
			"clients":[{"email":"wtwo@t","enable":true}]}`,
	}
	var s WgcService
	if _, err := s.ReconcileKeys(inb); err != nil {
		t.Fatalf("ReconcileKeys: %v", err)
	}
	cfgs, err := s.RenderClientConfigs(inb, "wtwo@t", "example.test")
	if err != nil {
		t.Fatalf("RenderClientConfigs: %v", err)
	}
	if len(cfgs) != 2 {
		t.Fatalf("configs = %d, want 2 (one per device)", len(cfgs))
	}
	if cfgs[0].IP == cfgs[1].IP {
		t.Fatalf("both devices got tunnel IP %s", cfgs[0].IP)
	}
	for i, c := range cfgs {
		if !strings.HasSuffix(c.IP, "/32") {
			t.Errorf("config %d IP = %s, want /32", i, c.IP)
		}
	}
	keyOf := func(cfg string) string {
		for _, line := range strings.Split(cfg, "\n") {
			if v, ok := strings.CutPrefix(line, "PrivateKey = "); ok {
				return v
			}
		}
		return ""
	}
	if keyOf(cfgs[0].Config) == keyOf(cfgs[1].Config) {
		t.Fatal("both wg-c configs carry the same PrivateKey")
	}
}

// An account that predates per-device keys must keep its ORIGINAL key as device 0, so a
// config already deployed on a customer's machine keeps working across the upgrade.
func TestWgcLegacyKeyAdoptedAsDeviceZero(t *testing.T) {
	legacyPriv := "aFq4hJ4Zt0nJ1r3vQq6mB8pQ2xY7wKcW9dE5sT1uZ0g="
	inb := &model.Inbound{
		Id: 22, Protocol: defaults.ProtoWGC, Port: 51820, Enable: true,
		Settings: `{"ipRanges":["10.7.22.2-10.7.22.254"],"userLimit":2,
			"clients":[{"email":"legacy@t","enable":true,"privKey":"` + legacyPriv + `","pubKey":"x"}]}`,
	}
	var s WgcService
	if _, err := s.ReconcileKeys(inb); err != nil {
		t.Fatalf("ReconcileKeys: %v", err)
	}
	var parsed wgcSettings
	if err := json.Unmarshal([]byte(inb.Settings), &parsed); err != nil {
		t.Fatalf("settings: %v", err)
	}
	devs := parsed.Clients[0].deviceList()
	if len(devs) != 2 {
		t.Fatalf("device slots = %d, want 2", len(devs))
	}
	if devs[0].PrivKey != legacyPriv {
		t.Errorf("device 0 key = %q, want the pre-existing account key (deployed configs would break)", devs[0].PrivKey)
	}
}

// The interface name must stay inside IFNAMSIZ and keep the exact shape the
// manifest's ownership test matches (vpn-ui pinned this implicitly through
// ifaceown.go; pin it explicitly here).
func TestWgcIfaceNameShape(t *testing.T) {
	for _, id := range []int{0, 1, 12, 4096, 999999} {
		name := wgIfaceName(id)
		if len(name) > 15 {
			t.Errorf("wgIfaceName(%d) = %q exceeds IFNAMSIZ-1", id, name)
		}
		if !manifest.WgcOwnedName(name) {
			t.Errorf("wgIfaceName(%d) = %q is not matched by the ownership name shape; the stale-link sweep would never reclaim it", id, name)
		}
	}
}
