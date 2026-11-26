package vpnout

// Runtime core-capability gate for the one patched-core dependency this family
// has: the CARRIER TUN (vpnoutcarrier.go's bridged carrier), which writes a
// `tun` INBOUND into the Xray config and routes it to the carrier outbound.
//
// Everything else the framework and the seven drivers emit is vanilla-official
// xray: freedom outbounds with streamSettings.sockopt.interface (the interface
// pin), blackhole fallbacks, plain routing rules, and client daemons driven
// outside the core entirely. The tun inbound, however, is recent-core material
// (xray-core 26.x); a core built without it refuses the WHOLE config, taking
// every inbound and every other tunnel down with one carrier — exactly the
// failure ApplyCarrierBridgesWith's comment warns about for a missing
// CAP_NET_ADMIN. So a bridged carrier is RESOLVED only when this host's core
// demonstrably accepts the shape, probed by running the core's own config
// check (xray.CheckConfig) against a minimal tun-inbound config. The probe
// runs once per process, on the first time anything actually asks for a
// bridged carrier; tunnels, SSH-style carriers and device carriers never
// trigger it.
//
// TODO(core wave): when the xray plane grows a real capability registry
// (per-core protocol support), move this probe there and have
// vpnOutCarrierFor consult it.

import (
	"fmt"
	"sync"

	"github.com/ImSoheilPx/pxpanel/internal/util/json_util"
	"github.com/ImSoheilPx/pxpanel/internal/xray"

	"github.com/goccy/go-json"
)

var (
	vpnOutTunProbeOnce sync.Once
	vpnOutTunProbeOK   bool
	vpnOutTunProbeWhy  string
)

// vpnOutCoreHasTunInbound answers whether the core binary this panel runs can
// accept a `tun` inbound, and when it cannot, one line saying so. The probe
// renders the minimal carrier-inbound shape — protocol tun, the settings
// ApplyCarrierBridgesWith writes, listen/port placeholders because the config
// shape requires them — and asks the core itself via its -test config run.
//
// Deliberately a VAR: tests on a core-less host can pin the answer.
var vpnOutCoreHasTunInbound = func() (bool, string) {
	settings, err := json.Marshal(map[string]any{
		"name": "xcar-capprobe",
		"mtu":  vpnOutCarrierMTU,
	})
	if err != nil {
		return false, "could not render the probe config: " + err.Error()
	}
	cfg := &xray.Config{
		InboundConfigs: []xray.InboundConfig{{
			Protocol: "tun",
			Tag:      "vpnout-capprobe",
			Settings: json_util.RawMessage(settings),
			Listen:   json_util.RawMessage(`"127.0.0.1"`),
			Port:     0,
		}},
	}
	binary := xray.GetBinaryPath()
	if err := xray.CheckConfig(binary, cfg); err != nil {
		return false, fmt.Sprintf("the Xray core at %s refused a tun inbound (%v), so an Xray "+
			"outbound cannot carry a tunnel here; name a tunnel, or a freedom outbound with an "+
			"Interface Name or sendThrough, instead", binary, err)
	}
	return true, ""
}

// vpnOutTunInboundCapability is the cached form. The check spawns the core,
// so it is paid at most once per process and only when a bridged carrier is
// actually being resolved.
func vpnOutTunInboundCapability() (bool, string) {
	vpnOutTunProbeOnce.Do(func() {
		vpnOutTunProbeOK, vpnOutTunProbeWhy = vpnOutCoreHasTunInbound()
	})
	return vpnOutTunProbeOK, vpnOutTunProbeWhy
}
