package controller

// Shared seams for the VPN controllers: the protocol identity constants (the vpn-ui
// database/model constants, restated here from the defaults package so the
// controllers read like the source), the restart seam into the web XrayService, and
// the inbound lookup helper shared by every per-protocol controller.

import (
	"net"
	"strconv"
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
	"github.com/ImSoheilPx/pxpanel/internal/web/service"

	"github.com/gin-gonic/gin"
)

// Protocol identity constants. vpn-ui declared these on database/model; the target's
// defaults package owns the canonical copy (defaults.Proto*), aliased here so the
// controllers keep the source's switch shapes. (model.Protocol is a plain string
// type; no DB tag is involved.)
var (
	protoL2TP         = defaults.ProtoL2TP
	protoPPTP         = defaults.ProtoPPTP
	protoOpenVPN      = defaults.ProtoOpenVPN
	protoOpenConnect  = defaults.ProtoOpenConnect
	protoSSTP         = defaults.ProtoSSTP
	protoIKEV2        = defaults.ProtoIKEv2
	protoWGC          = defaults.ProtoWGC
	protoAWG          = defaults.ProtoAWG
	protoGRE          = defaults.ProtoGRE
	protoMTPROTO      = defaults.ProtoMTProto
	protoSSH          = defaults.ProtoSSH
	protoWireguardXra = model.Protocol("wireguard") // the Xray-native variant
)

// xrayProtocol is the switch type of reconcileForInbounds; a plain alias so the
// map keys stay readable.
type xrayProtocol = model.Protocol

// The seams the web server fills at start-up (vpn_wire.go, called from web.go
// Server.start). Nil until then; every consumer degrades to its fallback.

var (
	// vpnXrayService is the panel's XrayService. The restart seam of last resort:
	// until the server wires vpnRequestRestartHook, SetToNeedRestart on this value
	// is exactly what the source's controllers called.
	vpnXrayService *service.XrayService
	// vpnRequestRestartHook is the preferred restart seam (set by web.go so the
	// VPN surface and the core restart scheduler share one path).
	vpnRequestRestartHook func()
	// vpnOnlineClientsSource is the running core's online-identity reader, wired
	// into xrayplane.SetOnlineClientsSource at start-up.
	vpnOnlineClientsSource func() []string
)

// vpnInboundById loads one inbound row (settings, no client stats preload — the
// same row shape vpn-ui's InboundService.GetInbound returned).
func vpnInboundById(id int) (*model.Inbound, error) {
	var inboundService service.InboundService
	return inboundService.GetInbound(id)
}

// serviceInboundSvc is the narrow face of the target inbound service the vpn
// controllers reach (Update from the cert generators, GetAllInbounds from the
// pool report). One named type so files need no direct service import.
type serviceInboundSvc = service.InboundService

// atoiDefault parses an id path param that may legitimately be absent (the
// id-less cert-generator forms), answering 0 for "" or garbage.
func atoiDefault(raw string) int {
	id, _ := strconv.Atoi(raw)
	return id
}

// browserHost is the panel-access host as the caller sees it (vpn-ui
// controller/util.go browserHost): trusted X-Forwarded-Host, else the request
// host without its port. This is what client configs embed as the endpoint.
func browserHost(c *gin.Context) string {
	host := c.GetHeader("X-Forwarded-Host")
	if host == "" {
		h, _, err := net.SplitHostPort(c.Request.Host)
		if err != nil {
			h = c.Request.Host
		}
		host = h
	}
	// A comma-separated X-Forwarded-Host (proxy chain) lists the original host first.
	if i := strings.IndexByte(host, ','); i >= 0 {
		host = strings.TrimSpace(host[:i])
	}
	return host
}
