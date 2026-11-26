package controller

// Operator egress tunnels (vpnout + sshoutbound), ported from vpn-ui
// web/controller/xray_setting.go onto internal/vpn/vpnout + internal/vpn/ssh.
//
// The source registered both under /panel/api/xray/…; the target's Xray settings
// controller (xray_setting.go) owns that group's stock surface, so this wave
// mounts the two action routes alongside it with the same relative paths —
// POST /panel/api/xray/vpnoutbound/:action and POST
// /panel/api/xray/sshoutbound/:action — without touching xray_setting.go.

import (
	"encoding/json"
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/vpn/ssh"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/vpnout"

	"github.com/gin-gonic/gin"
)

// VpnOutboundController drives operator-configured VPN client tunnels and SSH
// tunnels used as egress.
type VpnOutboundController struct {
	BaseController

	vpn vpnout.VpnOutboundService
	ssh ssh.SshOutboundService
}

// NewVpnOutboundController creates the controller and registers its routes on the
// xray API group.
func NewVpnOutboundController(xrayGroup *gin.RouterGroup) *VpnOutboundController {
	a := &VpnOutboundController{}
	a.initRouter(xrayGroup)
	return a
}

func (a *VpnOutboundController) initRouter(g *gin.RouterGroup) {
	g.POST("/vpnoutbound/:action", a.vpnoutbound)
	g.POST("/sshoutbound/:action", a.sshoutbound)
}

// vpnOutboundForm carries one client tunnel over the panel's form-urlencoded
// POSTs (vpn-ui vpnOutboundForm). The nested settings blob travels as text and is
// unmarshalled by hand: gin's form binder walks a json.RawMessage slice element by
// element through ParseUint, so a JSON object in that field fails the whole bind.
type vpnOutboundForm struct {
	Tag    string `form:"tag"`
	Kind   string `form:"kind"`
	Remark string `form:"remark"`
	Enable bool   `form:"enable"`
	// Via is the tag of another tunnel that carries this one's outer transport.
	// Blank is the ordinary case and blank is also what an older panel posts.
	Via      string `form:"via"`
	Settings string `form:"settings"`
}

// vpnOutKindInfo is one entry of the outbound protocol picker.
type vpnOutKindInfo struct {
	Kind      string `json:"kind"`
	Available bool   `json:"available"`
	// Why is set only when Available is false, so the UI has a single thing to
	// test. One line for an operator, naming what is missing.
	Why string `json:"why"`
}

// vpnOutKindList builds the picker: every protocol whose driver compiled in, each
// marked with whether this HOST can actually run it.
//
// Availability travels WITH the kind rather than filtering it out. A protocol that
// is simply absent from the list looks like a panel that does not support it, and
// the operator has nothing to act on; a greyed-out entry carrying "the client
// binary was not included in this build" is a different message entirely.
func vpnOutKindList() []vpnOutKindInfo {
	// Order is VpnOutKinds's, which is sorted, so the picker does not reshuffle
	// between loads.
	kinds := vpnout.VpnOutKinds()
	out := make([]vpnOutKindInfo, 0, len(kinds))
	for _, k := range kinds {
		// Asked through the service rather than by type-asserting the driver here:
		// Available is optional, and this is the one place that already answers for
		// the drivers that do not implement it.
		ok, why := vpnout.VpnOutKindAvailable(k)
		if ok {
			why = ""
		}
		out = append(out, vpnOutKindInfo{Kind: k, Available: ok, Why: why})
	}
	return out
}

// vpnoutbound drives operator-configured VPN client tunnels used as egress
// (list/save/delete/status/kinds). Each tunnel is backed by a synthesized tagged
// `freedom` outbound pinned to the netdev the driver brought up, so it is
// reverse/routing-selectable purely by that tag — the same shape as the SSH
// tunnels. Form-urlencoded, per the panel convention (no JSON binding).
func (a *VpnOutboundController) vpnoutbound(c *gin.Context) {
	switch c.Param("action") {
	case "list":
		jsonObj(c, a.vpn.List(), nil)
	case "kinds":
		jsonObj(c, vpnOutKindList(), nil)
	case "save":
		var f vpnOutboundForm
		if err := c.ShouldBind(&f); err != nil {
			jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
			return
		}
		cfg := vpnout.VpnOutboundConfig{
			Tag:    f.Tag,
			Kind:   f.Kind,
			Remark: f.Remark,
			Enable: f.Enable,
			Via:    f.Via,
		}
		// Rejected here rather than left to the driver, because a malformed blob
		// does not stop at the driver: it survives Validate if the driver only
		// looks at the fields it knows, then breaks the marshal of the WHOLE
		// tunnel list in persist, which reports itself as a failed save of an
		// unrelated field.
		if raw := strings.TrimSpace(f.Settings); raw != "" {
			if !json.Valid([]byte(raw)) {
				jsonMsg(c, I18nWeb(c, "somethingWentWrong"), errStr("settings is not valid JSON"))
				return
			}
			cfg.Settings = json.RawMessage(raw)
		}
		// Settings go through as posted. Save restores the keys the panel could not
		// send (it is served a masked list) under the same lock it writes with.
		saved, err := a.vpn.Save(cfg)
		if err != nil {
			jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
			return
		}
		// The interface goes back to the caller for the same reason the SSH
		// tunnel's socks port does: the driver picked it while bringing the tunnel
		// up, it is what the synthesized outbound binds to, and only the server
		// knows it.
		jsonObj(c, gin.H{"iface": saved.Iface}, nil)
	case "delete":
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), a.vpn.Delete(c.PostForm("tag")))
	case "status":
		up, detail := a.vpn.Status(c.PostForm("tag"))
		jsonObj(c, gin.H{"running": up, "detail": detail}, nil)
	default:
		jsonObj(c, a.vpn.List(), nil)
	}
}

// sshoutbound drives the operator `ssh -D` tunnels the same way (vpn-ui
// sshoutbound handler).
func (a *VpnOutboundController) sshoutbound(c *gin.Context) {
	switch c.Param("action") {
	case "list":
		jsonObj(c, a.ssh.List(), nil)
	case "save":
		var cfg ssh.SshOutboundConfig
		if err := c.ShouldBind(&cfg); err != nil {
			jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
			return
		}
		saved, err := a.ssh.Save(cfg)
		if err != nil {
			jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
			return
		}
		// The allocated loopback port goes back to the caller: it is what the
		// synthesized socks outbound has to point at, and only the server knows it.
		jsonObj(c, gin.H{"socksPort": saved.SocksPort}, nil)
	case "delete":
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), a.ssh.Delete(c.PostForm("tag")))
	case "status":
		up, logText := a.ssh.Status(c.PostForm("tag"))
		jsonObj(c, gin.H{"running": up, "log": logText}, nil)
	default:
		jsonObj(c, a.ssh.List(), nil)
	}
}
