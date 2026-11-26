package controller

// Per-protocol service endpoints, ported from vpn-ui web/controller/inbound.go
// (downloadOvpn, the cert generators, the per-account config getters) and
// addressing.go, mounted on the inbounds API group at the source paths.
//
// vpn-ui registered these on the SAME controller as inbound CRUD; here they are
// their own controller type for the same reason the source put the addressing
// handlers in addressing.go — inbound.go stays readable — while keeping the exact
// route paths so the API contract holds.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/awg"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/gre"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ikev2"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ocserv"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/openvpn"
	vpnrange "github.com/ImSoheilPx/pxpanel/internal/vpn/range"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ssh"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/sstp"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/wgc"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/xrayplane"
	"github.com/ImSoheilPx/pxpanel/internal/web/session"

	"github.com/gin-gonic/gin"
)

// VpnProtocolController serves the per-protocol inbound endpoints.
type VpnProtocolController struct {
	BaseController

	openvpn openvpn.OpenVpnService
	ocserv  ocserv.OcservService
	sstp    sstp.SstpService
	ikev2   ikev2.Ikev2Service
	wgc     wgc.WgcService
	awg     awg.AwgService
	gre     gre.GreService
	ssh     ssh.SshService
}

// NewVpnProtocolController creates the controller and registers its routes on the
// inbounds API group.
func NewVpnProtocolController(inbounds *gin.RouterGroup) *VpnProtocolController {
	a := &VpnProtocolController{}
	a.initRouter(inbounds)
	return a
}

func (a *VpnProtocolController) initRouter(g *gin.RouterGroup) {
	// OpenVPN client profile + certificate material.
	g.GET("/:id/ovpn/:proto", requirePermVpn(model.PermAccessInbounds), requireInboundAccessVpn(), a.downloadOvpn)
	g.POST("/:id/generate-openvpn-certs", requirePermVpn(model.PermEditInbound), requireInboundAccessVpn(), a.generateOpenVpnCerts)
	// id-less variant so certs can be generated for a not-yet-saved inbound
	g.POST("/generate-openvpn-certs", requirePermVpn(model.PermCreateInbound), a.generateOpenVpnCerts)
	g.POST("/:id/generate-ocserv-cert", requirePermVpn(model.PermEditInbound), requireInboundAccessVpn(), a.generateOcservCert)
	g.POST("/generate-ocserv-cert", requirePermVpn(model.PermCreateInbound), a.generateOcservCert)
	g.POST("/:id/generate-sstp-cert", requirePermVpn(model.PermEditInbound), requireInboundAccessVpn(), a.generateSstpCert)
	g.POST("/generate-sstp-cert", requirePermVpn(model.PermCreateInbound), a.generateSstpCert)
	g.POST("/:id/generate-ikev2-cert", requirePermVpn(model.PermEditInbound), requireInboundAccessVpn(), a.generateIkev2Cert)
	g.POST("/generate-ikev2-cert", requirePermVpn(model.PermCreateInbound), a.generateIkev2Cert)
	g.POST("/check-ikev2-cert", requirePermVpn(model.PermCreateInbound), a.checkIkev2Cert)

	// WireGuard (C): render a client's per-device .conf(s) (keys are server-minted).
	g.GET("/:id/wgc-configs", requirePermVpn(model.PermAccessInbounds), requireInboundAccessVpn(), a.getWgcConfigs)
	// AmneziaWG: render a client's per-device .conf(s) with obfuscation.
	g.GET("/:id/awg-configs", requirePermVpn(model.PermAccessInbounds), requireInboundAccessVpn(), a.getAwgConfigs)
	g.GET("/:id/gre-configs", requirePermVpn(model.PermAccessInbounds), requireInboundAccessVpn(), a.getGreConfigs)
	g.GET("/:id/ssh-configs", requirePermVpn(model.PermAccessInbounds), requireInboundAccessVpn(), a.getSshConfigs)
	// IKEv2 "Remote ID" (the cert SAN / IKE identity the server presents).
	// Inbound-wide, not per-account, so this is gated like getInbound (read+owns)
	// rather than the client-touch check the account-config getters need.
	g.GET("/:id/ikev2-remote-id", requirePermVpn(model.PermAccessInbounds), requireInboundAccessVpn(), a.getIkev2RemoteId)

	// Address-plane introspection. `/pools` is gated on createInbound, not the read
	// bit: it names every inbound on the box, which is more than a reseller may
	// see, and a derived reseller mask carries no *Inbound bit beyond access so
	// that gate excludes them structurally.
	g.GET("/:id/addressing", requirePermVpn(model.PermAccessInbounds), requireInboundAccessVpn(), a.getInboundAddressing)
	g.GET("/pools", requirePermVpn(model.PermCreateInbound), a.getVpnPools)
}

// downloadOvpn generates and returns an .ovpn client config file.
func (a *VpnProtocolController) downloadOvpn(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid inbound ID", err)
		return
	}
	proto := c.Param("proto") // "udp" or "tcp"
	if proto != "udp" && proto != "tcp" {
		jsonMsg(c, "Invalid protocol, must be udp or tcp", nil)
		return
	}

	inbound, err := vpnInboundById(id)
	if err != nil {
		jsonMsg(c, "Inbound not found", err)
		return
	}

	content, err := a.openvpn.GenerateClientConfig(inbound, proto, browserHost(c))
	if err != nil {
		jsonMsg(c, "Failed to generate client config", err)
		return
	}

	filename := fmt.Sprintf("client-%s.ovpn", proto)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Data(200, "application/x-openvpn-profile", []byte(content))
}

// persistCertSettings splices generated certificate material into an inbound's
// settings JSON and saves it, the shared tail of every cert generator below.
// Reports whether the material landed on a saved inbound (the id-less form returns
// it to the frontend instead).
func persistCertSettings(c *gin.Context, id int, hook func(inbound *model.Inbound, settings map[string]any), changed func()) bool {
	if id <= 0 {
		return false
	}
	inbound, err := vpnInboundById(id)
	if err != nil {
		jsonMsg(c, "Inbound not found", err)
		return true
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		jsonMsg(c, "Failed to parse settings", err)
		return true
	}
	hook(inbound, settings)

	settingsJSON, _ := json.Marshal(settings)
	inbound.Settings = string(settingsJSON)
	var inboundService serviceInboundAdapter
	if _, _, err := inboundService.Update(inbound); err != nil {
		jsonMsg(c, "Failed to save certificates", err)
		return true
	}
	if changed != nil {
		changed()
	}
	return true
}

// serviceInboundAdapter reaches the target inbound service's Update (the cert
// generators only rewrite settings and then re-run the protocol's reconcile hook).
type serviceInboundAdapter struct{}

func (serviceInboundAdapter) Update(inbound *model.Inbound) (*model.Inbound, bool, error) {
	var inboundService serviceInboundSvc
	return inboundService.UpdateInbound(inbound)
}

// generateOpenVpnCerts generates a self-signed CA, server cert, and tls-crypt
// key for OpenVPN. Certificate generation does not need a saved inbound — the
// material is returned to the caller. When called with a valid inbound id (the
// edit case) the certs are also persisted to that inbound and applied; for a
// new (unsaved) inbound the frontend stores them in the form and the normal
// "Add inbound" save persists + applies them.
func (a *VpnProtocolController) generateOpenVpnCerts(c *gin.Context) {
	caCert, caKey, serverCert, serverKey, tlsCrypt, err := a.openvpn.GenerateSelfSignedCA()
	if err != nil {
		jsonMsg(c, "Failed to generate certificates", err)
		return
	}

	persistCertSettings(c, atoiDefault(c.Param("id")), func(_ *model.Inbound, settings map[string]any) {
		settings["caCert"] = caCert
		settings["caKey"] = caKey
		settings["serverCert"] = serverCert
		settings["serverKey"] = serverKey
		settings["tlsCrypt"] = tlsCrypt
	}, vpnHooksService.onOpenVpnChanged)

	jsonObj(c, map[string]string{
		"caCert":     caCert,
		"caKey":      caKey,
		"serverCert": serverCert,
		"serverKey":  serverKey,
		"tlsCrypt":   tlsCrypt,
	}, nil)
}

// generateOcservCert generates a self-signed server certificate + key for
// OpenConnect (ocserv). Works with or without a saved inbound: with a valid id
// the material is persisted to the inbound (content mode) and applied; otherwise
// it is returned for the frontend to store in the form until the inbound is saved.
func (a *VpnProtocolController) generateOcservCert(c *gin.Context) {
	serverCert, serverKey, err := a.ocserv.GenerateSelfSignedCert("")
	if err != nil {
		jsonMsg(c, "Failed to generate certificate", err)
		return
	}

	persistCertSettings(c, atoiDefault(c.Param("id")), func(_ *model.Inbound, settings map[string]any) {
		// Self-signed material lands in content mode (tlsUseFile=false).
		settings["tlsUseFile"] = false
		settings["certificate"] = serverCert
		settings["key"] = serverKey
	}, vpnHooksService.onOcservChanged)

	jsonObj(c, map[string]string{
		"certificate": serverCert,
		"key":         serverKey,
	}, nil)
}

// generateSstpCert generates a self-signed server certificate + key for SSTP
// (accel-ppp). The Windows SSTP client's stricter trust requirements are surfaced
// by a warning in the UI, not changed here.
func (a *VpnProtocolController) generateSstpCert(c *gin.Context) {
	serverCert, serverKey, err := a.sstp.GenerateSelfSignedCert("")
	if err != nil {
		jsonMsg(c, "Failed to generate certificate", err)
		return
	}

	persistCertSettings(c, atoiDefault(c.Param("id")), func(_ *model.Inbound, settings map[string]any) {
		settings["tlsUseFile"] = false
		settings["certificate"] = serverCert
		settings["key"] = serverKey
	}, vpnHooksService.onSstpChanged)

	jsonObj(c, map[string]string{
		"certificate": serverCert,
		"key":         serverKey,
	}, nil)
}

// generateIkev2Cert generates a self-signed RSA CA + server certificate for IKEv2
// (strongSwan). Unlike SSTP/ocserv it returns a CA too — the client must trust it
// (import the CA) unless a publicly-trusted cert is used.
func (a *VpnProtocolController) generateIkev2Cert(c *gin.Context) {
	serverCert, serverKey, caCert, err := a.ikev2.GenerateSelfSignedCert("")
	if err != nil {
		jsonMsg(c, "Failed to generate certificate", err)
		return
	}

	persistCertSettings(c, atoiDefault(c.Param("id")), func(_ *model.Inbound, settings map[string]any) {
		settings["tlsUseFile"] = false
		settings["certificate"] = serverCert
		settings["key"] = serverKey
		settings["caCert"] = caCert
	}, vpnHooksService.onIkev2Changed)

	jsonObj(c, map[string]string{
		"certificate": serverCert,
		"key":         serverKey,
		"caCert":      caCert,
	}, nil)
}

// getWgcConfigs renders the WireGuard (C) client configuration(s) for one account
// (?email=) of an inbound: one .conf per device (K = the account's User Limit),
// with server-minted keys and the panel-access host as the endpoint. Ensures keys
// exist first.
func (a *VpnProtocolController) getWgcConfigs(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid inbound ID", err)
		return
	}
	// The account is a QUERY param, so no middleware sees it, and what comes back
	// is that account's private keys. `owns` on :id is enough for an admin and not
	// for a reseller, who shares the inbound with the admin whose accounts are on it.
	if !callerMayTouchClientVpn(c, c.Query("email")) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}
	// Mint/persist any missing server + device keypairs so the render has keys to use.
	a.wgc.ReconcileAllKeys()
	inbound, err := vpnInboundById(id)
	if err != nil {
		jsonMsg(c, "Inbound not found", err)
		return
	}
	configs, err := a.wgc.RenderClientConfigs(inbound, c.Query("email"), browserHost(c))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, configs, nil)
}

// getAwgConfigs renders the AmneziaWG client configuration(s) for one account
// (?email=) of an inbound: identical to getWgcConfigs plus the AWG obfuscation
// lines in [Interface].
func (a *VpnProtocolController) getAwgConfigs(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid inbound ID", err)
		return
	}
	if !callerMayTouchClientVpn(c, c.Query("email")) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}
	a.awg.ReconcileAllKeys()
	inbound, err := vpnInboundById(id)
	if err != nil {
		jsonMsg(c, "Inbound not found", err)
		return
	}
	configs, err := a.awg.RenderClientConfigs(inbound, c.Query("email"), browserHost(c))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, configs, nil)
}

// getGreConfigs renders one GRE account's per-peer router configuration(s) —
// WireGuard-style .conf text plus a shell snippet per pinned peer (vpn-ui
// getGreConfigs → GreService.RenderPeerConfigs).
func (a *VpnProtocolController) getGreConfigs(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid inbound ID", err)
		return
	}
	// See getWgcConfigs: the account is a query param, so ownership is checked on
	// it too.
	if !callerMayTouchClientVpn(c, c.Query("email")) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}
	a.gre.ReconcileAllPeers()
	inbound, err := vpnInboundById(id)
	if err != nil {
		jsonMsg(c, "Inbound not found", err)
		return
	}
	configs, err := a.gre.RenderPeerConfigs(inbound, c.Query("email"), browserHost(c))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, configs, nil)
}

// getSshConfigs renders the SSH client artifacts for one account (?email=) of an
// inbound: a sing-box "ssh" outbound JSON plus a plaintext host/port/user/pass
// block, one per endpoint (each external proxy, else the panel-access host).
// Ensures the server host key exists first so the config is complete.
func (a *VpnProtocolController) getSshConfigs(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid inbound ID", err)
		return
	}
	if !callerMayTouchClientVpn(c, c.Query("email")) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}
	if err := a.ssh.ReconcileHostKeys(); err != nil {
		loggerVpnWarning("SSH: host key reconcile failed:", err)
	}
	inbound, err := vpnInboundById(id)
	if err != nil {
		jsonMsg(c, "Inbound not found", err)
		return
	}
	configs, err := a.ssh.RenderClientConfigs(inbound, c.Query("email"), browserHost(c))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, configs, nil)
}

// getIkev2RemoteId resolves an ikev2 inbound's Remote ID / Server Identity
// (Ikev2Service.serverID): the IKE identity the server presents, which is also
// the SAN GenerateSelfSignedCert issued the server cert for.
func (a *VpnProtocolController) getIkev2RemoteId(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid inbound ID", err)
		return
	}
	inbound, err := vpnInboundById(id)
	if err != nil {
		jsonMsg(c, "Inbound not found", err)
		return
	}
	remoteId, err := a.ikev2.ResolveServerID(inbound)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, map[string]string{"remoteId": remoteId}, nil)
}

// checkIkev2Cert inspects the supplied IKEv2 server certificate's public-key type
// and returns a device-compatibility warning (non-RSA → iOS silently rejects it).
// Non-blocking: the UI surfaces the warning; it does not prevent saving.
func (a *VpnProtocolController) checkIkev2Cert(c *gin.Context) {
	data := &model.Inbound{}
	if err := c.ShouldBind(data); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	keyType, warning, err := a.ikev2.InspectServerCert(data)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, map[string]string{"keyType": keyType, "warning": warning}, nil)
}

// getInboundAddressing reports one inbound's pool, its User Limit resolution and
// every account's slot and tunnel address(es).
//
// Route gating is read+owns, so a reseller granted the inbound reaches it. What
// they get back is narrowed to their own accounts by filterInboundForCaller
// BEFORE the report is built, which is the only reason this is safe to expose.
func (a *VpnProtocolController) getInboundAddressing(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	inbound, err := vpnInboundById(id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), err)
		return
	}
	// Fails closed: an ownership question the panel cannot answer is a refusal,
	// never an unfiltered answer.
	if !filterInboundForCallerVpn(c, inbound) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}

	report, ok := inboundAddressingReport(inbound)
	if !ok {
		// Not an error: mtproto, ssh and every Xray-native protocol hand out no
		// client address at all. Saying so plainly beats an empty pool a caller
		// would read as "misconfigured".
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"),
			errStr(fmt.Sprintf("protocol %q hands out no client address, so it has no address pool", inbound.Protocol)))
		return
	}
	jsonObj(c, report, nil)
}

// getVpnPools reports which /24 of the VPN address space each inbound holds.
func (a *VpnProtocolController) getVpnPools(c *gin.Context) {
	jsonObj(c, vpnPoolOccupancy(), nil)
}

// --- addressing read model (vpn-ui web/service/vpnaddressing.go) -------------

// VpnAccountAddressing is one account's place in an inbound's address pool.
type VpnAccountAddressing struct {
	Email string `json:"email"`
	// Slot is the account's index into the pool, which is what its address is
	// derived from.
	Slot      int      `json:"slot"`
	Addresses []string `json:"addresses"`
}

// VpnAddressingReport is everything readable about one inbound's address plane.
type VpnAddressingReport struct {
	InboundId int            `json:"inboundId"`
	Protocol  model.Protocol `json:"protocol"`

	// Ranges is the pool as stored, in the allocator's own "A.B.C.s-A.B.C.e"
	// spelling (NOT CIDR). Subnets is the same thing as the /24 prefixes the
	// allocator works in.
	Ranges  []string `json:"ranges"`
	Subnets []string `json:"subnets"`

	// UserLimit reports the posted value, what it actually resolves to, and why.
	UserLimit VpnUserLimitReport `json:"userLimit"`

	// Capacity is how many accounts the CURRENT pool holds, MaxAccounts an upper
	// bound after the pool has auto-expanded as far as it is allowed to. Both are
	// counts of accounts, not addresses.
	Capacity    int `json:"capacity"`
	MaxAccounts int `json:"maxAccounts"`
	Used        int `json:"used"`

	Accounts []VpnAccountAddressing `json:"accounts"`
}

// VpnUserLimitReport spells out the User Limit resolution, which is the single
// most misread number in the settings JSON.
type VpnUserLimitReport struct {
	// Posted is the stored value, or nil when the key is absent.
	Posted *int `json:"posted"`
	// Effective is the device-block size actually used for this protocol.
	Effective int `json:"effective"`
	// Rule names which of the three resolutions applied:
	// "absent-legacy", "no-limit", "explicit".
	Rule string `json:"rule"`
}

// VpnPoolBlock is one /24 of the VPN address space and who holds it.
type VpnPoolBlock struct {
	Subnet    string         `json:"subnet"` // "A.B.C", the /24 prefix
	Protocol  model.Protocol `json:"protocol"`
	InboundId int            `json:"inboundId"`
	Remark    string         `json:"remark"`
}

// inboundAddressingReport builds the address-plane report for one inbound. ok is
// false for a protocol with no address pool at all: the relays (mtproto, ssh) and
// every Xray-native protocol hand out no client address.
//
// THE ADDRESSES ARE NOT RECOMPUTED HERE. They come from
// xrayplane.BuildVpnEmailToIPMap, the same mapper the Xray config generator uses
// to turn email-based routing rules into source-IP rules, so what this reports is
// by construction what the data plane routes.
func inboundAddressingReport(inbound *model.Inbound) (*VpnAddressingReport, bool) {
	if inbound == nil || !xrayplane.IsVpnProtocol(inbound.Protocol) {
		return nil, false
	}

	ranges := vpnrange.InboundRanges(inbound)
	report := &VpnAddressingReport{
		InboundId: inbound.Id,
		Protocol:  inbound.Protocol,
		Ranges:    ranges,
		Subnets:   vpnrange.SubnetsOf(ranges),
		UserLimit: inboundUserLimitReport(inbound),
		Accounts:  []VpnAccountAddressing{},
	}
	report.Capacity = vpnrange.VpnAccountsCapacity(report.Subnets, report.UserLimit.Effective)
	if max, ok := vpnrange.MaxVpnAccounts(inbound); ok {
		report.MaxAccounts = max
	}

	clients := settingsClientEmails(inbound)
	report.Used = len(clients)

	// The authoritative map, panel-wide and keyed by email. Filtering it to this
	// inbound's own subnets is what makes it per-inbound, and it is exact rather
	// than approximate: the allocator's central invariant is that no two inbounds
	// share a /24.
	all := xrayplane.BuildVpnEmailToIPMap()
	mine := subnetSetOf(report.Subnets)
	// OpenVPN owns a second /24 per range: the TCP side mirrors the UDP block into
	// 10.3.x, and those addresses are as much this inbound's as the UDP ones.
	if inbound.Protocol == protoOpenVPN {
		for _, s := range report.Subnets {
			mine[vpnrange.MirrorOvpnSubnet(s)] = true
		}
	}

	for i, email := range clients {
		report.Accounts = append(report.Accounts, VpnAccountAddressing{
			Email:     email,
			Slot:      vpnrange.SlotOr(nil, i),
			Addresses: addressesInSubnetsOf(all[email], mine),
		})
	}
	return report, true
}

// settingsClientEmails lists the account emails a stored settings blob carries.
func settingsClientEmails(inbound *model.Inbound) []string {
	var parsed struct {
		Clients []struct {
			Email string `json:"email"`
			Slot  *int   `json:"slot"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(inbound.Settings), &parsed); err != nil {
		return nil
	}
	out := make([]string, 0, len(parsed.Clients))
	for _, cl := range parsed.Clients {
		if cl.Email == "" {
			continue
		}
		out = append(out, cl.Email)
	}
	return out
}

// inboundUserLimitReport resolves the User Limit the way the inbound's own
// protocol does, and says which rule it used.
func inboundUserLimitReport(inbound *model.Inbound) VpnUserLimitReport {
	var raw struct {
		UserLimit *int `json:"userLimit"`
	}
	_ = json.Unmarshal([]byte(inbound.Settings), &raw)

	out := VpnUserLimitReport{Posted: raw.UserLimit}
	gateway := inbound.Protocol == protoWGC || inbound.Protocol == protoAWG
	switch {
	case raw.UserLimit == nil:
		out.Rule = "absent-legacy"
	case *raw.UserLimit == 0:
		out.Rule = "no-limit"
	default:
		out.Rule = "explicit"
	}
	if gateway {
		out.Effective = vpnrange.WgcEffectiveK(raw.UserLimit)
	} else {
		out.Effective = vpnrange.EffectiveUserLimit(raw.UserLimit)
	}
	return out
}

// subnetSetOf indexes /24 prefixes for membership tests.
func subnetSetOf(subnets []string) map[string]bool {
	out := make(map[string]bool, len(subnets))
	for _, s := range subnets {
		out[s] = true
	}
	return out
}

// addressesInSubnetsOf keeps the addresses that fall inside the given /24
// prefixes. Entries may be a bare address or a CIDR, so the prefix is taken off
// the address half before the /24 is read. Anything unparseable is dropped rather
// than guessed at.
func addressesInSubnetsOf(addresses []string, subnets map[string]bool) []string {
	out := []string{}
	for _, addr := range addresses {
		host := addr
		if slash := strings.IndexByte(host, '/'); slash >= 0 {
			host = host[:slash]
		}
		dot := strings.LastIndexByte(host, '.')
		if dot < 0 {
			continue
		}
		if subnets[host[:dot]] {
			out = append(out, addr)
		}
	}
	return out
}

// vpnPoolOccupancy lists every /24 of the VPN address space that an inbound
// currently holds, ordered by subnet (vpn-ui VpnPoolOccupancy).
func vpnPoolOccupancy() []VpnPoolBlock {
	var inboundService serviceInboundSvc
	inbounds, err := inboundService.GetAllInbounds()
	if err != nil || len(inbounds) == 0 {
		return []VpnPoolBlock{}
	}

	out := []VpnPoolBlock{}
	for _, inbound := range inbounds {
		if !xrayplane.IsVpnProtocol(inbound.Protocol) {
			continue
		}
		subnets := vpnrange.SubnetsOf(vpnrange.InboundRanges(inbound))
		if inbound.Protocol == protoOpenVPN {
			// The TCP mirror is held by this inbound too, and an operator who
			// cannot see it will eventually try to allocate over it.
			for _, s := range append([]string{}, subnets...) {
				subnets = append(subnets, vpnrange.MirrorOvpnSubnet(s))
			}
		}
		for _, subnet := range subnets {
			if subnet == "" {
				continue
			}
			out = append(out, VpnPoolBlock{
				Subnet:    subnet,
				Protocol:  inbound.Protocol,
				InboundId: inbound.Id,
				Remark:    inbound.Remark,
			})
		}
	}
	sortBlocks(out)
	return out
}

// sortBlocks orders "A.B.C" prefixes numerically, then by inbound id. Sorting
// them as strings puts "10.10.x" before "10.2.x", which reads as corruption in a
// list an operator is scanning for a free block.
func sortBlocks(out []VpnPoolBlock) {
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			a, b := out[j-1], out[j]
			if subnetLess(a.Subnet, b.Subnet) || (a.Subnet == b.Subnet && a.InboundId <= b.InboundId) {
				break
			}
			out[j-1], out[j] = b, a
		}
	}
}

// subnetLess orders "A.B.C" prefixes numerically.
func subnetLess(a, b string) bool {
	var a1, a2, a3, b1, b2, b3 int
	if _, err := fmt.Sscanf(a, "%d.%d.%d", &a1, &a2, &a3); err != nil {
		return a < b
	}
	if _, err := fmt.Sscanf(b, "%d.%d.%d", &b1, &b2, &b3); err != nil {
		return a < b
	}
	if a1 != b1 {
		return a1 < b1
	}
	if a2 != b2 {
		return a2 < b2
	}
	return a3 < b3
}

// filterInboundForCallerVpn narrows a single inbound to the clients the caller may
// see, in place (vpn-ui filterInboundForCaller). Reports false when the answer
// cannot be worked out, which the caller must treat as a refusal rather than as
// "nothing to filter". A no-op for anyone who is not a reseller.
func filterInboundForCallerVpn(c *gin.Context, inbound *model.Inbound) bool {
	user := session.GetLoginUser(c)
	if user == nil {
		return false
	}
	if !callerFlags(c).IsReseller || inbound == nil {
		return true
	}
	owned, err := resellerOwnedEmailsVpn(user.Id)
	if err != nil {
		return false
	}
	filterSettingsClientsForReseller(inbound, owned)
	return true
}
