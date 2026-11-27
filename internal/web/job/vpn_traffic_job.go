package job

// The VPN protocol traffic + reconcile job, ported from vpn-ui
// web/job/xray_traffic_job.go's VPN half and re-scoped to the target's job
// layout: the Xray-native stats half already runs in xray_traffic_job, so this
// job owns ONLY the vpn-ui deltas the core cannot see —
//
//   - the hard-enforcement reconcile (wgc/awg/gre peer sets, ikev2 disabled
//     connections) BEFORE the sweep polls, so a disabled account is cut within
//     one tick;
//   - the rbridge sweep (quota/disable + User-Limit enforcement + session
//     store + nft accounting for the non-RADIUS protocols);
//   - the per-account nft counter collection folded into client traffic
//     (client_traffic_windows) through InboundService.AddTraffic;
//   - the SSH relay's own byte counters (userspace relay, no tunnel IP);
//   - the level-triggered KillDisabledSessions sweep.
//
// The telemt mtproto relay's CollectTraffic/KillDisabledSessions are
// deliberately NOT called: this panel's mtproto plane is the v3 mtg sidecar
// (internal/mtproto + mtproto_job), and the vpn-ui telemt stack stays unlinked
// from those rows.

import (
	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/logger"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/accounts"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/awg"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/gre"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ikev2"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/l2tp"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/nftables"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ocserv"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/openvpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/pptp"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/radius"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/rbridge"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/ssh"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/sstp"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/wgc"
	"github.com/ImSoheilPx/pxpanel/internal/web/service"
	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

// VpnTrafficJob collects VPN per-account traffic and reconciles the tunnel
// families. Its sweeper and RADIUS handle are filled by NewVpnTrafficJob from
// the wire-up state (controller.VpnRuntime); a nil sweeper skips the sweep, so
// the job is safe to construct before the stack is wired (tests, panel-only).
type VpnTrafficJob struct {
	inboundService service.InboundService

	radius  *radius.RadiusService
	sweeper *rbridge.Sweeper

	wgc     wgc.WgcService
	awg     awg.AwgService
	gre     gre.GreService
	ikev2   ikev2.Ikev2Service
	ssh     ssh.SshService
	l2tp    l2tp.L2tpService
	pptp    pptp.PptpService
	openvpn openvpn.OpenVpnService
	ocserv  ocserv.OcservService
	sstp    sstp.SstpService

	nft nftables.Service
}

// NewVpnTrafficJob creates the job. radius/sweeper come from the server's
// wire-up; a later call to AttachVpnRuntime fills them if absent.
func NewVpnTrafficJob() *VpnTrafficJob {
	return new(VpnTrafficJob)
}

// AttachVpnRuntime points the job at the wire-up state (RADIUS + sweeper). The
// RADIUS protocols' KillDisabledSessions need the shared instance — a zero-value
// service copy without it silently no-ops every session kill (vpn-ui wired this
// in NewXrayTrafficJob and documented exactly this failure).
func (j *VpnTrafficJob) AttachVpnRuntime(radiusSvc *radius.RadiusService, sweeper *rbridge.Sweeper) {
	j.radius = radiusSvc
	j.sweeper = sweeper
}

// Run performs one VPN traffic + reconcile tick.
func (j *VpnTrafficJob) Run() {
	// Hard-enforcement reconcile BEFORE the sweep polls (vpn-ui: the WireGuard
	// family re-adds enabled devices and removes disabled ones; a removed peer
	// cannot complete a handshake, so disable/quota enforcement is HARD. GRE
	// matters MORE: no handshake to refuse, the reconcile IS the enforcement).
	if err := j.wgc.GenerateAllConfigs(); err != nil {
		logger.Debug("wgc: peer reconcile failed:", err)
	}
	if err := j.awg.GenerateAllConfigs(); err != nil {
		logger.Debug("awg: peer reconcile failed:", err)
	}
	if err := j.gre.GenerateAllConfigs(); err != nil {
		logger.Debug("gre: peer reconcile failed:", err)
	}
	// IKEv2 psk/eap-tls authenticate locally at charon, so the sweep only
	// terminates the SA and the client re-dials into the next tick's gap —
	// disabled, but still browsing. This drops the disabled account's swanctl
	// connection so the eviction sticks (eap-mschapv2 is untouched: its RADIUS
	// re-auth already enforces).
	j.ikev2.ReconcileDisabled()

	if j.sweeper != nil {
		j.sweeper.Tick()
	}

	if j.radius == nil {
		return
	}

	// Session maps (IP→email) come from the embedded RADIUS server; the non-
	// RADIUS protocols' sessions were just written into it by the sweep above.
	vpnSessions := map[string]map[string]string{
		"l2tp":        j.radius.GetSessions("l2tp"),
		"pptp":        j.radius.GetSessions("pptp"),
		"openvpn":     j.radius.GetSessions("openvpn"),
		"openconnect": j.radius.GetSessions("openconnect"),
		"sstp":        j.radius.GetSessions("sstp"),
		"ikev2":       j.radius.GetSessions("ikev2"),
		"wg-c":        j.radius.GetSessions("wg-c"),
		"awg":         j.radius.GetSessions("awg"),
		"gre":         j.radius.GetSessions("gre"),
	}
	// Which inbound each tunnel address belongs to, so every collected record
	// names the SOURCE of its bytes (traffic multiplier + per-inbound breakdown).
	vpnInbounds := make(map[string]map[string]int, len(vpnSessions))
	for protocol, ipToEmail := range vpnSessions {
		if len(ipToEmail) == 0 {
			continue
		}
		byIP := j.radius.GetSessionInbounds(protocol)
		if byIP == nil {
			byIP = map[string]int{}
		}
		// Fallback for an address the session store cannot place (a panel
		// restarted mid-session, before the first interim re-adds it): the
		// inbound whose settings hold the account — when exactly one does.
		var idByEmail map[string]int
		for ip, email := range ipToEmail {
			if byIP[ip] != 0 {
				continue
			}
			if idByEmail == nil {
				idByEmail = j.singleInboundIdByEmail(protocol)
			}
			if id := idByEmail[accounts.AccountKeyOf(email)]; id != 0 {
				byIP[ip] = id
			}
		}
		vpnInbounds[protocol] = byIP
	}
	clientTraffics := j.nft.CollectAndResetTraffic(vpnSessions, vpnInbounds)

	// The SSH relay keeps its own per-account byte counters (the gateway's
	// io.Copy tallies); records arrive already stamped with their inbound.
	clientTraffics = append(clientTraffics, j.ssh.CollectTraffic()...)

	// Level-triggered enforcement: disconnect any STILL-connected client that is
	// no longer allowed (quota/expiry hit, or disabled in settings). The
	// edge-triggered paths only fire on the exact tick a quota is first crossed;
	// this sweep re-derives the disabled set from the DB each run.
	j.l2tp.KillDisabledSessions()
	j.pptp.KillDisabledSessions()
	j.openvpn.KillDisabledSessions()
	j.ocserv.KillDisabledSessions()
	j.sstp.KillDisabledSessions()
	j.ikev2.KillDisabledSessions()
	j.ssh.KillDisabledSessions()

	if len(clientTraffics) == 0 {
		return
	}

	// Fold into the usual client accounting (client_traffics + the windows).
	// Same entry the Xray-native half uses; per-email deltas SUM there.
	if _, _, err := j.inboundService.AddTraffic(nil, clientTraffics); err != nil {
		logger.Warning("vpn traffic: add inbound traffic failed:", err)
	}
}

// singleInboundIdByEmail maps account key → the one inbound of the protocol
// serving it, 0 when none or when two do (vpn-ui
// InboundService.SingleInboundIdByEmail, over the accounts adapter).
func (j *VpnTrafficJob) singleInboundIdByEmail(protocol string) map[string]int {
	out := map[string]int{}
	var accountService accounts.AccountService
	db := vpn.DB()
	if db == nil {
		return out
	}
	var inbounds []*model.Inbound
	if err := db.Model(&model.Inbound{}).Where("protocol = ? AND enable = ?", protocol, true).Find(&inbounds).Error; err != nil {
		return out
	}
	for _, inbound := range inbounds {
		emails, err := accountService.InboundAccountEmails(db, inbound.Id)
		if err != nil {
			continue
		}
		for _, email := range emails {
			key := accounts.AccountKeyOf(email)
			if _, seen := out[key]; seen {
				out[key] = 0 // two inbounds of the protocol serve this account
				continue
			}
			out[key] = inbound.Id
		}
	}
	return out
}

// keep the xray import honest when no record is collected this tick.
var _ = xray.ClientTraffic{}
