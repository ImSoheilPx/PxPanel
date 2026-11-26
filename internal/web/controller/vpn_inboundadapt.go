package controller

// Inbound-save adaptations for the VPN protocol surface: the pieces vpn-ui's
// InboundController ran around its inbound service calls (core-readiness gate,
// settings defaults+validation, VPN address-range assignment, creator grant,
// accounts mirror, per-protocol reconcile), re-pointed at the target's inbound
// service and the ported vpn packages.
//
// Everything here is a NO-OP for Xray-native protocols, so the existing v3 flows
// are untouched.

import (
	"github.com/ImSoheilPx/pxpanel/internal/database"
	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/accounts"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/adminaccess"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/coresettings"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
	vpnrange "github.com/ImSoheilPx/pxpanel/internal/vpn/range"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/xrayplane"
	"github.com/ImSoheilPx/pxpanel/internal/web/session"

	"github.com/gin-gonic/gin"
)

// isVpnSurfaceProtocol reports whether an inbound belongs to the vpn-ui protocol
// family (the nine tunnel protocols or the SSH relay). MTProto is deliberately
// excluded: this panel's mtproto plane is the v3 sidecar (internal/mtproto), and
// the vpn-ui telemt stack stays unlinked from those rows.
func isVpnSurfaceProtocol(p model.Protocol) bool {
	return xrayplane.IsVpnProtocol(p) || p == protoSSH
}

// vpnAdaptNewInbound runs the vpn-ui add-path adaptations on a bound inbound and,
// when it answers false, has already written the refusal — the caller must stop.
// Order matters and mirrors vpn-ui addInbound: core gate → settings defaults →
// address ranges.
func vpnAdaptNewInbound(c *gin.Context, inbound *model.Inbound) bool {
	if !isVpnSurfaceProtocol(inbound.Protocol) {
		return true
	}
	if vpnCoreMissingForProtocol(c, inbound.Protocol) {
		return false
	}
	// Fill the protocol's settings defaults and validate, in that order: a
	// caller who omitted a field is judged on the default that will actually be
	// stored, not on its absence. This is also where the mtproto settings lifter
	// would run (defaults.NormalizeInboundSettings), were telemt rows in scope.
	if err := defaults.NormalizeInboundSettings(inbound); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return false
	}
	// Assign/validate VPN client IP ranges (no-op for the SSH relay). A
	// user-supplied range overlapping another inbound is rejected here.
	if err := vpnrange.NormalizeVpnRanges(inbound, 0); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return false
	}
	return true
}

// vpnAdaptUpdatedInbound is the update-path twin: same order, with this inbound
// excluded from its own overlap check, and the core gate only when the RESULT is
// enabled — turning a stranded inbound off has to stay possible.
func vpnAdaptUpdatedInbound(c *gin.Context, inbound *model.Inbound) bool {
	if !isVpnSurfaceProtocol(inbound.Protocol) {
		return true
	}
	if inbound.Enable && vpnCoreMissingForProtocol(c, inbound.Protocol) {
		return false
	}
	if err := defaults.NormalizeInboundSettings(inbound); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return false
	}
	if err := vpnrange.NormalizeVpnRanges(inbound, inbound.Id); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return false
	}
	return true
}

// vpnCoreMissingForProtocol refuses a VPN inbound whose core this host is not set
// up for, writing the response and reporting true when it did (vpn-ui
// coreMissingForProtocol: the predicate is the CATALOG, not a hardcoded list).
func vpnCoreMissingForProtocol(c *gin.Context, protocol model.Protocol) bool {
	if !isVpnSurfaceProtocol(protocol) {
		return false
	}
	var coreService coresettings.CoreService
	if !coreService.ProtocolNeedsSetup(string(protocol)) {
		return false
	}
	// Nothing set up at all, versus set up but not for this core: the operator has
	// to run Initialize Setup in the first case and install the core in the
	// second, so the two cannot share a message.
	if !coreService.IsProvisioned() {
		pureJsonMsg(c, 200, false, I18nWeb(c, "pages.inbounds.toasts.setupRequired"))
		return true
	}
	pureJsonMsg(c, 200, false, I18nWeb(c, "pages.inbounds.toasts.setupRequiredForProtocol"))
	return true
}

// vpnAfterInboundCreate runs the post-create adaptations: grant the creator
// access (access is assigned, so a creator has no grant for what they just made
// and it would vanish the moment it was created), reconcile the accounts mirror,
// and fire the protocol's reconcile hook.
func vpnAfterInboundCreate(c *gin.Context, inbound *model.Inbound) {
	if inbound == nil {
		return
	}
	user := session.GetLoginUser(c)
	if user != nil && !callerFlags(c).IsSuperAdmin {
		if gerr := adminaccess.GrantInbound(user.Id, inbound.Id); gerr != nil {
			loggerVpnWarning("granting the creator access to their new inbound: ", gerr)
		}
	}
	vpnSyncInboundAccounts(inbound.Id)
	if isVpnSurfaceProtocol(inbound.Protocol) {
		vpnHooksService.reconcileForInbounds([]int{inbound.Id}, true)
	}
}

// vpnAfterInboundDelete settles the accounts mirror and the reseller ledger for
// an inbound that just went away, then fires the protocol hook (vpn-ui
// delInbound's tail).
func vpnAfterInboundDelete(c *gin.Context, id int, protocol model.Protocol) {
	vpnSyncInboundAccounts(id)
	if owned, oerr := resellerOwnedOnInboundVpn(id); oerr != nil {
		loggerVpnWarning("listing reseller accounts before an inbound delete: ", oerr)
	} else if len(owned) > 0 {
		if usage, uerr := resellerUsageVpn(owned); uerr == nil {
			if rerr := resellerDropInboundVpn(id, owned, usage); rerr != nil {
				loggerVpnWarning("settling reseller ownership after an inbound delete: ", rerr)
			}
		}
	}
	if isVpnSurfaceProtocol(protocol) {
		vpnHooksService.reconcileForInbounds([]int{id}, true)
	}
}

// vpnAfterInboundUpdate mirrors the accounts layer and fires the protocol hook.
func vpnAfterInboundUpdate(inbound *model.Inbound) {
	if inbound == nil {
		return
	}
	vpnSyncInboundAccounts(inbound.Id)
	if isVpnSurfaceProtocol(inbound.Protocol) {
		vpnHooksService.reconcileForInbounds([]int{inbound.Id}, true)
	}
}

// vpnSyncInboundAccounts reconciles one inbound's settings.clients[] against the
// accounts layer. Called after every vpn-surface write; the mirror is how the
// Clients page and the RADIUS/rbridge plane stay in step with the data plane.
func vpnSyncInboundAccounts(inboundId int) {
	var accountService accounts.AccountService
	if err := accountService.SyncInboundAccounts(database.GetDB(), inboundId); err != nil {
		loggerVpnWarning("syncing the accounts mirror for inbound ", inboundId, ": ", err)
	}
}
