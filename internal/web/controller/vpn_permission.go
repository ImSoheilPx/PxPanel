package controller

// Permission gating for the VPN surface, ported from vpn-ui
// web/controller/permission.go and re-pointed at the ported machinery:
//
//	vpn-ui service.AdminService  -> internal/vpn/adminaccess
//	vpn-ui service.ResellerService -> internal/vpn/reseller (ledger half)
//	vpn-ui model.User.IsSuperAdmin / IsReseller / Can
//	                             -> model.AdminFlags via adminaccess.FlagsFor
//	                               (pxpanel's User row predates the role columns;
//	                                see adminaccess/roles.go FlagsFor)
//
// This is the ONLY enforcement for the routes registered in this wave: hiding a
// nav entry in the UI is cosmetic, since the routes stay reachable by direct
// request. Everything under /panel/api additionally passes checkAPIAuth
// (api.go), which proves only that a session/API token exists — these middlewares
// prove the caller may DO the thing.

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/accounts"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/adminaccess"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/reseller"
	"github.com/ImSoheilPx/pxpanel/internal/web/session"

	"github.com/gin-gonic/gin"
)

// Self-inflicted lockouts the Admins UI refuses. The service enforces that a panel
// always retains a super admin; these catch the narrower case of the caller doing
// it to themselves, where the service cannot tell who is asking.
var (
	errSelfDemote = errStr("you cannot remove your own super admin role or disable your own account")
	errSelfDelete = errStr("you cannot delete your own account")
	// errNotOwned is reported as a not-found so it cannot confirm that an object with
	// that id exists under another admin.
	errNotOwned = errStr("not found")
)

// errStr is a tiny errors.New alias so the var block above stays readable.
type errStr = stringError

type stringError string

func (e stringError) Error() string { return string(e) }

// viewerFor maps the session user into the accounts.Viewer the ported list/picker
// scoping decides on (role derivation lives in adminaccess, registered into the
// accounts adapter from that package's init).
func viewerFor(c *gin.Context) accounts.Viewer {
	return accounts.ViewerForUser(session.GetLoginUser(c))
}

// callerFlags resolves the session user's role snapshot. A nil session user (no
// login) resolves to flags that pass nothing, which is what every caller below
// wants.
func callerFlags(c *gin.Context) model.AdminFlags {
	user := session.GetLoginUser(c)
	if user == nil {
		return model.AdminFlags{Enable: false}
	}
	flags, err := adminaccess.FlagsFor(user.Id)
	if err != nil {
		// Fail closed: an unreadable role is nobody.
		return model.AdminFlags{Enable: false}
	}
	return flags
}

// deny aborts the request, matching the shape each caller expects: a JSON error
// for XHR, a redirect for a page navigation (ported verbatim from vpn-ui — under
// the SPA the JSON branch is the one every API caller takes; the HTML branch
// stays for direct browser hits).
//
// The XHR case answers HTTP 200 with success:false, which is this panel's
// convention everywhere (see jsonMsg). It matters: axios REJECTS any non-2xx, so a
// real 403 never reaches the success/msg handling and the user is shown axios's own
// "Request failed with status code 403" instead of what actually went wrong. The
// status argument is kept for the 401 case, which the frontend does treat specially.
//
// An EMPTY redirectTo means the caller can open no page at all. That case must not
// redirect: every target would deny them in turn and the browser would spin
// through the redirect chain until it gave up.
func vpnDeny(c *gin.Context, status int, msgKey string, redirectTo string) {
	if !wantsHTML(c) {
		if status == http.StatusUnauthorized {
			// Session expired: the frontend keys off the 401 to send them to login.
			pureJsonMsg(c, status, false, I18nWeb(c, msgKey))
			c.Abort()
			return
		}
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, msgKey))
		c.Abort()
		return
	}
	if redirectTo == "" {
		c.String(http.StatusForbidden, I18nWeb(c, msgKey))
		c.Abort()
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, redirectTo)
	c.Abort()
}

// wantsHTML reports whether this is a browser navigating to a page, as opposed to
// a call expecting data. Only the former should ever be redirected.
func wantsHTML(c *gin.Context) bool {
	if isAjax(c) {
		return false
	}
	if c.Request.Method != http.MethodGet {
		return false
	}
	return strings.Contains(c.GetHeader("Accept"), "text/html")
}

// requirePermVpn gates a route on a single permission bit. Super admins always
// pass. (Named ...Vpn because the SPA base has no generic Perm middleware yet;
// this wave's routes are its only consumers.)
func requirePermVpn(perm model.Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		if session.GetLoginUser(c) == nil {
			// Logged out, deleted mid-session, or disabled.
			vpnDeny(c, http.StatusUnauthorized, "pages.login.loginAgain", c.GetString("base_path"))
			return
		}
		if !callerFlags(c).Can(perm) {
			vpnDeny(c, http.StatusForbidden, "pages.admins.forbidden", "")
			return
		}
		c.Next()
	}
}

// requireSuperAdminVpn gates the escalation-class routes that no permission bit can
// safely stand in for: core uninstall, the host reboot, core config writes and
// admin management itself.
func requireSuperAdminVpn() gin.HandlerFunc {
	return func(c *gin.Context) {
		if session.GetLoginUser(c) == nil {
			vpnDeny(c, http.StatusUnauthorized, "pages.login.loginAgain", c.GetString("base_path"))
			return
		}
		if !callerFlags(c).IsSuperAdmin {
			vpnDeny(c, http.StatusForbidden, "pages.admins.forbidden", "")
			return
		}
		c.Next()
	}
}

// denyNotFoundVpn refuses a cross-owner reference. It reports "not found" rather
// than "forbidden" on purpose: a distinguishable 403 would confirm that an inbound
// with that id exists and belongs to someone else, turning the middleware into an
// enumeration oracle over the small integer id space.
func denyNotFoundVpn(c *gin.Context) {
	if !wantsHTML(c) {
		// 200 + success:false, like every other error this panel returns: axios
		// rejects a non-2xx before the msg is ever read.
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.inbounds.notFound"))
		c.Abort()
		return
	}
	c.String(http.StatusForbidden, I18nWeb(c, "pages.inbounds.notFound"))
	c.Abort()
}

// requireInboundAccessVpn asserts the caller has been GRANTED the inbound named by
// the :id path param. Routes registered in both an :id-ful and an :id-less form
// (the cert generators, which also serve not-yet-saved inbounds) pass through when
// :id is absent; there is no object to authorize against yet.
func requireInboundAccessVpn() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := session.GetLoginUser(c)
		if user == nil {
			vpnDeny(c, http.StatusUnauthorized, "pages.login.loginAgain", c.GetString("base_path"))
			return
		}
		if callerFlags(c).IsSuperAdmin {
			c.Next()
			return
		}
		raw := c.Param("id")
		if raw == "" {
			c.Next()
			return
		}
		id, err := strconv.Atoi(raw)
		if err != nil {
			denyNotFoundVpn(c)
			return
		}
		ok, err := adminaccess.CanAccessInbound(id, user.Id)
		if err != nil || !ok {
			denyNotFoundVpn(c)
			return
		}
		c.Next()
	}
}

// requireClientAccessVpn asserts the caller may act on the client named by the
// :email path param. Client emails are a single panel-wide namespace, so without
// this an :email route reaches straight across admins.
//
// Two different questions, depending on who is asking. For an admin it is the
// inbound grant: every client on an inbound they hold is theirs to touch. For a
// reseller it is account ownership, and that check REPLACES the grant check rather
// than joining it (vpn-ui permission.go requireClientAccess).
func requireClientAccessVpn() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := session.GetLoginUser(c)
		if user == nil {
			vpnDeny(c, http.StatusUnauthorized, "pages.login.loginAgain", c.GetString("base_path"))
			return
		}
		if callerFlags(c).IsSuperAdmin {
			c.Next()
			return
		}
		email := c.Param("email")
		if email == "" {
			denyNotFoundVpn(c)
			return
		}
		if callerFlags(c).IsReseller {
			owns, err := reseller.OwnsClientEmail(email, user.Id)
			if err != nil || !owns {
				denyNotFoundVpn(c)
				return
			}
			c.Next()
			return
		}
		ok, err := adminaccess.CanAccessClientEmail(email, user.Id)
		if err != nil || !ok {
			denyNotFoundVpn(c)
			return
		}
		c.Next()
	}
}

// Refusal text for the routes a reseller can reach with the bits the role derives
// but must not use (vpn-ui permission.go).
const (
	// Both traffic-writing routes hand an account bytes past the quota the
	// reseller's balance was debited for, and the giveaway comes off the house
	// rather than off them.
	msgResellerNoTrafficWrite = "Resellers cannot change an account's traffic counters. Change the account's traffic limit instead."
	// Both inbound-wide routes are defined over every client on an inbound, which
	// a reseller shares with admins and with other resellers, so they reach
	// accounts that are not theirs.
	msgResellerNoInboundWide = "Resellers cannot run this across a whole inbound: it would reach accounts you do not own."
)

// denyForResellerVpn refuses an operation outright when the caller is a reseller,
// and reports whether it answered the request so call sites read as a guard.
func denyForResellerVpn(c *gin.Context, msg string) bool {
	user := session.GetLoginUser(c)
	if user == nil || !callerFlags(c).IsReseller {
		return false
	}
	pureJsonMsg(c, http.StatusOK, false, msg)
	return true
}

// callerOwnsInboundVpn answers whether the session user may act on one inbound.
// (vpn-ui InboundController.callerOwnsInbound.)
func callerOwnsInboundVpn(c *gin.Context, inboundId int) bool {
	user := session.GetLoginUser(c)
	if user == nil {
		return false
	}
	if callerFlags(c).IsSuperAdmin {
		return true
	}
	owns, err := adminaccess.CanAccessInbound(inboundId, user.Id)
	return err == nil && owns
}

// callerOwnsInboundsVpn is the plural of callerOwnsInboundVpn.
func callerOwnsInboundsVpn(c *gin.Context, inboundIds []int) bool {
	user := session.GetLoginUser(c)
	if user == nil {
		return false
	}
	if callerFlags(c).IsSuperAdmin {
		return true
	}
	owns, err := adminaccess.CanAccessAllInbounds(inboundIds, user.Id)
	return err == nil && owns
}

// callerMayTouchClientVpn is requireClientAccessVpn's question for the routes whose
// target is a query param, and so cannot be answered by middleware.
func callerMayTouchClientVpn(c *gin.Context, email string) bool {
	user := session.GetLoginUser(c)
	if user == nil {
		return false
	}
	if !callerFlags(c).IsReseller {
		return true
	}
	if email == "" {
		return false
	}
	owns, err := reseller.OwnsClientEmail(email, user.Id)
	return err == nil && owns
}

// errNoInboundNotYours refuses to leave an account on no inbound at all, for a
// caller who would then never see it again.
var errNoInboundNotYours = errStr(
	"only a super admin can leave an account on no inbound: an account with no membership " +
		"sits outside every inbound grant, so it would disappear from your own Clients list " +
		"with no way to reach it again")

// callerMayLeaveAccountUnservedVpn answers whether this caller may leave an account
// with no inbound at all. Super admins only, and the reason is the Clients list
// rather than the write (vpn-ui inbound.go callerMayLeaveAccountUnserved).
func callerMayLeaveAccountUnservedVpn(c *gin.Context) bool {
	user := session.GetLoginUser(c)
	return user != nil && callerFlags(c).IsSuperAdmin
}
