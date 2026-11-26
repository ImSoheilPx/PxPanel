package controller

// The account plane's HTTP surface, ported from vpn-ui web/controller (clients.go,
// the account routes inside inbound.go, and addressing.go's read model), adapted to
// the ported machinery:
//
//	accountService            -> accounts.AccountService (internal/vpn/accounts)
//	resellerService.BalanceFor -> reseller.BalanceFor (internal/vpn/reseller)
//	inboundService.GetInbound  -> service.InboundService.GetInbound (the target's)
//
// Route placement under the target's API tree: the SPA's client CRUD already owns
// GET /panel/api/clients/list (the v3 client rows), so the vpn-ui account-centric
// read model takes its own /panel/api/accounts group instead of the source's
// /clients/list + /clients/assignable. Everything else keeps the source paths.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/accounts"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/adminaccess"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/reseller"
	"github.com/ImSoheilPx/pxpanel/internal/web/session"

	"github.com/gin-gonic/gin"
)

// shared singletons, the way the source's permission.go kept its package-level
// services: every service here is stateless.
var (
	vpnAccountService  accounts.AccountService
	vpnResellerService = &resellerViewAdapter{}
	vpnHooksService    = &vpnHooks{}
)

// resellerViewAdapter carries the pieces of vpn-ui's ResellerService the inbound
// controller used (BalanceFor/OwnedEmails/UsageOf are package functions here).
type resellerViewAdapter struct{}

// VpnAccountsController registers the account-plane routes.
type VpnAccountsController struct {
	BaseController
}

// NewVpnAccountsController creates the controller and registers its routes on the
// api root (/panel/api/accounts) and the inbounds group.
func NewVpnAccountsController(api *gin.RouterGroup, inbounds *gin.RouterGroup) *VpnAccountsController {
	a := &VpnAccountsController{}
	a.initRouter(api, inbounds)
	return a
}

func (a *VpnAccountsController) initRouter(api *gin.RouterGroup, inbounds *gin.RouterGroup) {
	// The Clients page read model: same claim as the inbounds group (it shows the
	// same accounts from the other side); rows are narrowed per caller inside
	// ListAccounts.
	accountsApi := api.Group("/accounts")
	accountsApi.Use(requirePermVpn(model.PermAccessInbounds))
	accountsApi.GET("/list", a.accountsList)
	accountsApi.GET("/assignable", a.accountsAssignable)

	// The account routes that live beside the client routes (vpn-ui registered
	// these on the inbounds group and this wave keeps that shape).
	inbounds.POST("/saveAccount", requirePermVpn(model.PermCreateClient), a.saveAccount)
	inbounds.POST("/delAccount/:email", requirePermVpn(model.PermDeleteClient), requireClientAccessVpn(), a.delAccount)
	// Switch one account on or off on ONE inbound (see the source route comment).
	inbounds.POST("/:id/setMembershipEnable/:email",
		requirePermVpn(model.PermEditClient), requireInboundAccessVpn(), requireClientAccessVpn(), a.setMembershipEnable)
	// Adding or removing MEMBERSHIPS in bulk.
	inbounds.POST("/bulkMembership", requirePermVpn(model.PermBulkOperation), a.bulkMembership)
	// Prices a bulk operation without applying any part of it.
	inbounds.POST("/bulkPreview", requirePermVpn(model.PermBulkOperation), a.bulkPreview)
	// The reseller's own balance, for the chip the pages refresh after every
	// operation. Gated on the read bit rather than on the role: it answers
	// "not a reseller" for everyone else.
	inbounds.GET("/resellerBalance", requirePermVpn(model.PermAccessInbounds), a.resellerBalance)
	// Per-(inbound, account) liveness for the Clients page's expander.
	inbounds.POST("/onlineMemberships", requirePermVpn(model.PermAccessInbounds), a.onlineMemberships)
}

// accountsList returns one page of accounts the caller may see.
func (a *VpnAccountsController) accountsList(c *gin.Context) {
	page, _ := strconv.Atoi(c.Query("page"))
	size, _ := strconv.Atoi(c.Query("size"))
	viewer := viewerFor(c)
	result, err := vpnAccountService.ListAccounts(&viewer, page, size,
		c.Query("search"), c.Query("sort"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, result, nil)
}

// accountsAssignable lists the inbounds the caller may put an account on, for the
// page's inbound picker. Filtered by the same grant the write path enforces.
func (a *VpnAccountsController) accountsAssignable(c *gin.Context) {
	viewer := viewerFor(c)
	rows, err := vpnAccountService.AssignableInboundsFor(&viewer)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, rows, nil)
}

// saveAccount creates or edits an account that NO inbound serves (vpn-ui
// saveAccountClient). Super-admin only in the handler; see
// callerMayLeaveAccountUnservedVpn for why.
func (a *VpnAccountsController) saveAccount(c *gin.Context) {
	if !callerMayLeaveAccountUnservedVpn(c) {
		// Not only about the empty set: this route's other job is editing an account
		// that is ALREADY on nothing, which is an account only a super admin can see.
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), errNoInboundNotYours)
		return
	}
	data := &model.Inbound{}
	if err := c.ShouldBind(data); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	entry, err := singlePostedClientEntry(data.Settings)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	email, _ := entry["email"].(string)
	if err := accounts.ValidateClientEmail(email); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	if subId, ok := entry["subId"].(string); ok {
		if err := accounts.ValidateClientSubID(subId); err != nil {
			jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
			return
		}
	}

	// Target 0: nothing addressed this write, so the set is exactly what was posted.
	membershipIds, _ := postedMembershipIds(c, 0)
	if !callerOwnsInboundsVpn(c, membershipIds) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}
	if err := validateMembershipSetVpn(membershipIds); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}

	if _, err := vpnAccountService.SaveAccountWithoutInbound(entry); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	// Anchor 0: no settings blob was written, so there is nothing for the mirror to
	// read the account back out of. Explicit, always: this route's whole contract is
	// that the posted set is the account's set.
	previous, perr := vpnAccountService.InboundIdsForEmail(email)
	if perr != nil {
		loggerVpnWarning("reading previous memberships: ", perr)
	}
	projected, merr := vpnAccountService.ApplyMembershipsFrom(email, 0, membershipIds, previous, true)
	if merr != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), merr)
		return
	}

	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundClientAddSuccess"), nil)

	// The inbounds it is on now and the ones it just left, exactly as the edit path
	// does: a membership that went away has to rewrite that daemon's config too.
	// needRestart is true because nothing here hot-added anything into the running
	// core — ApplyMembershipsFrom only writes the database.
	vpnHooksService.reconcileForInbounds(
		unionInboundIds(unionInboundIds(membershipIds, previous), projected), true)
}

// delAccount removes an account that no inbound serves (vpn-ui delAccountClient).
// It refuses an account that still holds a membership, so a served account keeps
// exactly one destructive path.
func (a *VpnAccountsController) delAccount(c *gin.Context) {
	email := c.Param("email")
	current, err := vpnAccountService.InboundIdsForEmail(email)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	if len(current) > 0 {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"),
			errStr("this account is still served by an inbound; delete it there instead"))
		return
	}
	// Refund before the delete: removing the client_traffics row destroys what a
	// refund priced afterwards would read, so the consumption snapshot has to be
	// taken first (vpn-ui usageBeforeDelete).
	used, known, uerr := reseller.UsageOf(email)
	if uerr != nil {
		loggerVpnWarning("reading traffic before a delete, refund will be withheld: ", uerr)
	}
	if err := vpnAccountService.DeleteAccountWithoutInbound(email); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	if err := reseller.RefundDeleted(email, used, known); err != nil {
		loggerVpnWarning("refunding a reseller for a deleted account: ", err)
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundClientDeleteSuccess"), nil)
}

// setMembershipEnable switches one account on or off on ONE inbound.
func (a *VpnAccountsController) setMembershipEnable(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	email := c.Param("email")
	var body struct {
		Enable bool `form:"enable" json:"enable"`
	}
	if err := c.ShouldBind(&body); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}

	touched, err := vpnAccountService.SetMembershipEnable(email, id, body.Enable)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundClientUpdateSuccess"), nil)
	// Only this inbound's entry can have changed, but the reconcile goes through the
	// same fan-out as every other client write so a protocol is never left holding a
	// config the settings JSON no longer agrees with.
	vpnHooksService.reconcileForInbounds(unionInboundIds([]int{id}, touched), true)
}

// bulkMembershipResult is what one bulk membership run reports back.
type bulkMembershipResult struct {
	Applied int      `json:"applied"`
	Skipped int      `json:"skipped"`
	Reasons []string `json:"reasons,omitempty"`
}

// bulkMembership puts the selected accounts ON a set of inbounds, or takes them OFF
// (vpn-ui bulkClientMembership). Everything a new membership needs — minting the
// credential its protocol keys on, allocating a pool slot, projecting the account's
// quota and expiry onto the new inbound, and stripping the entry from the ones it
// left — lives behind accounts.ApplyMemberships.
func (a *VpnAccountsController) bulkMembership(c *gin.Context) {
	var body struct {
		Data string `form:"data" json:"data"`
	}
	if err := c.ShouldBind(&body); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	var req reseller.BulkClientUpdateRequest
	if err := json.Unmarshal([]byte(body.Data), &req); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	var adding bool
	switch req.Op {
	case "addInbounds":
		adding = true
	case "removeInbounds":
	default:
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"),
			errStr(fmt.Sprintf("unknown bulk membership operation: %q", req.Op)))
		return
	}

	// The reseller decision, and it is a refusal. Which inbounds serve an account
	// is the admin's call (vpn-ui ErrBulkNoMembership).
	user := session.GetLoginUser(c)
	if user == nil || callerFlags(c).IsReseller {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"),
			errStr("resellers cannot move an account between inbounds"))
		return
	}

	// unionInboundIds with nothing to union is just "dedupe, keep order". The id
	// filter is the same one postedMembershipIds applies.
	positive := make([]int, 0, len(req.InboundIds))
	for _, id := range req.InboundIds {
		if id > 0 {
			positive = append(positive, id)
		}
	}
	chosen := unionInboundIds(positive, nil)
	if len(chosen) == 0 {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"),
			errStr("no inbound was named to add to or remove from"))
		return
	}
	// Two assertions over two different id sets, and both are load-bearing:
	// `chosen` authorises the write, `targets` authorises reaching these ACCOUNTS
	// at all.
	if !callerOwnsInboundsVpn(c, chosen) || !callerOwnsInboundsVpn(c, distinctInboundIdsOfTargets(req.Targets)) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}

	result := bulkMembershipResult{}
	seen := map[string]bool{}
	skip := func(reason string) {
		result.Skipped++
		if reason != "" && !seen[reason] {
			seen[reason] = true
			result.Reasons = append(result.Reasons, reason)
		}
	}
	var touched []int
	for _, email := range distinctTargetEmailsVpn(req.Targets) {
		current, err := vpnAccountService.InboundIdsForEmail(email)
		if err != nil {
			skip(fmt.Sprintf("%s: %v", email, err))
			continue
		}
		if len(current) == 0 {
			// No membership means no account row to re-home.
			skip(fmt.Sprintf("%s: no such account", email))
			continue
		}
		wanted := current
		if adding {
			wanted = unionInboundIds(current, chosen)
		} else {
			wanted = subtractInboundIds(current, chosen)
		}
		// Exact, not an approximation: adding can only grow the set and removing
		// can only shrink it, so an unchanged length means an unchanged set.
		if len(wanted) == len(current) {
			skip("some accounts were already in the requested state and were left alone")
			continue
		}
		if len(wanted) == 0 && !callerMayLeaveAccountUnservedVpn(c) {
			skip(fmt.Sprintf("%s: %v", email, errNoInboundNotYours))
			continue
		}
		if err := validateMembershipSetVpn(wanted); err != nil {
			skip(fmt.Sprintf("%s: %v", email, err))
			continue
		}
		// Removing is authorised by owning the inbound removed FROM, which is why
		// this is not simply "everything not in wanted": an account can be on an
		// inbound this caller cannot see, and that membership must survive.
		var removable []int
		if !adding {
			removable = intersectInboundIds(current, chosen)
		}
		changed, err := vpnAccountService.ApplyMemberships(email, wanted, removable, true)
		if err != nil {
			skip(fmt.Sprintf("%s: %v", email, err))
			continue
		}
		result.Applied++
		touched = unionInboundIds(touched, changed)
	}
	jsonObj(c, result, nil)

	// needRestart is true because nothing here hot-added anything; ApplyMemberships
	// only writes the database. The VPN protocols each request their own restart
	// from their hook regardless.
	if len(touched) > 0 {
		vpnHooksService.reconcileForInbounds(touched, true)
	}
}

// bulkPreview prices a bulk operation without applying any part of it, so a
// reseller who cannot afford the whole batch can be offered the part they can.
// Writes nothing, reserves nothing.
func (a *VpnAccountsController) bulkPreview(c *gin.Context) {
	var body struct {
		Data string `form:"data" json:"data"`
	}
	if err := c.ShouldBind(&body); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	var req reseller.BulkClientUpdateRequest
	if err := json.Unmarshal([]byte(body.Data), &req); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	ids := make([]int, 0, len(req.Targets))
	for _, t := range req.Targets {
		ids = append(ids, t.InboundId)
	}
	if !callerOwnsInboundsVpn(c, ids) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}
	preview, err := reseller.PreviewBulk(viewerFor(c), &req)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, preview, nil)
}

// resellerBalance reports what the caller has left to sell, so the page can show
// it after every operation rather than only on load.
func (a *VpnAccountsController) resellerBalance(c *gin.Context) {
	jsonObj(c, reseller.BalanceFor(viewerFor(c)), nil)
}

// onlineMemberships reports the same liveness per (inbound, account) pair, for the
// Clients page's expander. "<inboundId>:<email>", inbound 0 meaning the session's
// source inbound could not be named. Scoped on BOTH halves (vpn-ui
// onlineMemberships).
func (a *VpnAccountsController) onlineMemberships(c *gin.Context) {
	online := vpnOnlineEmails()
	if len(online) == 0 {
		jsonObj(c, []string{}, nil)
		return
	}

	byEmail := make(map[string][]string, len(online))
	for _, email := range online {
		ids, err := vpnAccountService.InboundIdsForEmail(email)
		if err != nil || len(ids) == 0 {
			// Live somewhere the panel cannot name (a bare client_traffic row with
			// no account row behind it): report it as inbound 0 so the expander at
			// least shows the account as online.
			byEmail[email] = append(byEmail[email], "0:"+email)
			continue
		}
		for _, id := range ids {
			byEmail[email] = append(byEmail[email], strconv.Itoa(id)+":"+email)
		}
	}

	allowed := func(int) bool { return true }
	if user := session.GetLoginUser(c); user != nil && !callerFlags(c).IsSuperAdmin {
		ids, err := adminaccess.AccessibleInboundIds(user.Id)
		if err != nil {
			jsonObj(c, []string{}, nil)
			return
		}
		granted := make(map[int]bool, len(ids))
		for _, id := range ids {
			granted[id] = true
		}
		allowed = func(id int) bool { return id == 0 || granted[id] }
	}

	out := make([]string, 0, len(online))
	for _, email := range scopeEmailsVpn(c, online) {
		for _, pair := range byEmail[email] {
			sep := strings.IndexByte(pair, ':')
			id, err := strconv.Atoi(pair[:sep])
			if err != nil || !allowed(id) {
				continue
			}
			out = append(out, pair)
		}
	}
	jsonObj(c, out, nil)
}

// --- shared helpers ---------------------------------------------------------

// vpnOnlineEmails reads the online-identity source the server registered at
// start-up (xrayplane.SetOnlineClientsSource). Unwired it answers nil, and every
// account reads as offline — the accounts adapter's documented default.
func vpnOnlineEmails() []string {
	if vpnOnlineClientsSource != nil {
		return vpnOnlineClientsSource()
	}
	return nil
}

// scopeEmailsVpn filters a panel-wide list of client emails down to the caller's
// own. Super admins see everything, an admin sees the clients on inbounds they
// hold, and a reseller sees only the accounts they created. Fails CLOSED.
func scopeEmailsVpn(c *gin.Context, emails []string) []string {
	user := session.GetLoginUser(c)
	if user == nil {
		return []string{}
	}
	if callerFlags(c).IsSuperAdmin {
		return emails
	}
	mine := make([]string, 0, len(emails))
	if callerFlags(c).IsReseller {
		owned, err := resellerOwnedEmailsVpn(user.Id)
		if err != nil {
			return []string{}
		}
		for _, email := range emails {
			if owned[strings.ToLower(email)] {
				mine = append(mine, email)
			}
		}
		return mine
	}
	access, err := adminaccess.ClientEmailAccess()
	if err != nil {
		return []string{}
	}
	for _, email := range emails {
		if access[email][user.Id] {
			mine = append(mine, email)
		}
	}
	return mine
}

// resellerOwnedEmailsVpn is the reseller ledger's owned set, lower-cased keys —
// the exact map shape every scope filter in this package compares against.
func resellerOwnedEmailsVpn(userId int) (map[string]bool, error) {
	owned, err := reseller.OwnedEmails(userId)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(owned))
	for email := range owned {
		out[strings.ToLower(email)] = true
	}
	return out, nil
}

// resellerOwnedOnInboundVpn lists the reseller-owned account emails one inbound
// serves (vpn-ui ResellerService.OwnedEmailsOnInbound).
func resellerOwnedOnInboundVpn(inboundId int) ([]string, error) {
	return reseller.OwnedEmailsOnInbound(inboundId)
}

// resellerUsageVpn snapshots lifetime consumption for a delete-time refund
// (vpn-ui ResellerService.UsageSnapshot). Keyed lower-cased, like every refund
// lookup.
func resellerUsageVpn(emails []string) (map[string]int64, error) {
	usage, err := reseller.UsageSnapshot(emails)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(usage))
	for email, used := range usage {
		out[strings.ToLower(email)] = used
	}
	return out, nil
}

// resellerDropInboundVpn settles the ledger after an inbound delete, refunding
// the accounts this inbound was the LAST inbound for (vpn-ui
// ResellerService.DropInbound).
func resellerDropInboundVpn(inboundId int, emails []string, usage map[string]int64) error {
	return reseller.DropInbound(inboundId, emails, usage)
}

// vpnAfterClientDelete settles the reseller ledger after a client delete: refund
// the unused part of the charge to whoever sold the account (vpn-ui
// refundDeletedClient). A no-op for a house-owned account, so every delete path
// can call it unconditionally. The consumption snapshot is read BEFORE the delete
// destroys the traffic row — here, where the caller has just run it.
func vpnAfterClientDelete(email string) {
	if email == "" {
		return
	}
	used, known, err := reseller.UsageOf(email)
	if err != nil {
		loggerVpnWarning("reading traffic before a delete, refund will be withheld: ", err)
		return
	}
	if err := reseller.RefundDeleted(email, used, known); err != nil {
		loggerVpnWarning("refunding a reseller for a deleted account: ", err)
	}
}

// filterSettingsClientsForReseller drops every settings.clients[] entry the given
// reseller does not own from the inbound, in place (vpn-ui
// InboundService.FilterInboundForReseller's settings half). Used by the
// single-inbound reads so a reseller cannot read another seller's credentials off
// a shared inbound's detail row.
func filterSettingsClientsForReseller(inbound *model.Inbound, owned map[string]bool) {
	if inbound == nil || len(owned) == 0 {
		return
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(inbound.Settings), &parsed); err != nil {
		return
	}
	clients, _ := parsed["clients"].([]any)
	kept := make([]any, 0, len(clients))
	for _, cl := range clients {
		cm, _ := cl.(map[string]any)
		email, _ := cm["email"].(string)
		if email != "" && owned[strings.ToLower(email)] {
			kept = append(kept, cl)
		}
	}
	parsed["clients"] = kept
	if b, err := json.Marshal(parsed); err == nil {
		inbound.Settings = string(b)
	}
}

// singlePostedClientEntry pulls the ONE client entry out of a posted settings
// blob, as the raw map the accounts layer reads. A map rather than a model.Client
// because the account columns are decided on the PRESENCE of a key, not on its
// decoded value.
func singlePostedClientEntry(settings string) (map[string]any, error) {
	var parsed struct {
		Clients []map[string]any `json:"clients"`
	}
	if err := json.Unmarshal([]byte(settings), &parsed); err != nil {
		return nil, err
	}
	if len(parsed.Clients) != 1 {
		return nil, fmt.Errorf("expected exactly one client, got %d", len(parsed.Clients))
	}
	return parsed.Clients[0], nil
}

// postedMembershipIds reads the inbound id set a client-mutating request carried
// (vpn-ui postedMembershipIds).
func postedMembershipIds(c *gin.Context, targetId int) ([]int, bool) {
	raw := c.PostFormArray("inboundIds")
	seen := map[int]bool{}
	out := []int{}
	if targetId > 0 {
		seen[targetId] = true
		out = append(out, targetId)
	}
	named := 0
	for _, value := range raw {
		// The empty-string sentinel is how the browser posts a CLEARED checkbox
		// group; it means "none ticked", not "id 0".
		if value == "" {
			continue
		}
		id, err := strconv.Atoi(value)
		if err != nil || id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
		named++
	}
	// A named inbound beats the flag, always.
	if named > 0 {
		return out, true
	}
	if isTruthyForm(c.PostForm("noInbounds")) {
		return nil, true
	}
	if len(raw) == 0 {
		if targetId <= 0 {
			return nil, false
		}
		return []int{targetId}, false
	}
	// The list was posted and named nothing usable — the cleared-checkbox sentinel,
	// or ids that do not parse.
	return out, true
}

// isTruthyForm reads a boolean posted as a form field.
func isTruthyForm(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// validateMembershipSetVpn refuses a set the data plane cannot actually serve.
func validateMembershipSetVpn(inboundIds []int) error {
	if len(inboundIds) < 2 {
		return nil
	}
	inbounds := make([]*model.Inbound, 0, len(inboundIds))
	for _, id := range inboundIds {
		inbound, err := vpnInboundById(id)
		if err != nil || inbound == nil {
			return fmt.Errorf("inbound %d not found", id)
		}
		inbounds = append(inbounds, inbound)
	}
	return vpnAccountService.ValidateMembershipSet(inbounds)
}

// distinctTargetEmailsVpn reduces a bulk target list to the ACCOUNTS it names.
func distinctTargetEmailsVpn(targets []reseller.BulkClientTarget) []string {
	seen := make(map[string]bool, len(targets))
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		key := strings.ToLower(strings.TrimSpace(t.Email))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t.Email)
	}
	return out
}

// distinctInboundIdsOfTargets lists the unique inbound ids a bulk target list names.
func distinctInboundIdsOfTargets(targets []reseller.BulkClientTarget) []int {
	seen := map[int]bool{}
	out := []int{}
	for _, t := range targets {
		if t.InboundId <= 0 || seen[t.InboundId] {
			continue
		}
		seen[t.InboundId] = true
		out = append(out, t.InboundId)
	}
	return out
}

// unionInboundIds returns the ids in a and b, deduped, a's order first.
func unionInboundIds(a, b []int) []int {
	seen := make(map[int]bool, len(a)+len(b))
	out := make([]int, 0, len(a)+len(b))
	for _, lists := range [2][]int{a, b} {
		for _, id := range lists {
			if id <= 0 || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// subtractInboundIds returns the ids in a that are not in b, order preserved.
func subtractInboundIds(a, b []int) []int {
	drop := make(map[int]bool, len(b))
	for _, id := range b {
		drop[id] = true
	}
	out := make([]int, 0, len(a))
	for _, id := range a {
		if !drop[id] {
			out = append(out, id)
		}
	}
	return out
}

// intersectInboundIds returns the ids present in both lists, order following a.
func intersectInboundIds(a, b []int) []int {
	keep := make(map[int]bool, len(b))
	for _, id := range b {
		keep[id] = true
	}
	out := make([]int, 0, len(a))
	for _, id := range a {
		if keep[id] {
			out = append(out, id)
		}
	}
	return out
}
