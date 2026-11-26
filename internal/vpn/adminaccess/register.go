// Wire-up into the accounts adapter seams.
//
// The accounts package predates this one and holds the seams its list/picker
// scoping needs (AccessibleInboundIds, OwnedResellerEmails, the Viewer role
// flags). It cannot import this package — this package imports accounts for the
// membership/identity resolution — so the delegation runs through registered
// function values, the same pattern the mtproto lifter and the radius seams
// use: the owning package fills the var from init(), and the adapter's minimal
// default stays as the fallback for builds that do not link the owner.
//
// Deliberately NOT ported here: vpn-ui's AdminService.MigrationOverviewAccess.
// It bitwise-ORs PermAccessOverview into users.permissions — a COLUMN pxpanel
// does not have — guarded by a settings marker. The backfill lands with the
// user-roles columns wave, which is the one that can run it; running it here
// would log a failed UPDATE on every boot.
package adminaccess

import "github.com/ImSoheilPx/pxpanel/internal/vpn/accounts"

func init() {
	// inbound-access filters: the adapter's AccessibleInboundIds is this exact
	// query, now owned here.
	accounts.RegisterAccessibleInboundIds(AccessibleInboundIds)
	// role flags: the adapter's ViewerForUser derives both flags the same way;
	// the derivation now lives in FlagsFor and is registered here.
	accounts.RegisterRoleFlags(IsSuperAdmin, IsReseller)
}
