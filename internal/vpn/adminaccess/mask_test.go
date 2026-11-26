package adminaccess

// The cgo-free halves of vpn-ui web/service/admin_test.go: the permission-mask
// evaluation and the derived-mask rules. The DB-bound checks live in
// access_db_test.go (gated linux && cgo).
//
// The evaluation itself is model.Permission / model.AdminFlags.Can (ported in
// internal/database/model/permission.go); these tests pin the RULES this package
// adds around it — super-admin bypass, the reseller's derived mask, and the
// disabled-anchored fail-closed default.

import (
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
)

// Slugs are the wire format: what crosses to the API and the UI, so a mask must
// round-trip through them and an unknown slug must cost only itself.
func TestPermissionMaskRoundTrip(t *testing.T) {
	slugs := []string{"accessInbounds", "editClient", "bulkOperation"}
	mask := model.PermissionsFromSlugs(slugs)

	if !mask.Has(model.PermAccessInbounds) || !mask.Has(model.PermEditClient) || !mask.Has(model.PermBulkOperation) {
		t.Error("mask lost a permission it was given")
	}
	if mask.Has(model.PermDeleteInbound) || mask.Has(model.PermPanelSettings) {
		t.Error("mask granted a permission it was never given")
	}
	got := mask.Slugs()
	if len(got) != 3 {
		t.Errorf("round-trip = %v; want 3 slugs", got)
	}
	// An unknown slug must cost only itself, not the whole save.
	mixed := model.PermissionsFromSlugs([]string{"accessInbounds", "nonsenseSlug"})
	if !mixed.Has(model.PermAccessInbounds) || mixed.Slugs()[0] != "accessInbounds" {
		t.Error("an unknown slug must be ignored, not poison the mask")
	}
}

// A non-super admin is confined to their own permission bits, and a disabled
// account can do nothing regardless of what it was granted. (vpn-ui User.Can,
// expressed over the AdminFlags snapshot pxpanel resolves for a user.)
func TestAdminFlagsCan(t *testing.T) {
	limited := model.AdminFlags{
		Enable:      true,
		Permissions: model.PermAccessInbounds | model.PermEditClient,
	}
	if !limited.Can(model.PermAccessInbounds) || !limited.Can(model.PermEditClient) {
		t.Error("granted permission denied")
	}
	if limited.Can(model.PermDeleteInbound) || limited.Can(model.PermPanelSettings) {
		t.Error("ungranted permission allowed")
	}

	disabled := model.AdminFlags{Enable: false, Permissions: model.PermAccessInbounds, IsSuperAdmin: true}
	if disabled.Can(model.PermAccessInbounds) {
		t.Error("a disabled account must be able to do nothing, even as super admin")
	}

	// The zero snapshot (an unresolvable user) can do nothing: the flags fail
	// closed on every axis at once.
	var none model.AdminFlags
	if none.Can(model.PermAccessInbounds) {
		t.Error("a zero snapshot must be able to do nothing")
	}
}

// A reseller's stored mask is IGNORED — the role derives it — so a stale or
// tampered permissions column cannot widen the role. The derived set is
// exactly the selling toolkit: the client bits and bulkOperation (scoped, in
// this package's sibling reseller package, to the reseller's own accounts and
// priced against their balance), accessInbounds to see the inbounds they were
// assigned — and deliberately NOT the inbound-mutation bits, the settings bits,
// manageResellers, or either overview bit (their profile booleans answer for
// the overview, and model.Permission's doc records why).
func TestResellerDerivedMask(t *testing.T) {
	// A tampered column: every bit on the row. The role must still confine.
	tampered := model.AdminFlags{
		Enable:      true,
		IsReseller:  true,
		Permissions: model.Permission(1<<14 - 1), // all fourteen bits
	}
	for _, perm := range []model.Permission{
		model.PermAccessInbounds, model.PermCreateClient, model.PermEditClient,
		model.PermDeleteClient, model.PermBulkOperation,
	} {
		if !tampered.Can(perm) {
			t.Errorf("reseller denied %v; the derived selling toolkit must hold", perm)
		}
	}
	for _, perm := range []model.Permission{
		model.PermCreateInbound, model.PermEditInbound, model.PermDeleteInbound,
		model.PermCoreSettings, model.PermXraySettings, model.PermPanelSettings,
		model.PermManageResellers, model.PermAccessOverview, model.PermOverviewManage,
	} {
		if tampered.Can(perm) {
			t.Errorf("reseller granted %v off a tampered mask; the stored column must be ignored", perm)
		}
	}

	// The stored mask alone (role flags off) must NOT confer the derived set:
	// the derivation runs on the ROLE, not on whatever the column holds.
	storedOnly := model.AdminFlags{Enable: true, Permissions: model.PermBulkOperation}
	if !storedOnly.Can(model.PermBulkOperation) {
		t.Error("a plain admin answers from their own mask")
	}
	if storedOnly.Can(model.PermCreateClient) {
		t.Error("a plain admin must not inherit the reseller's derived bits")
	}
}
