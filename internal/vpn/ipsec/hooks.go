package ipsec

// The wiring that switches pkgmgr's libreswan/charon plumbing onto the bundled
// paths implemented in this package. vpn-ui called usingBundledIpsec() /
// startBundledPluto() / syncCharon() as plain functions in the one service
// package; here pkgmgr (which the CORE and provisioning code drives) reaches
// them through its IpsecHooks seam, populated below at link time.
//
// Importing this package is what turns the bundled paths on — exactly the
// vpn-ui semantics, where ipsec_bundle.go/charon.go sat in the same package as
// everything that referenced them. The l2tp package imports it (its
// RestartServices drives the IPsec layer directly); the core wave's
// Provisioner does too.

import (
	"github.com/ImSoheilPx/pxpanel/internal/vpn/pkgmgr"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"
)

func init() {
	pkgmgr.IpsecHooks.UsingBundled = UsingBundledIpsec
	pkgmgr.IpsecHooks.UsingStrongswanBundle = func() bool {
		return procmgrHasStrongswanBundle()
	}
	pkgmgr.IpsecHooks.EnsureBundledLibreswan = EnsureBundledLibreswan
	pkgmgr.IpsecHooks.StartBundledPluto = StartBundledPluto
	pkgmgr.IpsecHooks.StopBundledPluto = StopBundledPluto
	pkgmgr.IpsecHooks.SyncCharon = SyncCharon
	pkgmgr.IpsecHooks.StopCharon = StopCharon
	pkgmgr.IpsecHooks.SwanctlConfDir = func() string { return swanctlConfDir }
}

// procmgrHasStrongswanBundle reports whether the strongSwan relocatable tree is
// embedded (vpn-ui backend.HasStrongswanBundle). With no bundle layer the
// bundled path is out of play and pkgmgr drives the host services.
func procmgrHasStrongswanBundle() bool {
	return procmgr.Bundles().HasStrongswanBundle()
}
