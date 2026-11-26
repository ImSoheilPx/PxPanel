// Wire-up into the accounts adapter seam: the reseller package owns the ledger
// (ResellerClient) and registers its ownership reader into the accounts
// adapter, replacing the minimal query there. See adminaccess/register.go for
// why this runs through registered function values and not an import.
package reseller

import "github.com/ImSoheilPx/pxpanel/internal/vpn/accounts"

func init() {
	// accounts.OwnedResellerEmails answers "whose accounts are these" for the
	// Clients-page scoping; the ledger's own reader lower-cases its keys, which
	// is what every consumer compares against (accountKey).
	accounts.RegisterOwnedResellerEmails(OwnedEmails)
}
