// Online-identity source: the bridge between the running core's session list
// and the accounts layer's "online" sort. vpn-ui read InboundService's
// process-global online list (xray.Process.GetOnlineClients / SetOnlineClients);
// here the core process belongs to the web layer, so the controllers wave
// registers the reader and every consumer goes through the accounts adapter.
package xrayplane

import (
	"github.com/ImSoheilPx/pxpanel/internal/vpn/accounts"
)

// SetOnlineClientsSource registers the running core's online-identity reader
// (the vpn-ui equivalent of Process.SetOnlineClients + GetOnlineClients). It is
// forwarded to accounts.RegisterOnlineClientEmails, which is what the Clients
// list's online sort reads — one registration covers both consumers, so the two
// can never disagree about who is online.
//
// TODO(controllers wave): wire it at server start-up with the core process's
// online list, e.g.
//
//	xrayplane.SetOnlineClientsSource(func() []string { return theProcess.GetOnlineClients() })
//
// Unwired, every account reads as offline (the accounts adapter's default).
func SetOnlineClientsSource(fn func() []string) {
	accounts.RegisterOnlineClientEmails(fn)
}
