// Relay account resolution: which accounts a relay's paired socks inbound
// carries, and whether the relay egresses through Xray at all. Ported from
// vpn-ui mtproto.go (activeClients / anyAdtag / usingRouting / GetSocksConfig)
// and ssh.go (activeClients / GetSocksConfig), with the per-protocol
// parseSettings calls replaced by a registration seam so the mtproto/ssh waves
// can override the default readers without touching this package.
package xrayplane

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
)

// MtprotoSystemAccount is the socks identity telemt falls back to for its own
// account-less connections (startup DC probes). It is deliberately not a valid
// email, so it cannot be shadowed by a real account and never matches an
// operator's per-client routing rule; that traffic takes the default outbound.
// (vpn-ui mtproto.go mtprotoSystemAccount.)
const MtprotoSystemAccount = "telemt-system"

// RelayAccountsProvider resolves one relay inbound's socks account list from
// its stored settings. routed=false means the relay must NOT egress through
// Xray (mtproto adtag / middle-proxy mode), and no socks inbound is injected.
type RelayAccountsProvider func(inbound *model.Inbound) (accounts []SocksAccount, routed bool)

var (
	relayProvidersMu sync.RWMutex
	relayProviders   = map[string]RelayAccountsProvider{}
)

// RegisterRelayAccounts attaches a relay's account reader, replacing the
// default one (nil removes an override). The mtproto/ssh waves call this when
// their settings types land; until then the defaults below read the same
// stored JSON shapes.
func RegisterRelayAccounts(protocol string, p RelayAccountsProvider) {
	relayProvidersMu.Lock()
	if p == nil {
		delete(relayProviders, protocol)
	} else {
		relayProviders[protocol] = p
	}
	relayProvidersMu.Unlock()
}

// RelayAccountsFor resolves the account list for a relay inbound. Unknown or
// non-relay protocols report routed=false.
func RelayAccountsFor(protocol string, inbound *model.Inbound) ([]SocksAccount, bool) {
	relayProvidersMu.RLock()
	p, ok := relayProviders[protocol]
	relayProvidersMu.RUnlock()
	if ok && p != nil {
		return p(inbound)
	}
	if inbound == nil {
		return nil, false
	}
	switch protocol {
	case string(defaults.ProtoMTProto):
		return defaultMtprotoAccounts(inbound.Settings)
	case string(defaults.ProtoSSH):
		return defaultSshAccounts(inbound.Settings)
	default:
		return nil, false
	}
}

// defaultMtprotoAccounts ports MtprotoService.GetSocksConfig's account body:
// the system account (telemt's own DC-reachability probes carry no account and
// fall back to the upstream's configured username, so that identity needs an
// account too or the probes fail the handshake and telemt reports every DC
// unreachable), then every active client.
//
// routed mirrors usingRouting: adtag forces direct egress, because the
// middle-proxy RPC key is derived from the proxy's own egress IP AND port, so
// ANY account carrying a tag puts the whole inbound on that path.
func defaultMtprotoAccounts(settingsJSON string) ([]SocksAccount, bool) {
	var settings struct {
		Clients []struct {
			Email       string `json:"email"`
			Secret      string `json:"secret"`
			AdtagEnable bool   `json:"adtagEnable"`
			Adtag       string `json:"adtag"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(settingsJSON), &settings); err != nil {
		return nil, false
	}

	// anyAdtag: Any, not each. The FIELD is per-account but its EFFECT is a
	// process-wide switch (use_middle_proxy): tagging ONE account takes Xray
	// routing away from every account on the inbound. Telegram's design, not a
	// telemt gap.
	for _, c := range settings.Clients {
		if c.AdtagEnable && strings.TrimSpace(c.Adtag) != "" {
			return nil, false
		}
	}

	// activeClients: usable as telemt accounts, in a stable order so the
	// rendered config is byte-identical when nothing changed (which keeps the
	// config watcher from reloading on every regeneration). NOTE: vpn-ui does
	// NOT filter on enable here — ported as-is; the enable state is enforced by
	// the depletion sweep, not the config build.
	var active []string
	for _, c := range settings.Clients {
		if strings.TrimSpace(c.Email) == "" || strings.TrimSpace(c.Secret) == "" {
			continue
		}
		active = append(active, c.Email)
	}
	sort.Strings(active)

	accounts := []SocksAccount{{User: MtprotoSystemAccount, Pass: MtprotoSystemAccount}}
	seen := map[string]bool{MtprotoSystemAccount: true}
	for _, email := range active {
		if seen[email] {
			continue
		}
		seen[email] = true
		accounts = append(accounts, SocksAccount{User: email, Pass: email})
	}
	return accounts, true
}

// defaultSshAccounts ports SshService.GetSocksConfig's account body: accounts
// usable by the SSH server (non-empty id, password, email, and enabled),
// de-duplicated by email. An inbound with none returns routed=false: a socks
// inbound with no accounts would reject every egress, so inject nothing.
func defaultSshAccounts(settingsJSON string) ([]SocksAccount, bool) {
	var settings struct {
		Clients []struct {
			ID       string `json:"id"`
			Password string `json:"password"`
			Email    string `json:"email"`
			Enable   bool   `json:"enable"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(settingsJSON), &settings); err != nil {
		return nil, false
	}

	accounts := make([]SocksAccount, 0, len(settings.Clients))
	seen := map[string]bool{}
	for _, c := range settings.Clients {
		if strings.TrimSpace(c.ID) == "" || strings.TrimSpace(c.Password) == "" || strings.TrimSpace(c.Email) == "" {
			continue
		}
		if !c.Enable {
			continue
		}
		if seen[c.Email] {
			continue
		}
		seen[c.Email] = true
		accounts = append(accounts, SocksAccount{User: c.Email, Pass: c.Email})
	}
	if len(accounts) == 0 {
		return nil, false
	}
	return accounts, true
}
