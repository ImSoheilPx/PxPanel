// Package-level registration of the seams the RADIUS foundation asks the
// protocol wave to fill.
//
// PORT NOTE: vpn-ui's radius.go called killOcservByIP(inboundId, ip) directly
// from the User-Limit accept-eviction. The foundation's dispatch is
// vpn.EvictProtocolIP(protocol, ip) — ip-only — so the evictor registered here
// locates the ocserv instance by scanning the per-inbound occtl sockets instead
// of being handed the inbound id. The RADIUS session registry already knows the
// OpenConnect liveness probe (`ip route get` through an ocserv device), so only
// the evictor and the subnet reader need registering.
package ocserv

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/procmgr"
	vpnrange "github.com/ImSoheilPx/pxpanel/internal/vpn/range"
)

// Register attaches OpenConnect's evictor and subnet reader to the shared
// registries. Call once at server wire-up; safe to call again (last one wins
// with an identical implementation).
func Register() {
	vpn.RegisterProtocolEvictor("openconnect", evictRegisteredIP)
	vpn.RegisterSubnetResolver("openconnect", ocservSubnetsForInbound)
}

// evictRegisteredIP is the EvictProtocolIP seam: find whichever running ocserv
// holds tunnel IP `ip` and disconnect that session. The occtl sockets exist only
// for inbounds whose daemon is running (RestartServices started them), so the
// scan is bounded by the enabled ocserv count.
func evictRegisteredIP(ip string) error {
	socks, err := filepath.Glob("/var/run/ocserv/occtl-*.sock")
	if err != nil {
		return err
	}
	// Lowest inbound id first, so behaviour is deterministic when two inbounds
	// (mis)configured the same address.
	sort.Slice(socks, func(i, j int) bool {
		a, b := sockInboundId(socks[i]), sockInboundId(socks[j])
		return a < b
	})
	for _, sock := range socks {
		if evictByIPOnSocket(sock, ip) {
			return nil
		}
	}
	return fmt.Errorf("no live ocserv session holds %s", ip)
}

// evictByIPOnSocket disconnects the session with tunnel IP `ip` on one occtl
// socket. Reports whether it found (and asked ocserv to drop) the session — the
// same best-effort contract as vpn-ui's killOcservByIP, made error-reporting so
// EvictProtocolIP can log a real miss.
func evictByIPOnSocket(sock, ip string) bool {
	bin := procmgr.DaemonBin("occtl")
	out, err := probeCmd(bin, "-s", sock, "-j", "show", "users")
	if err != nil {
		return false
	}
	var users []struct {
		ID   json.Number `json:"ID"`
		IPv4 string      `json:"IPv4"`
	}
	if err := json.Unmarshal(out, &users); err != nil {
		return false
	}
	for _, u := range users {
		if u.IPv4 == ip {
			_, _ = probeCmd(bin, "-s", sock, "disconnect", "id", u.ID.String())
			return true
		}
	}
	return false
}

// sockInboundId extracts the inbound id from an occtl socket path
// ("/var/run/ocserv/occtl-7.sock" → 7; 0 when unparsable).
func sockInboundId(sock string) int {
	base := filepath.Base(sock)
	base = strings.TrimPrefix(base, "occtl-")
	base = strings.TrimSuffix(base, ".sock")
	id, _ := strconv.Atoi(base)
	return id
}

// ocservSubnetsForInbound returns the ordered /24 prefixes ("10.4.5") the
// inbound's sessions hold addresses in: its stored ranges, or the legacy
// id-derived 10.4.{id}. Mirrors ocservBlockFor's fallback.
func ocservSubnetsForInbound(inbound *model.Inbound) []string {
	if inbound == nil {
		return nil
	}
	settings, err := (&OcservService{}).parseSettings(inbound)
	if err != nil {
		return nil
	}
	if subs := vpnrange.SubnetsOf(settings.effectiveRanges()); len(subs) > 0 {
		return subs
	}
	return []string{fmt.Sprintf("10.%d.%d", vpnrange.ProtocolBase("openconnect"), inbound.Id)}
}
