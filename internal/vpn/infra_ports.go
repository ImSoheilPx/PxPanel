// Package vpn is the root of the ported vpn-ui network/RADIUS infrastructure:
//
//	range      the VPN address plan (package vpnrange; pure math + the slot
//	           machinery, DB reached through the injected handle below)
//	nftables   nftables table/rules management + per-account egress accounting
//	radius     in-binary RADIUS server (MS-CHAPv2 / PAP / EAP-MSCHAPv2) + session registry
//	rbridge    non-RADIUS protocol reconcile/quota/evict sweeper
//
// This file holds the thin port-local seams the ported code needs where vpn-ui
// reached into its web/service layer (InboundService / SettingService /
// trafficmultiplier). Everything here is deliberately free of imports from
// internal/web (the target web wave lands later) and — importantly for the
// GOOS=linux cross-build — free of imports from internal/database, whose CGO
// sqlite driver cannot compile in a dependency build on a host without a
// linux C toolchain. The gorm handle is injected instead (SetDB); the wire-up
// (later web wave) passes database.GetDB() exactly once.
package vpn

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"gorm.io/gorm"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
)

// ---------------------------------------------------------------------------
// DB handle injection
// ---------------------------------------------------------------------------

var (
	dbMu  sync.RWMutex
	getDB func() *gorm.DB
)

// SetDB wires the target's database handle into every vpn infrastructure
// package. Call it once at server wire-up with database.GetDB(); all ported
// services resolve the handle lazily through DB() so a nil handle (tests,
// GOOS builds) degrades to "no database" instead of panicking.
func SetDB(fn func() *gorm.DB) {
	dbMu.Lock()
	getDB = fn
	dbMu.Unlock()
}

// DB returns the injected gorm handle, or nil when none was wired.
func DB() *gorm.DB {
	dbMu.RLock()
	defer dbMu.RUnlock()
	if getDB == nil {
		return nil
	}
	return getDB()
}

// ---------------------------------------------------------------------------
// Traffic sink (vpn-ui web/service/trafficmultiplier.go foldClientTraffic)
// ---------------------------------------------------------------------------

// TrafficSink folds a torn-down session's final counter bytes into an account's
// client_traffics row. vpn-ui's foldClientTraffic additionally applies the
// owning inbound's traffic multiplier and writes a per-inbound membership
// breakdown; both live in the account/membership layer that lands in a later
// wave. Replace the sink registered here at wire-up to restore that behaviour
// (SetTrafficSink) — every RADIUS/rbridge teardown path already calls it with
// the (email, protocol, serving inbound) triple it needs.
type TrafficSink interface {
	FoldClientTraffic(email, protocol string, inboundId int, up, down int64)
}

var (
	sinkMu sync.RWMutex
	sink   TrafficSink = defaultTrafficSink{}
)

// SetTrafficSink replaces the default sink. nil restores the default.
func SetTrafficSink(s TrafficSink) {
	sinkMu.Lock()
	if s == nil {
		sink = defaultTrafficSink{}
	} else {
		sink = s
	}
	sinkMu.Unlock()
}

// TrafficSinkFor returns the registered sink (never nil).
func TrafficSinkFor() TrafficSink {
	sinkMu.RLock()
	defer sinkMu.RUnlock()
	return sink
}

// defaultTrafficSink is the minimal sink that compiles against the target
// schema: a plain read-modify-free UPDATE of client_traffics.up/down by email.
// DELIBERATELY NOT the vpn-ui semantics — the traffic multiplier weighting and
// the per-inbound membership breakdown (web/service/trafficmultiplier.go,
// membershipusage) are account-layer features that land with the inbound wave.
type defaultTrafficSink struct{}

func (defaultTrafficSink) FoldClientTraffic(email, protocol string, inboundId int, up, down int64) {
	_ = protocol  // consumed by the multiplier/membership sink, not this one
	_ = inboundId // ditto: which membership the bytes belong to
	if email == "" || (up <= 0 && down <= 0) {
		return
	}
	db := DB()
	if db == nil {
		return
	}
	if err := db.Exec(
		"UPDATE client_traffics SET up = up + ?, down = down + ? WHERE email = ?",
		up, down, email).Error; err != nil {
		// model/logger-free path: the caller logs through its own logger anyway;
		// keep this silent-but-safe to avoid an import cycle into logger from root.
		_ = err
	}
}

// ---------------------------------------------------------------------------
// Protocol evictors (vpn-ui: killOcservByIP / SstpService.KillClientIP /
// Ikev2Service.KillClientIP — protocol-service teardowns)
// ---------------------------------------------------------------------------

// RegisterProtocolEvictor attaches the teardown for one protocol's sessions by
// tunnel IP. The protocol wave registers its own (ocserv occtl, accel-cmd,
// swanctl --terminate). The RADIUS User-Limit "accept" eviction and
// KillSessionsByEmail dispatch through here; protocols without a registered
// evictor are logged and skipped rather than torn down blindly.
func RegisterProtocolEvictor(protocol string, evict func(ip string) error) {
	evictorMu.Lock()
	protocolEvictors[protocol] = evict
	evictorMu.Unlock()
}

// EvictProtocolIP tears down the session of `protocol` at tunnel IP `ip`.
// Returns an error when no evictor is registered.
func EvictProtocolIP(protocol, ip string) error {
	evictorMu.RLock()
	evict, ok := protocolEvictors[protocol]
	evictorMu.RUnlock()
	if !ok {
		return fmt.Errorf("no evictor registered for protocol %q", protocol)
	}
	return evict(ip)
}

var (
	evictorMu        sync.RWMutex
	protocolEvictors = map[string]func(ip string) error{}
)

// ---------------------------------------------------------------------------
// Liveness probes (vpn-ui: RadiusService.isIPActive per-protocol branches)
// ---------------------------------------------------------------------------

// RegisterIPProber attaches a liveness probe for one protocol: does a live
// tunnel still hold `ip`? l2tp/pptp/openvpn/openconnect ship default probes
// inside the radius package (plain `ip` shell-outs); ikev2 (swanctl SA list)
// and any daemon-based protocol register their own.
func RegisterIPProber(protocol string, probe func(ip string) bool) {
	proberMu.Lock()
	ipProbers[protocol] = probe
	proberMu.Unlock()
}

// ProbeIPActive reports whether protocol's tunnel at `ip` is live. Unknown
// protocols report active (fail-open: a missed probe only delays cleanup,
// whereas a false "dead" frees a live device's address).
func ProbeIPActive(protocol, ip string) bool {
	proberMu.RLock()
	probe, ok := ipProbers[protocol]
	proberMu.RUnlock()
	if !ok {
		return true
	}
	return probe(ip)
}

var (
	proberMu  sync.RWMutex
	ipProbers = map[string]func(ip string) bool{}
)

// ---------------------------------------------------------------------------
// Per-inbound subnet resolution (vpn-ui: per-protocol GetSubnetsForInbound)
// ---------------------------------------------------------------------------

// RegisterSubnetResolver attaches the address-pool reader for one protocol.
// Resolvers return the ordered /24 prefixes ("10.0.5") and/or CIDRs
// ("10.6.8.0/24") an inbound owns; both shapes are accepted downstream
// (subnetHoldsIP in the radius package handles each).
func RegisterSubnetResolver(protocol string, resolve func(inbound *model.Inbound) []string) {
	subnetMu.Lock()
	subnetResolvers[protocol] = resolve
	subnetMu.Unlock()
}

// SubnetsForInbound resolves an inbound's address pool. Falls back to the
// settings-JSON ipRanges/ipRange decode for protocols the protocol wave has
// not registered yet, which matches the stored shape for every pool protocol.
func SubnetsForInbound(protocol string, inbound *model.Inbound) []string {
	subnetMu.RLock()
	resolve, ok := subnetResolvers[protocol]
	subnetMu.RUnlock()
	if ok {
		return resolve(inbound)
	}
	// Default: the shared settings-JSON decode (vpnrange.SubnetsOf over
	// ipRanges, legacy single ipRange). Good enough for session→inbound
	// attribution until the protocol wave registers exact readers.
	if inbound == nil {
		return nil
	}
	return vpnrangeSubnetsOfSettings(inbound.Settings)
}

var (
	subnetMu        sync.RWMutex
	subnetResolvers = map[string]func(inbound *model.Inbound) []string{}
)

// vpnrangeSubnetsOfSettings is a small local decode so the root package does
// not import the vpnrange package for one function (root stays leaf-only).
func vpnrangeSubnetsOfSettings(settings string) []string {
	if settings == "" {
		return nil
	}
	var raw struct {
		IpRanges []string `json:"ipRanges"`
		IpRange  string   `json:"ipRange"` // legacy single-range field
	}
	if err := json.Unmarshal([]byte(settings), &raw); err != nil {
		return nil
	}
	ranges := raw.IpRanges
	if len(ranges) == 0 && raw.IpRange != "" {
		ranges = []string{raw.IpRange}
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range ranges {
		// "A.B.C.s-A.B.C.e" -> "A.B.C" (drop everything from the last dash
		// back to the third dot). Malformed entries are skipped.
		dash := strings.LastIndexByte(r, '-')
		if dash < 0 {
			continue
		}
		start := r[:dash]
		dots := strings.Count(start, ".")
		if dots != 3 {
			continue
		}
		prefix := start[:strings.LastIndexByte(start, '.')]
		if prefix != "" && !seen[prefix] {
			seen[prefix] = true
			out = append(out, prefix)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Settings port (vpn-ui SettingService.GetRadiusSecret)
// ---------------------------------------------------------------------------

// RadiusSecret reads the shared RADIUS secret from the target settings KV
// store (model.Setting, key "radiusSecret" — the vpn-ui key name is kept so a
// migrated DB keeps working). ok=false when unset/absent; callers fall back to
// the running server's current secret.
func RadiusSecret() (string, bool) {
	db := DB()
	if db == nil {
		return "", false
	}
	var s model.Setting
	if err := db.Where("key = ?", "radiusSecret").First(&s).Error; err != nil {
		return "", false
	}
	return s.Value, s.Value != ""
}
