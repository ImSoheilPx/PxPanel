package vpnrange

import (
	"encoding/json"
	"net"

	"github.com/ImSoheilPx/pxpanel/internal/database/model"
)

// Exported API surface for the protocol waves.
//
// vpnrange.go keeps the original vpn-ui file contents (package-private, as they
// were inside one giant `service` package). This file is the package boundary:
// everything a protocol service, the RADIUS server, nftables writer or inbound
// controller needs is re-exported here under Go's capitalised convention. Nothing
// new is implemented — each wrapper names its vpnrange.go counterpart.

// PrefixToMask returns the dotted-decimal netmask for an IPv4 prefix length.
func PrefixToMask(prefix int) string { return prefixToMask(prefix) }

// NormUserLimitStrategy normalizes a per-inbound User Limit Strategy ("reject"
// everything else reads as "accept").
func NormUserLimitStrategy(s string) string { return normUserLimitStrategy(s) }

// NormUserLimit maps a PRESENT user-limit value to a device-block size.
// See the normUserLimit doc before calling: only for values known to be present.
func NormUserLimit(k int) int { return normUserLimit(k) }

// EffectiveUserLimit resolves a User Limit read into a struct field (absent nil
// → 1, explicit 0 → the no-limit block).
func EffectiveUserLimit(p *int) int { return effectiveUserLimit(p) }

// WgcEffectiveK is the wg-c/awg/gre block-size reading of a User Limit (0 =
// the maximum /26).
func WgcEffectiveK(p *int) int { return wgcEffectiveK(p) }

// ResolveUserLimitOverride folds an account's own device cap (lower-only) into
// the inbound's resolved K.
func ResolveUserLimitOverride(k int, override *int) int { return resolveUserLimitOverride(k, override) }

// UserLimitOverrideApplies reports whether a per-account device cap means
// anything on this inbound (gateway-model protocols answer false).
func UserLimitOverrideApplies(inbound *model.Inbound) bool { return userLimitOverrideApplies(inbound) }

// SlotOr returns the account's stored slot, falling back to its list index.
func SlotOr(slot *int, listIndex int) int { return slotOr(slot, listIndex) }

// SlotsForNewAccounts returns the lowest free slots for n new accounts.
func SlotsForNewAccounts(existing []SlotClient, n int) []int { return slotsForNewAccounts(existing, n) }

// AssignSlotsToClientMaps stamps pool slots onto raw client maps that lack one.
func AssignSlotsToClientMaps(protocol model.Protocol, existing []SlotClient, clients []any) {
	assignSlotsToClientMaps(protocol, existing, clients)
}

// HighestSlot returns the largest slot held, or -1 for none.
func HighestSlot(clients []SlotClient) int { return highestSlot(clients) }

// SlotPoolProtocol reports whether a protocol's accounts draw pool addresses.
func SlotPoolProtocol(p model.Protocol) bool { return slotPoolProtocol(p) }

// ProtocolBase returns the second octet of a protocol's /16.
func ProtocolBase(proto string) int { return protocolBase(proto) }

// NextFreeSubnet returns the lowest free "10.{base}.{n}" /24, "" when exhausted.
func NextFreeSubnet(proto string, usedSets ...map[string]bool) string {
	return nextFreeSubnet(proto, usedSets...)
}

// DefaultRange is the default host window (.2-.254) of a /24 prefix.
func DefaultRange(subnet string) string { return defaultRange(subnet) }

// OvpnRangeForSubnet is DefaultRange under its OpenVPN name (kept as a separate
// export because callers in the openvpn wave read it that way).
func OvpnRangeForSubnet(subnet string) string { return ovpnRangeForSubnet(subnet) }

// MirrorOvpnSubnet swaps an OpenVPN UDP /24 (10.2.x) with its TCP mirror (10.3.x).
func MirrorOvpnSubnet(sub string) string { return mirrorOvpnSubnet(sub) }

// InboundRanges returns the /24 ranges an inbound currently owns.
func InboundRanges(ib *model.Inbound) []string { return inboundRanges(ib) }

// UsedVpnSubnets returns the /24 prefixes owned by every VPN inbound except
// excludeId (OpenVPN includes its TCP mirror).
func UsedVpnSubnets(excludeId int) map[string]bool { return usedVpnSubnets(excludeId) }

// SubnetsOf returns the distinct /24 prefixes covered by ranges.
func SubnetsOf(ranges []string) []string { return subnetsOf(ranges) }

// RangeCapacity returns usable host addresses across ranges.
func RangeCapacity(ranges []string) int { return rangeCapacity(ranges) }

// VpnBlock returns the (network, prefix) of the aligned block covering ranges in
// the 10.{base} /16.
func VpnBlock(ranges []string, base, fallbackId int) (net.IP, int) {
	return vpnBlock(ranges, base, fallbackId)
}

// OvpnBlock is VpnBlock specialised to the OpenVPN transport bases.
func OvpnBlock(udpRanges []string, proto string, fallbackId int) (net.IP, int) {
	return ovpnBlock(udpRanges, proto, fallbackId)
}

// OvpnBlockClientIP returns the tunnel IP for client index i inside an OpenVPN block.
func OvpnBlockClientIP(netAddr net.IP, prefix, i int) string {
	return ovpnBlockClientIP(netAddr, prefix, i)
}

// AccountsPerSubnet is how many K-sized account blocks fit in one /24.
func AccountsPerSubnet(k int) int { return accountsPerSubnet(k) }

// VpnAccountsCapacity is how many K-account blocks the given /24 prefixes hold.
func VpnAccountsCapacity(subnets []string, k int) int { return vpnAccountsCapacity(subnets, k) }

// MaxVpnAccounts is the upper bound of per-account tunnel IPs after expansion.
func MaxVpnAccounts(inbound *model.Inbound) (int, bool) { return maxVpnAccounts(inbound) }

// VpnAccountBlock maps account index i to its (/24 prefix, first-host octet).
func VpnAccountBlock(subnets []string, i, k int) (string, int, bool) {
	return vpnAccountBlock(subnets, i, k)
}

// VpnAccountDeviceIPs returns the K tunnel IPs of account i's block.
func VpnAccountDeviceIPs(subnets []string, i, k int) []string {
	return vpnAccountDeviceIPs(subnets, i, k)
}

// VpnAccountDeviceIP returns one device's tunnel IP within account i's block.
func VpnAccountDeviceIP(subnets []string, i, k, d int) string {
	return vpnAccountDeviceIP(subnets, i, k, d)
}

// AccountKeyOf is the identity normalization (lower, trimmed) the slot lookups
// use, exposed so callers key their maps identically.
func AccountKeyOf(email string) string { return accountKey(email) }

// ParseRange parses one "A.B.C.s-A.B.C.e" range (also the last-octet shorthand).
func ParseRange(s string) (start, end net.IP, ok bool) { return parseRange(s) }

// CanonRange returns the canonical "A.B.C.s-A.B.C.e" form of a valid range.
func CanonRange(s string) (string, bool) { return canonRange(s) }

// RangeSubnet returns the "A.B.C" /24 prefix of a range.
func RangeSubnet(s string) string { return rangeSubnet(s) }

// DecodeRanges returns the explicit ranges from a settings map.
func DecodeRanges(raw map[string]json.RawMessage) []string { return decodeRanges(raw) }
