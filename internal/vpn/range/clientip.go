package vpnrange

import (
	"fmt"
	"net"
)

// The two allocators below lived in vpn-ui web/service/radius.go (they reached
// back into the service package for parseRange/subnetsOf/protocolBase). They
// are consolidated here — next to the block math they sit on — so the whole
// address plan is one importable package and the former duplicate
// internal/vpn/vpnrange (which carried them exported) could be deleted.

// ComputeVpnClientIP computes the deterministic IP for the L2TP/PPTP-style client at
// the given index by walking the inbound's ranges in order: the client lives in
// the range whose cumulative capacity first exceeds the index. Returns nil only
// when the index exceeds the total capacity of every range (the normalizer keeps
// capacity ahead of the client count so this should not happen in practice).
func ComputeVpnClientIP(ranges []string, inboundId, clientIndex int, protocol string) net.IP {
	if len(ranges) == 0 {
		ranges = []string{DefaultRange(fmt.Sprintf("10.%d.%d", ProtocolBase(protocol), inboundId))}
	}

	remaining := clientIndex
	for _, r := range ranges {
		start, end, ok := ParseRange(r)
		if !ok {
			continue
		}
		capacity := int(end[3]) - int(start[3]) + 1
		if remaining < capacity {
			ip := make(net.IP, 4)
			copy(ip, start)
			ip[3] += byte(remaining)
			return ip
		}
		remaining -= capacity
	}
	return nil
}

// PppSubnetsOrDefault returns the ordered /24 prefixes ("A.B.C") an L2TP/PPTP-style
// inbound owns, falling back to the legacy id-derived /24 when none are stored.
func PppSubnetsOrDefault(ranges []string, proto string, id int) []string {
	if subs := SubnetsOf(ranges); len(subs) > 0 {
		return subs
	}
	return []string{fmt.Sprintf("10.%d.%d", ProtocolBase(proto), id)}
}
