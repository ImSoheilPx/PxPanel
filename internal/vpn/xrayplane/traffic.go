// Direction-keyed traffic-stat aggregation, ported verbatim from vpn-ui
// xray/api.go (the parser delta). The target's internal/xray keeps the older
// TAG-keyed parser for its own lineage: keyed by tag alone, an inbound and an
// outbound sharing a name collapse into one record. The vpn-side sweep uses
// these.
package xrayplane

import (
	"regexp"

	"github.com/ImSoheilPx/pxpanel/internal/util/common"
	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

// TrafficStatRegex splits an Xray traffic stat name into direction, tag and link.
// Package level so the parser and its tests cannot drift apart.
var TrafficStatRegex = regexp.MustCompile(`(inbound|outbound)>>>([^>]+)>>>traffic>>>(downlink|uplink)`)

// ClientTrafficRegex splits an Xray per-user traffic stat name into email and direction.
var ClientTrafficRegex = regexp.MustCompile(`user>>>([^>]+)>>>traffic>>>(downlink|uplink)`)

// ParseTrafficStat classifies one stat name against the two stat shapes,
// returning the regex matches (4 for a tag stat, 3 for a user stat) or nil.
func ParseTrafficStat(name string) []string {
	if matches := TrafficStatRegex.FindStringSubmatch(name); len(matches) == 4 {
		return matches
	}
	if matches := ClientTrafficRegex.FindStringSubmatch(name); len(matches) == 3 {
		return matches
	}
	return nil
}

// ProcessTraffic aggregates a traffic stat into trafficMap using regex matches and value.
//
// Keyed by DIRECTION and tag, not by tag alone. Nothing stops an inbound and an
// outbound sharing a name (the panel's uniqueness check spans outbounds and
// tunnels, not inbounds), and one key for both meant the first stat the map
// iteration happened to reach decided the direction for the pair while their bytes
// were summed into a single record: an inbound's traffic then appeared in the
// outbounds table, or a tunnel's egress was billed to an inbound.
func ProcessTraffic(matches []string, value int64, trafficMap map[string]*xray.Traffic) {
	isInbound := matches[1] == "inbound"
	tag := matches[2]
	isDown := matches[3] == "downlink"

	if tag == "api" {
		return
	}

	key := matches[1] + ">>>" + tag

	traffic, ok := trafficMap[key]
	if !ok {
		traffic = &xray.Traffic{
			IsInbound:  isInbound,
			IsOutbound: !isInbound,
			Tag:        tag,
		}
		trafficMap[key] = traffic
	}

	if isDown {
		traffic.Down = value
	} else {
		traffic.Up = value
	}
}

// ProcessClientTraffic updates clientTrafficMap with upload/download values for a client email.
//
// TODO(traffic job wave): vpn-ui set CoreCounted=true on records created here —
// this stat is "user>>><email>>>>traffic" and carries no inbound, so it is
// precisely the bytes the panel has to attribute for itself. The target's
// xray.ClientTraffic has no such field (it is the 3x-ui upstream shape); the
// attribution pass belongs to the vpn traffic job, which must treat every record
// built here as core-counted until it carries the flag on its own wrapper type.
func ProcessClientTraffic(matches []string, value int64, clientTrafficMap map[string]*xray.ClientTraffic) {
	email := matches[1]
	isDown := matches[2] == "downlink"

	traffic, ok := clientTrafficMap[email]
	if !ok {
		traffic = &xray.ClientTraffic{Email: email}
		clientTrafficMap[email] = traffic
	}

	if isDown {
		traffic.Down = value
	} else {
		traffic.Up = value
	}
}

// MapToSlice converts a map of pointers to a slice of pointers.
func MapToSlice[T any](m map[string]*T) []*T {
	result := make([]*T, 0, len(m))
	for _, v := range m {
		result = append(result, v)
	}
	return result
}

// AggregateTrafficStats folds one QueryStats response page (stat name -> value)
// into per-tag and per-email records, the way vpn-ui's reset-based GetTraffic
// did. The target's internal/xray keeps its own delta-baselined fetch; this is
// the pure fold the vpn traffic job reuses over whatever fetch it drives.
// Returns (nil, nil, error) when the API handle is not initialised.
func AggregateTrafficStats(stats map[string]int64) ([]*xray.Traffic, []*xray.ClientTraffic, error) {
	if stats == nil {
		return nil, nil, common.NewError("xray api is not initialized")
	}

	tagTrafficMap := make(map[string]*xray.Traffic)
	emailTrafficMap := make(map[string]*xray.ClientTraffic)

	for name, value := range stats {
		if matches := TrafficStatRegex.FindStringSubmatch(name); len(matches) == 4 {
			ProcessTraffic(matches, value, tagTrafficMap)
		} else if matches := ClientTrafficRegex.FindStringSubmatch(name); len(matches) == 3 {
			ProcessClientTraffic(matches, value, emailTrafficMap)
		}
	}
	return MapToSlice(tagTrafficMap), MapToSlice(emailTrafficMap), nil
}
