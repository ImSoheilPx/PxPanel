// Traffic aggregation tests, ported from vpn-ui xray/api_traffic_test.go.
package xrayplane

import (
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/xray"
)

// The stat name is the ONLY thing that says which direction a counter belongs to.
// Everything downstream (addInboundTraffic, addOutboundTraffic, the outbounds table's
// Traffic column) keys off the flags set here, so a name parsed into the wrong bucket
// bills one tag's bytes to another.

func collect(names map[string]int64) map[string]*xray.Traffic {
	out := map[string]*xray.Traffic{}
	for name, value := range names {
		matches := TrafficStatRegex.FindStringSubmatch(name)
		if len(matches) != 4 {
			continue
		}
		ProcessTraffic(matches, value, out)
	}
	return out
}

func TestProcessTrafficSplitsInboundFromOutbound(t *testing.T) {
	got := collect(map[string]int64{
		"outbound>>>vpn-l2tp>>>traffic>>>uplink":   10,
		"outbound>>>vpn-l2tp>>>traffic>>>downlink": 100,
		"inbound>>>inbound-443>>>traffic>>>uplink": 7,
	})

	out, ok := got["outbound>>>vpn-l2tp"]
	if !ok {
		t.Fatalf("the vpn outbound produced no record at all: %v", got)
	}
	if !out.IsOutbound || out.IsInbound {
		t.Errorf("vpn-l2tp is inbound=%v outbound=%v, want outbound", out.IsInbound, out.IsOutbound)
	}
	if out.Tag != "vpn-l2tp" {
		t.Errorf("tag = %q, want vpn-l2tp; the outbounds table matches the row on this", out.Tag)
	}
	if out.Up != 10 || out.Down != 100 {
		t.Errorf("up/down = %d/%d, want 10/100", out.Up, out.Down)
	}
	if in := got["inbound>>>inbound-443"]; in == nil || !in.IsInbound {
		t.Errorf("the inbound record was lost or mislabelled: %v", got["inbound>>>inbound-443"])
	}
}

// An inbound and an outbound may carry the same tag: the panel's uniqueness check
// covers outbounds and tunnels only, and nothing stops an operator naming a tunnel
// after an inbound. Keyed by tag alone, the first stat seen decided the direction for
// both and their bytes were summed into one record, so an inbound's traffic showed up
// in the outbounds table (or a tunnel's egress was billed to an inbound). Map
// iteration order made which one non-deterministic.
func TestProcessTrafficKeepsCollidingTagsApart(t *testing.T) {
	got := collect(map[string]int64{
		"inbound>>>shared>>>traffic>>>uplink":    1000,
		"inbound>>>shared>>>traffic>>>downlink":  2000,
		"outbound>>>shared>>>traffic>>>uplink":   3,
		"outbound>>>shared>>>traffic>>>downlink": 4,
	})

	in, out := got["inbound>>>shared"], got["outbound>>>shared"]
	if in == nil || out == nil {
		t.Fatalf("one direction swallowed the other: %v", got)
	}
	if !in.IsInbound || in.IsOutbound || in.Up != 1000 || in.Down != 2000 {
		t.Errorf("inbound record = %+v, want inbound 1000/2000", in)
	}
	if !out.IsOutbound || out.IsInbound || out.Up != 3 || out.Down != 4 {
		t.Errorf("outbound record = %+v, want outbound 3/4", out)
	}
}

// The api inbound is the panel's own gRPC channel. Counting it would put the panel's
// polling in the operator's traffic figures.
func TestProcessTrafficDropsTheApiTag(t *testing.T) {
	if got := collect(map[string]int64{"inbound>>>api>>>traffic>>>uplink": 5}); len(got) != 0 {
		t.Errorf("the api tag was counted: %v", got)
	}
}

// User stats land per email regardless of arrival order, and both directions of one
// email fold into the same record.
func TestProcessClientTrafficFoldsByEmail(t *testing.T) {
	m := map[string]*xray.ClientTraffic{}
	ProcessClientTraffic([]string{"", "a@x", "downlink"}, 30, m)
	ProcessClientTraffic([]string{"", "a@x", "uplink"}, 3, m)
	ProcessClientTraffic([]string{"", "b@x", "downlink"}, 7, m)

	a := m["a@x"]
	if a == nil || a.Up != 3 || a.Down != 30 {
		t.Errorf("a@x = %+v, want up 3 / down 30", a)
	}
	if b := m["b@x"]; b == nil || b.Down != 7 {
		t.Errorf("b@x = %+v, want down 7", b)
	}
}

// The aggregate fold classifies both stat shapes and skips everything else.
func TestAggregateTrafficStats(t *testing.T) {
	traffic, clients, err := AggregateTrafficStats(map[string]int64{
		"inbound>>>inbound-443>>>traffic>>>downlink": 1,
		"outbound>>>vpn-gre>>>traffic>>>uplink":      2,
		"user>>>a@x>>>traffic>>>uplink":              3,
		"some>>>other>>>stat":                        99,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(traffic) != 2 {
		t.Errorf("traffic records = %d, want 2", len(traffic))
	}
	if len(clients) != 1 || clients[0].Email != "a@x" || clients[0].Up != 3 {
		t.Errorf("client records = %+v, want one a@x with up 3", clients)
	}
	if _, _, err := AggregateTrafficStats(nil); err == nil {
		t.Error("nil stats returned no error; the job wave needs the not-initialised signal")
	}
}
