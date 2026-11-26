package rbridge

import (
	"testing"
	"time"
)

// Ported verbatim from vpn-ui web/service/rbridge/rbridge_test.go.

func TestTrimToLimit(t *testing.T) {
	now := time.Now()
	sessions := []Live{
		{Email: "a@x", IP: "10.6.0.2", Since: now.Add(3 * time.Second)},
		{Email: "a@x", IP: "10.6.0.3", Since: now.Add(1 * time.Second)},
		{Email: "a@x", IP: "10.6.0.4", Since: now.Add(2 * time.Second)},
	}

	// reject keeps the OLDEST k.
	surv, ev := TrimToLimit(sessions, 2, "reject")
	if len(surv) != 2 || len(ev) != 1 {
		t.Fatalf("reject: got %d survivors %d evicted, want 2/1", len(surv), len(ev))
	}
	if ev[0].IP != "10.6.0.2" { // newest evicted
		t.Fatalf("reject: evicted %s, want the newest (10.6.0.2)", ev[0].IP)
	}

	// accept keeps the NEWEST k.
	surv, ev = TrimToLimit(sessions, 2, "accept")
	if len(surv) != 2 || len(ev) != 1 {
		t.Fatalf("accept: got %d survivors %d evicted, want 2/1", len(surv), len(ev))
	}
	if ev[0].IP != "10.6.0.3" { // oldest evicted
		t.Fatalf("accept: evicted %s, want the oldest (10.6.0.3)", ev[0].IP)
	}

	// k <= 0 = no limit.
	surv, ev = TrimToLimit(sessions, 0, "reject")
	if len(surv) != 3 || ev != nil {
		t.Fatalf("no limit: got %d survivors %d evicted", len(surv), len(ev))
	}

	// input must not be modified
	if sessions[0].IP != "10.6.0.2" || sessions[1].IP != "10.6.0.3" {
		t.Fatal("input slice was reordered")
	}
}

type fakeAdapter struct {
	proto    string
	live     []Live
	evicted  []string
	limits   map[int]int
	strategy string
}

func (f *fakeAdapter) Protocol() string { return f.proto }
func (f *fakeAdapter) Poll() ([]Live, error) {
	return f.live, nil
}
func (f *fakeAdapter) Limit(inboundID int) (int, string) {
	if f.strategy == "" {
		f.strategy = "reject"
	}
	return f.limits[inboundID], f.strategy
}
func (f *fakeAdapter) Evict(l Live) error {
	f.evicted = append(f.evicted, l.IP)
	return nil
}

type fakeSink struct {
	reconciled map[string]map[string]Reconciled
}

func (f *fakeSink) ReconcileLocalSessions(proto string, desired map[string]Reconciled) {
	if f.reconciled == nil {
		f.reconciled = map[string]map[string]Reconciled{}
	}
	f.reconciled[proto] = desired
}
func (f *fakeSink) DisabledEmails() map[string]bool {
	return map[string]bool{"dead@x": true}
}

func TestSweeperTick(t *testing.T) {
	now := time.Now()
	ad := &fakeAdapter{
		proto: "ikev2",
		live: []Live{
			{Email: "dead@x", IP: "10.6.0.9", InboundID: 1, Since: now},
			{Email: "a@x", IP: "10.6.0.2", InboundID: 1, Since: now.Add(3 * time.Second)},
			{Email: "a@x", IP: "10.6.0.3", InboundID: 1, Since: now.Add(1 * time.Second)},
		},
		limits: map[int]int{1: 1},
	}
	sink := &fakeSink{}
	sw := New(sink)
	sw.Register(ad)
	sw.Tick()

	// disabled account evicted
	if len(ad.evicted) != 2 {
		t.Fatalf("evicted %v, want the disabled account and the over-limit device", ad.evicted)
	}
	got := sink.reconciled["ikev2"]
	if len(got) != 1 {
		t.Fatalf("reconciled %d survivors, want 1", len(got))
	}
	if r, ok := got["10.6.0.3"]; !ok || r.Email != "a@x" {
		t.Fatalf("survivor wrong: %v", got)
	}
}
