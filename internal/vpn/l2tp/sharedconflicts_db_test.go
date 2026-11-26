//go:build linux && cgo

package l2tp

// The save-time shared-daemon conflict tests, from vpn-ui
// web/service/l2tp_ipsec_psk_test.go's DB half. Gated to linux+cgo: the check
// reads the panel database (CGO sqlite; see internal/database) and the
// dependency builds and Windows hosts compile the cgo-free psk_test.go renders
// instead; CI runs this file.

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/op/go-logging"

	"github.com/ImSoheilPx/pxpanel/internal/database"
	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/logger"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"
)

// The check paths log unconditionally, and logger.Debug dereferences a package
// global that is nil until InitLogger runs.
var conflictTestLoggerOnce sync.Once

// newConflictDB gives the sqlite harness the check reads through vpn.DB().
func newConflictDB(t *testing.T) {
	t.Helper()
	conflictTestLoggerOnce.Do(func() { logger.InitLogger(logging.ERROR) })
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	vpn.SetDB(database.GetDB)
}

// seedL2tpInbound stores an inbound the incoming one will be checked against.
func seedL2tpInbound(t *testing.T, id int, listen, settings string) {
	t.Helper()
	inbound := &model.Inbound{
		Id: id, UserId: 1, Tag: fmt.Sprintf("inbound-shared-%d", id), Port: 20000 + id,
		Protocol: defaults.ProtoL2TP, Enable: true, Listen: listen, Remark: fmt.Sprintf("box-%d", id),
		Settings: settings,
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound %d: %v", id, err)
	}
}

func TestL2tpPskConflictOnlyWhenTheIkeListenerIsShared(t *testing.T) {
	for _, tc := range []struct {
		name         string
		otherListen  string
		mineListen   string
		wantConflict bool
	}{
		{"both on every address", "", "", true},
		{"the stored one is on every address", "", "10.0.0.2", true},
		{"the incoming one is on every address", "10.0.0.1", "", true},
		{"both on the same address", "10.0.0.1", "10.0.0.1", true},
		{"an explicit wildcard still covers the other", "0.0.0.0", "10.0.0.2", true},
		{"each on its own address", "10.0.0.1", "10.0.0.2", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newConflictDB(t)
			seedL2tpInbound(t, 1, tc.otherListen, `{"ipsecEnable":true,"ipsecPsk":"first-key"}`)

			mine := &model.Inbound{
				Id: 2, Protocol: defaults.ProtoL2TP, Enable: true, Listen: tc.mineListen,
				Settings: `{"ipsecEnable":true,"ipsecPsk":"second-key"}`,
			}
			err := CheckSharedDaemonConflicts(mine, 0)
			if tc.wantConflict != (err != nil) {
				t.Fatalf("conflict=%v (err=%v), want conflict=%v", err != nil, err, tc.wantConflict)
			}
			if err == nil {
				return
			}
			// The message has to name the way out, or the operator's only option is to
			// copy the other inbound's key.
			for _, want := range []string{
				"IPsec pre-shared key", "#1", "box-1", "first-key", "L2TP", "Listen",
			} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal never mentions %q: %s", want, err)
				}
			}
		})
	}
}

// Distinct addresses buy a key each and nothing else: DNS and MTU are the one pppd
// options file the single xl2tpd LNS reads, which no address can split up.
func TestL2tpDnsAndMtuConflictRegardlessOfListenAddress(t *testing.T) {
	for _, tc := range []struct {
		name, other, mine, want string
	}{
		{
			"dns", `{"dns1":"1.1.1.1"}`, `{"dns1":"9.9.9.9"}`, "The primary DNS server",
		},
		{
			"mtu", `{"mtu":1400}`, `{"mtu":1300}`, "The MTU",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newConflictDB(t)
			seedL2tpInbound(t, 1, "10.0.0.1", tc.other)

			mine := &model.Inbound{
				Id: 2, Protocol: defaults.ProtoL2TP, Enable: true, Listen: "10.0.0.2", Settings: tc.mine,
			}
			err := CheckSharedDaemonConflicts(mine, 0)
			if err == nil {
				t.Fatalf("two %s values on separate addresses were accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("wrong conflict reported: %s", err)
			}
			// The generic message must name the real protocol, not a hardcoded one.
			if !strings.Contains(err.Error(), "every L2TP inbound on this server") {
				t.Errorf("the message does not name the protocol: %s", err)
			}
		})
	}
}
