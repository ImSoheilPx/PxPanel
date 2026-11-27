package main

// Hermetic checks for the control-socket protocol (main_ctlserver.go server
// half, main_vpncli.go client half): command dispatch shapes and the one-JSON-
// line framing both sides speak. No sockets on disk, no host probing, no root.

import (
	"bufio"
	"net"
	"strings"
	"testing"

	"github.com/ImSoheilPx/pxpanel/internal/config"
)

func TestHandleControlCommandPing(t *testing.T) {
	resp := handleControlCommand("ping")
	if !resp.OK {
		t.Fatalf("ping: want OK, got error %q", resp.Error)
	}
	if !strings.Contains(resp.Msg, config.GetPanelVersion()) {
		t.Fatalf("ping: want the version in the reply, got %q", resp.Msg)
	}
	if !strings.Contains(resp.Msg, "pid") {
		t.Fatalf("ping: want the pid in the reply, got %q", resp.Msg)
	}
}

func TestHandleControlCommandUnknownAndEmpty(t *testing.T) {
	resp := handleControlCommand("no.such.command")
	if resp.OK {
		t.Fatal("unknown command: want an error")
	}
	if !strings.Contains(resp.Error, "known:") {
		t.Fatalf("unknown command: want the known set in the error, got %q", resp.Error)
	}
	for _, known := range ctlControlCommands {
		if !strings.Contains(resp.Error, known) {
			t.Fatalf("unknown command: error %q does not list known command %q", resp.Error, known)
		}
	}

	if resp := handleControlCommand(""); resp.OK || !strings.Contains(resp.Error, "empty command") {
		t.Fatalf("empty command: want the empty-command error, got ok=%v error=%q", resp.OK, resp.Error)
	}
}

// fakePanelReply is the panel side of a net.Pipe ctl conversation: read the one
// JSON-line request, then write one reply line. net.Pipe is synchronous — a
// Write blocks until the peer Reads — so a fake panel that writes without first
// reading deadlocks against ctlSend's own request Write, which is exactly the
// hang the first draft of these tests shipped (10m test timeout in CI).
func fakePanelReply(t *testing.T, conn net.Conn, reply string) {
	t.Helper()
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Errorf("fake panel: read request: %v", err)
		return
	}
	if _, err := conn.Write([]byte(reply)); err != nil {
		t.Errorf("fake panel: write reply: %v", err)
	}
	_ = conn.Close()
}

func TestCtlSendFraming(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go fakePanelReply(t, server, "{\"ok\":true,\"msg\":\"pong\"}\n")

	resp, err := ctlSend(client, "ping")
	if err != nil {
		t.Fatalf("ctlSend: %v", err)
	}
	if !resp.OK || resp.Msg != "pong" {
		t.Fatalf("ctlSend: want ok=true msg=pong, got ok=%v msg=%q", resp.OK, resp.Msg)
	}
}

func TestCtlSendMalformedReply(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go fakePanelReply(t, server, "not json at all\n")

	_, err := ctlSend(client, "ping")
	if err == nil || !strings.Contains(err.Error(), "malformed reply") {
		t.Fatalf("ctlSend: want a malformed-reply error, got %v", err)
	}
}

func TestCtlPingDeadSocket(t *testing.T) {
	// A path nothing serves: ctlPing must report false, not hang.
	orig := ctlSocketPathOverride(t, t.TempDir()+"/nothing-here.sock")
	defer orig()
	if ctlPing() {
		t.Fatal("ctlPing: want false on a dead socket path")
	}
}

// ctlSocketPathOverride points ctlSocketPath at path for the duration of the
// test and returns a restore func.
func ctlSocketPathOverride(t *testing.T, path string) func() {
	t.Helper()
	orig := socketPathOverride
	socketPathOverride = path
	return func() { socketPathOverride = orig }
}
