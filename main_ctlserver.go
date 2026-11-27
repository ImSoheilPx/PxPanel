package main

// The panel's control socket: a root-only unix socket that lets a separate CLI
// process (`pxpanel ctl <cmd>`) drive the LIVE panel's Xray and daemons.
// Ported from vpn-ui web/service/control.go (server half); the client half and
// the `ctl` verb live in main_vpncli.go.
//
// It exists because Xray and the VPN daemons are CHILD PROCESSES of the running
// panel, tracked only by in-process state: XrayService's package-level process
// and the procmgr singleton. A second process starts with neither, so a CLI
// that called those services directly would be wrong in both directions — a
// "stop" that reports not-running while Xray serves, and a "restart" that
// spawns a second, port-colliding core. So the CLI asks the live panel to act
// rather than acting itself, and the handlers call the very same seams the web
// controllers use: one code path, not two.
//
// Server-side xray restarts go through the web.Server RestartXray (the same
// entry the SIGUSR1 handler and the tunnel-health monitor use), so the
// vpnout.ReassertCarriers hook on that path runs for ctl-driven restarts too.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/config"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/coresettings"
	"github.com/ImSoheilPx/pxpanel/internal/web/service"
)

const (
	controlSocketName = "pxpanel.sock"
	// How long to wait for the stale-socket probe. Only a live panel's accept
	// loop answers, and it is local, so this is generous already.
	controlDialTimeout = 500 * time.Millisecond
	// Idle time allowed between requests on one connection, and the budget for
	// writing a reply. Neither covers command EXECUTION: cores.restart-all
	// restarts every core and takes tens of seconds, so the deadlines are
	// (re)armed around the read and the write only.
	controlIdleTimeout  = 30 * time.Second
	controlWriteTimeout = 10 * time.Second
	// Ceiling on what one CONNECTION may send, so a rogue client cannot make the
	// panel buffer unbounded input. A command is a single short JSON line and
	// the CLI sends exactly one per connection.
	controlMaxRequest = 4 << 10
)

// ctlRestarter is the restart seam the socket is wired with: the running
// server's RestartXray, so ctl-driven restarts ride the same path (and the same
// carrier-reassert hook) as the panel's own.
type ctlRestarter interface{ RestartXray() error }

// ctlXrayRestart is set once at panel start, before the servers come up.
var ctlXrayRestart ctlRestarter

// ctlControlCommands lists every command the socket accepts, in the order the
// CLI documents them. Exported to the CLI through ctlCommandList so the client
// prints the set without keeping a second copy that can drift from
// handleControlCommand.
var ctlControlCommands = []string{
	"ping",
	"xray.start",
	"xray.stop",
	"xray.restart",
	"cores.restart-all",
	"cores.status",
}

// ctlCommandList returns the documented command set for usage lines.
func ctlCommandList() string { return strings.Join(ctlControlCommands, ", ") }

// ctlControlRequest is one line of the socket protocol: a JSON object per line.
type ctlControlRequest struct {
	Cmd string `json:"cmd"`
}

// ctlControlResponse is the single JSON line sent back for each request. Error
// is empty exactly when OK is true, so a client can branch on either.
type ctlControlResponse struct {
	OK    bool                      `json:"ok"`
	Cmd   string                    `json:"cmd,omitempty"`
	Msg   string                    `json:"msg,omitempty"`
	Error string                    `json:"error,omitempty"`
	Cores []coresettings.CoreStatus `json:"cores,omitempty"`
}

// socketPathOverride, when set (tests), replaces the derived socket path so a
// test never touches the real next-to-binary location.
var socketPathOverride string

// ctlSocketPath returns the control socket's path: pxpanel.sock next to the
// panel binary.
//
// Derived from os.Executable() rather than config.GetDBFolderPath(): the panel
// calls godotenv.Load() at startup and the CLI does not, so a DB-folder
// override in a .env would move the panel's socket while the CLI kept dialing a
// path that never existed. Both are the SAME binary, so its directory is the
// one location they can never disagree on.
func ctlSocketPath() string {
	if socketPathOverride != "" {
		return socketPathOverride
	}
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return filepath.Join(config.GetDBFolderPath(), controlSocketName)
	}
	return filepath.Join(filepath.Dir(exe), controlSocketName)
}

// startControlSocket binds the control socket and serves it in a background
// goroutine. restarter is the live server's RestartXray (nil-tolerant). Callers
// must treat a failure as non-fatal and keep going: the socket only serves the
// CLI, and a panel carrying VPN traffic without it is far better than a panel
// that refused to start over it.
func startControlSocket(restarter ctlRestarter) error {
	ctlXrayRestart = restarter
	path := ctlSocketPath()

	// A socket file left behind by a panel that died without cleanup makes
	// Listen fail with EADDRINUSE, so the stale entry would block every later
	// start. Unlink it, but only after proving nothing answers on it, because a
	// successful dial means a live panel owns it and stealing its socket would
	// be worse than not having one.
	dialer := net.Dialer{Timeout: controlDialTimeout}
	if conn, derr := dialer.DialContext(context.Background(), "unix", path); derr == nil {
		_ = conn.Close()
		return fmt.Errorf("another pxpanel is already serving %s", path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale control socket %s: %w", path, err)
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("chmod control socket %s: %w", path, err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				// Accept only fails permanently here (the listener is never
				// closed while the panel runs), so log and stop rather than
				// spin on the same error.
				return
			}
			go serveControlConn(conn)
		}
	}()
	return nil
}

// serveControlConn reads request lines until the peer hangs up, answering each.
func serveControlConn(conn net.Conn) {
	defer conn.Close()

	if !controlPeerIsRoot(conn) {
		_ = conn.SetWriteDeadline(time.Now().Add(controlWriteTimeout))
		_ = writeControlResponse(conn, ctlControlResponse{Error: "permission denied: the control socket is root-only"})
		return
	}

	r := bufio.NewReader(io.LimitReader(conn, controlMaxRequest))
	for {
		// Armed per request so a client that connects and says nothing cannot
		// pin this goroutine forever, and re-armed after each reply for the
		// next one.
		_ = conn.SetReadDeadline(time.Now().Add(controlIdleTimeout))
		line, err := r.ReadString('\n')
		if strings.TrimSpace(line) == "" {
			if err != nil {
				return // EOF / timeout / hang-up: nothing left to answer
			}
			continue
		}

		var req ctlControlRequest
		var resp ctlControlResponse
		if jerr := json.Unmarshal([]byte(line), &req); jerr != nil {
			resp = ctlControlResponse{Error: fmt.Sprintf("malformed request: %v", jerr)}
		} else {
			resp = handleControlCommand(strings.TrimSpace(req.Cmd))
		}

		_ = conn.SetWriteDeadline(time.Now().Add(controlWriteTimeout))
		if werr := writeControlResponse(conn, resp); werr != nil {
			return
		}
		if err != nil {
			return
		}
	}
}

// handleControlCommand executes one command against the LIVE panel's own
// services: the same entries the web controllers and the signal handler use, so
// the CLI and the dashboard can never diverge in behaviour.
func handleControlCommand(cmd string) ctlControlResponse {
	var xrayService service.XrayService
	var coreService coresettings.CoreService // zero-value usable and stateless

	switch cmd {
	case "ping":
		return ctlControlResponse{OK: true, Cmd: cmd, Msg: fmt.Sprintf("pxpanel %s panel is running (pid %d)", config.GetPanelVersion(), os.Getpid())}

	case "xray.start":
		// Xray has no separate Start: "stopped" means no live process, and the
		// server's RestartXray is exactly what the panel itself calls to bring
		// it back (it also clears the manual-stop guard, without which the
		// health job would deliberately leave Xray down).
		if xrayService.IsXrayRunning() {
			return ctlControlResponse{OK: true, Cmd: cmd, Msg: "xray is already running"}
		}
		if err := ctlRestartXray(); err != nil {
			return ctlControlResponse{Cmd: cmd, Error: err.Error()}
		}
		return ctlControlResponse{OK: true, Cmd: cmd, Msg: "xray started"}

	case "xray.stop":
		if err := xrayService.StopXray(); err != nil {
			return ctlControlResponse{Cmd: cmd, Error: err.Error()}
		}
		return ctlControlResponse{OK: true, Cmd: cmd, Msg: "xray stopped"}

	case "xray.restart":
		if err := ctlRestartXray(); err != nil {
			return ctlControlResponse{Cmd: cmd, Error: err.Error()}
		}
		return ctlControlResponse{OK: true, Cmd: cmd, Msg: "xray restarted"}

	case "cores.restart-all":
		// RestartAll aggregates per-core errors instead of stopping at the
		// first, so a partial failure still restarted the rest. Report it as a
		// failure with the detail, never as a silent success.
		if err := coreService.RestartAll(); err != nil {
			return ctlControlResponse{Cmd: cmd, Error: err.Error()}
		}
		return ctlControlResponse{OK: true, Cmd: cmd, Msg: "all cores restarted"}

	case "cores.status":
		return ctlControlResponse{OK: true, Cmd: cmd, Cores: coreService.GetCoresStatus()}

	case "":
		return ctlControlResponse{Error: "empty command (known: " + ctlCommandList() + ")"}
	}
	return ctlControlResponse{Cmd: cmd, Error: fmt.Sprintf("unknown command %q (known: %s)", cmd, ctlCommandList())}
}

// ctlRestartXray restarts the core through the live server when the socket was
// wired with it, so the carrier-reassert hook on Server.RestartXray runs; a
// direct service call is the fallback for a socket started without one.
func ctlRestartXray() error {
	if ctlXrayRestart != nil {
		return ctlXrayRestart.RestartXray()
	}
	var xrayService service.XrayService
	return xrayService.RestartXray(true)
}

// writeControlResponse emits one JSON line. json.Encoder appends the newline
// that terminates the record.
func writeControlResponse(conn net.Conn, resp ctlControlResponse) error {
	return json.NewEncoder(conn).Encode(resp)
}

// controlPeerIsRoot reports whether the connected peer runs as root, in the
// per-OS peercred files: Linux checks SO_PEERCRED (recorded by the kernel at
// connect() time and impossible to race or spoof); elsewhere the process's own
// euid is the only available answer. The socket is already mode 0600, but the
// mode can only be applied AFTER bind, so the extra guarantee closes that
// window.
