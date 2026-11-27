package ssh

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// Hostname preservation through the socks handshake: the SSH relay's routing
// contract. A direct-tcpip channel whose client sent a HOSTNAME must reach
// Xray's socks inbound as ATYP=domain — that is the only way a domain-based
// routing rule (route *.example through the WARP outbound) can match SSH
// traffic, because Xray sees the connection as a plain socks CONNECT and has
// nothing else to sniff (SSH on port 22 is not TLS/HTTP). A server that
// resolved the name locally (CONNECT with a raw IP) would silently strip every
// domain rule's ability to match SSH traffic, while IP rules kept working —
// exactly the "routing rules apply only to vless/vmess" report.
//
// The mock below captures the CONNECT request bytes instead of dialling, so
// the assertion is on what the client actually put on the wire.

// socksRequest is the captured CONNECT request (VER CMD RSV ATYP ADDR PORT).
type socksRequest struct {
	atyp byte
	addr []byte // raw ADDR bytes, ATYP-decoded length
	port int
}

// startCaptureSocks serves one RFC1928/1929 handshake, records the request,
// replies success (with a bound address), and then holds the connection open
// until the closer runs. It never dials an upstream.
func startCaptureSocks(t *testing.T, wantUser string, captured chan<- socksRequest) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				if !mockSocksAuth(c, br, wantUser) {
					return
				}
				head := make([]byte, 4)
				if _, err := io.ReadFull(br, head); err != nil {
					return
				}
				req := socksRequest{atyp: head[3]}
				switch head[3] {
				case 0x01:
					req.addr = make([]byte, 4)
				case 0x04:
					req.addr = make([]byte, 16)
				case 0x03:
					l := make([]byte, 1)
					if _, err := io.ReadFull(br, l); err != nil {
						return
					}
					req.addr = make([]byte, int(l[0]))
				default:
					return
				}
				if _, err := io.ReadFull(br, req.addr); err != nil {
					return
				}
				pb := make([]byte, 2)
				if _, err := io.ReadFull(br, pb); err != nil {
					return
				}
				req.port = int(binary.BigEndian.Uint16(pb))
				captured <- req
				// Success reply, then hold the connection so the client's
				// post-reply flow (none needed here) cannot error out.
				c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
				buf := make([]byte, 64)
				for {
					if _, err := br.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return portOf(t, ln.Addr().String()), func() { ln.Close() }
}

func captureRequest(t *testing.T, captured chan socksRequest) socksRequest {
	t.Helper()
	select {
	case req := <-captured:
		return req
	case <-time.After(3 * time.Second):
		t.Fatal("socks server never received a CONNECT request")
		return socksRequest{}
	}
}

// A hostname destination rides ATYP=domain with the exact name bytes.
func TestDialSocksConnectPreservesHostname(t *testing.T) {
	captured := make(chan socksRequest, 1)
	port, closeSocks := startCaptureSocks(t, "alice@x", captured)
	defer closeSocks()

	conn, err := dialSocksConnect(port, "alice@x", "exit-node.example.com", 22)
	if err != nil {
		t.Fatalf("dialSocksConnect: %v", err)
	}
	defer conn.Close()

	req := captureRequest(t, captured)
	if req.atyp != 0x03 {
		t.Fatalf("ATYP = %#02x, want 0x03 (domain): the hostname was not carried through the handshake", req.atyp)
	}
	if string(req.addr) != "exit-node.example.com" {
		t.Errorf("ADDR = %q, want the hostname byte-for-byte", req.addr)
	}
	if req.port != 22 {
		t.Errorf("port = %d, want 22", req.port)
	}
}

// A literal IPv4 destination rides ATYP=IPv4 — IP-based routing rules keep
// matching clients that resolve locally.
func TestDialSocksConnectPreservesIPv4(t *testing.T) {
	captured := make(chan socksRequest, 1)
	port, closeSocks := startCaptureSocks(t, "alice@x", captured)
	defer closeSocks()

	conn, err := dialSocksConnect(port, "alice@x", "203.0.113.7", 22)
	if err != nil {
		t.Fatalf("dialSocksConnect: %v", err)
	}
	defer conn.Close()

	req := captureRequest(t, captured)
	if req.atyp != 0x01 {
		t.Fatalf("ATYP = %#02x, want 0x01 (IPv4)", req.atyp)
	}
	if net.IP(req.addr).String() != "203.0.113.7" {
		t.Errorf("ADDR = %v, want 203.0.113.7", req.addr)
	}
}

// A literal IPv6 destination rides ATYP=IPv6.
func TestDialSocksConnectPreservesIPv6(t *testing.T) {
	captured := make(chan socksRequest, 1)
	port, closeSocks := startCaptureSocks(t, "alice@x", captured)
	defer closeSocks()

	conn, err := dialSocksConnect(port, "alice@x", "2001:db8::7", 22)
	if err != nil {
		t.Fatalf("dialSocksConnect: %v", err)
	}
	defer conn.Close()

	req := captureRequest(t, captured)
	if req.atyp != 0x04 {
		t.Fatalf("ATYP = %#02x, want 0x04 (IPv6)", req.atyp)
	}
	if net.IP(req.addr).String() != "2001:db8::7" {
		t.Errorf("ADDR = %v, want 2001:db8::7", req.addr)
	}
}

// The UDP encoder (the udpgw bridge's path) shares the encoder: today udpgw
// feeds it raw IPs (the badvpn wire format carries no names), but the encoder
// itself must not silently resolve or mangle a non-IP host either.
func TestSocksEncodeUDPHostname(t *testing.T) {
	pkt := socksEncodeUDP("exit-node.example.com", 53, []byte("payload"))
	if len(pkt) < 4+1+len("exit-node.example.com")+2+len("payload") {
		t.Fatalf("packet too short: %d bytes", len(pkt))
	}
	if pkt[3] != 0x03 {
		t.Fatalf("ATYP = %#02x, want 0x03 (domain)", pkt[3])
	}
	n := int(pkt[4])
	if string(pkt[5:5+n]) != "exit-node.example.com" {
		t.Errorf("ADDR = %q, want the hostname", pkt[5:5+n])
	}
	port := int(binary.BigEndian.Uint16(pkt[5+n : 7+n]))
	if port != 53 {
		t.Errorf("port = %d, want 53", port)
	}
	if string(pkt[7+n:]) != "payload" {
		t.Errorf("payload = %q, want %q", pkt[7+n:], "payload")
	}
}

// The full relay chain's first half: a direct-tcpip channel-open payload
// carrying a hostname parses to a destHost that IS the hostname (nothing in
// the parse resolves or normalizes it), which is what dialSocksConnect then
// encodes as ATYP=domain.
func TestParseDirectTCPIPPreservesHostname(t *testing.T) {
	payload := make([]byte, 0, 4+len("exit-node.example.com")+4+4+9+4)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len("exit-node.example.com")))
	payload = append(payload, "exit-node.example.com"...)
	payload = binary.BigEndian.AppendUint32(payload, 22)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len("10.0.0.2")))
	payload = append(payload, "10.0.0.2"...)
	payload = binary.BigEndian.AppendUint32(payload, 51555)

	d, ok := parseDirectTCPIP(payload)
	if !ok {
		t.Fatal("parseDirectTCPIP failed on a well-formed payload")
	}
	if d.destHost != "exit-node.example.com" {
		t.Errorf("destHost = %q, want the hostname carried through untouched", d.destHost)
	}
	if d.destPort != 22 {
		t.Errorf("destPort = %d, want 22", d.destPort)
	}
	if d.origHost != "10.0.0.2" || d.origPort != 51555 {
		t.Errorf("orig = %s:%d, want 10.0.0.2:51555", d.origHost, d.origPort)
	}
}
