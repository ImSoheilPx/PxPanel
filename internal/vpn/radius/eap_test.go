package radius

// Ported from vpn-ui web/service/radius_eap_test.go — the parts that need no
// database. RT1 (Identity -> Access-Challenge) and RT2 (MSCHAPv2 Response ->
// Access-Challenge with the MSCHAPv2 Success) run here against an injected
// lookupFn (the same seam idea as ocActiveFn), so the EAP framing, state-token
// correlation and Message-Authenticator signing are verified on any host.
// RT3 (the Access-Accept with Framed-IP/MS-MPPE) drives getClientIP, which reads
// the panel database — that half lives in eap_db_test.go, gated behind cgo.

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2759"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

// capRW captures the response packet handleAuth writes, so a test can assert on it
// without opening a real UDP socket.
type capRW struct{ resp *radius.Packet }

func (c *capRW) Write(p *radius.Packet) error { c.resp = p; return nil }

// getRadiusAttr returns the first attribute of the given type as raw bytes.
func getRadiusAttr(p *radius.Packet, typ radius.Type) []byte {
	for _, avp := range p.Attributes {
		if avp.Type == typ {
			return radius.Bytes(avp.Attribute)
		}
	}
	return nil
}

// assertEAPMsgAuth verifies the Message-Authenticator on a response the way a NAS
// would: HMAC-MD5(secret, packet-with-msgauth-zeroed). strongSwan drops replies that
// lack a valid one, so this is the load-bearing check for the EAP path.
func assertEAPMsgAuth(t *testing.T, p *radius.Packet, secret string) {
	t.Helper()
	got := getRadiusAttr(p, rfc2869.MessageAuthenticator_Type)
	if len(got) != 16 {
		t.Fatalf("response carries no Message-Authenticator (strongSwan would drop it)")
	}
	_ = rfc2869.MessageAuthenticator_Set(p, make([]byte, 16))
	raw, _ := p.MarshalBinary()
	mac := hmac.New(md5.New, []byte(secret))
	mac.Write(raw)
	want := mac.Sum(nil)
	_ = rfc2869.MessageAuthenticator_Set(p, got) // restore
	if !hmac.Equal(got, want) {
		t.Fatalf("Message-Authenticator mismatch: got %x want %x", got, want)
	}
}

func codeOrNil(p *radius.Packet) any {
	if p == nil {
		return "nil"
	}
	return p.Code
}

// newEAPService returns a RadiusService wired for database-free EAP testing:
// the credential comes from lookupFn, and every DB-touching path stays out of
// the exercised rounds.
func newEAPService(secret string) *RadiusService {
	return &RadiusService{
		sessions:    map[string]*radiusSession{},
		pending:     map[string]time.Time{},
		stationIP:   map[string]string{},
		stationSeen: map[string]time.Time{},
		secret:      []byte(secret),
		lookupFn: func(protocol string, inboundId int, username string) (string, error) {
			if protocol == "ikev2" && username == "ikuser" {
				return "ikpass", nil
			}
			return "", fmt.Errorf("client %s not found in inbound %d", username, inboundId)
		},
	}
}

// TestHandleAuthEAPMSCHAPv2Rounds drives the first two rounds of the 3-round
// EAP-MSCHAPv2 exchange strongSwan's eap-radius plugin proxies for an IKEv2 login:
// Identity -> Access-Challenge (MSCHAPv2 Challenge), then a valid MSCHAPv2 Response
// -> Access-Challenge (MSCHAPv2 Success). Framing/offset bugs in the state machine
// are caught in seconds, with no VM/charon/client and no database.
func TestHandleAuthEAPMSCHAPv2Rounds(t *testing.T) {
	const secret = "testsecret"
	const user, pass = "ikuser", "ikpass"
	s := newEAPService(secret)
	nasID := "ikev2-7"

	newReq := func(eap, state []byte) *radius.Request {
		pkt := radius.New(radius.CodeAccessRequest, []byte(secret))
		rfc2865.UserName_SetString(pkt, user)
		rfc2865.NASIdentifier_SetString(pkt, nasID)
		rfc2865.CallingStationID_SetString(pkt, "203.0.113.77")
		if state != nil {
			_ = rfc2865.State_Set(pkt, state)
		}
		_ = rfc2869.EAPMessage_Set(pkt, eap)
		return &radius.Request{Packet: pkt}
	}

	// --- RT1: EAP-Response/Identity -> Access-Challenge (MSCHAPv2 Challenge) ---
	w1 := &capRW{}
	s.handleAuth(w1, newReq(buildEAPPacket(eapCodeResponse, 1, eapTypeIdentity, []byte(user)), nil))
	if w1.resp == nil {
		t.Fatal("RT1: no response")
	}
	if w1.resp.Code != radius.CodeAccessChallenge {
		t.Fatalf("RT1: got %v, want Access-Challenge", w1.resp.Code)
	}
	chalEAP := getEAPMessage(w1.resp)
	if len(chalEAP) < 26 || chalEAP[0] != eapCodeRequest || chalEAP[4] != eapTypeMSCHAPv2 || chalEAP[5] != mschapOpChallenge {
		t.Fatalf("RT1: bad Challenge EAP: %x", chalEAP)
	}
	authChallenge := chalEAP[10:26]
	chapID := chalEAP[6]
	state1 := rfc2865.State_Get(w1.resp)
	if len(state1) == 0 {
		t.Fatal("RT1: Challenge carries no State")
	}
	assertEAPMsgAuth(t, w1.resp, secret)
	// The exchange must be tracked by its State token.
	if s.eapGet(state1) == nil {
		t.Fatal("RT1: no in-flight eapState recorded for the issued State")
	}

	// --- client computes its NT-response over the server challenge ---
	peerChallenge := bytes.Repeat([]byte{0xAB}, 16)
	ntResp, err := rfc2759.GenerateNTResponse(authChallenge, peerChallenge, []byte(user), []byte(pass))
	if err != nil {
		t.Fatalf("client GenerateNTResponse: %v", err)
	}

	// --- RT2: EAP-Response/MSCHAPv2 (Response) -> Access-Challenge (Success) ---
	respVal := make([]byte, 0, 50)
	respVal = append(respVal, 49)                 // Value-Size
	respVal = append(respVal, peerChallenge...)   // Peer-Challenge (16)
	respVal = append(respVal, make([]byte, 8)...) // Reserved (8)
	respVal = append(respVal, ntResp...)          // NT-Response (24)
	respVal = append(respVal, 0)                  // Flags
	respVal = append(respVal, []byte(user)...)    // Name
	respMS := make([]byte, 4+len(respVal))
	respMS[0] = mschapOpResponse
	respMS[1] = chapID
	binary.BigEndian.PutUint16(respMS[2:4], uint16(4+len(respVal)))
	copy(respMS[4:], respVal)

	w2 := &capRW{}
	s.handleAuth(w2, newReq(buildEAPPacket(eapCodeResponse, 2, eapTypeMSCHAPv2, respMS), state1))
	if w2.resp == nil || w2.resp.Code != radius.CodeAccessChallenge {
		t.Fatalf("RT2: got %v, want Access-Challenge(Success) — server rejected a VALID NT-response (framing bug?)", codeOrNil(w2.resp))
	}
	succEAP := getEAPMessage(w2.resp)
	if len(succEAP) < 6 || succEAP[5] != mschapOpSuccess {
		t.Fatalf("RT2: expected MSCHAPv2 Success, got %x", succEAP)
	}
	state2 := rfc2865.State_Get(w2.resp)
	if string(state2) != string(state1) {
		t.Fatalf("RT2: State token changed mid-exchange (%x -> %x)", state1, state2)
	}
	assertEAPMsgAuth(t, w2.resp, secret)

	// --- RT2-bad: a WRONG NT-response must be rejected (state discarded) ---
	badVal := append([]byte(nil), respVal...)
	badVal[26] ^= 0xFF // corrupt one NT-response byte
	badMS := make([]byte, 4+len(badVal))
	badMS[0] = mschapOpResponse
	badMS[1] = chapID
	binary.BigEndian.PutUint16(badMS[2:4], uint16(4+len(badVal)))
	copy(badMS[4:], badVal)
	// Restart the exchange (the verify above left it in-flight; RT2 does not consume it).
	w1b := &capRW{}
	s.handleAuth(w1b, newReq(buildEAPPacket(eapCodeResponse, 1, eapTypeIdentity, []byte(user)), nil))
	state1b := rfc2865.State_Get(w1b.resp)
	wBad := &capRW{}
	s.handleAuth(wBad, newReq(buildEAPPacket(eapCodeResponse, 2, eapTypeMSCHAPv2, badMS), state1b))
	if wBad.resp == nil || wBad.resp.Code != radius.CodeAccessReject {
		t.Fatalf("RT2-bad: got %v, want Access-Reject for a wrong NT-response", codeOrNil(wBad.resp))
	}
	if s.eapGet(state1b) != nil {
		t.Fatal("RT2-bad: failed exchange left its eapState in flight")
	}
}
