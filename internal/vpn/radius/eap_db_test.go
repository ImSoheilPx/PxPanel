//go:build linux && cgo

package radius

// The FULL 3-round EAP-MSCHAPv2 test from vpn-ui web/service/radius_eap_test.go,
// including RT3 (Access-Accept with Framed-IP-Address + MS-MPPE keys) — which
// drives getClientIP and therefore needs the panel database (CGO sqlite; see
// internal/database). Gated to linux+cgo: dependency builds and Windows hosts
// compile the cgo-free eap_test.go rounds instead; CI runs this file.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/database"
	"github.com/ImSoheilPx/pxpanel/internal/database/model"
	"github.com/ImSoheilPx/pxpanel/internal/logger"
	"github.com/ImSoheilPx/pxpanel/internal/vpn"
	"github.com/ImSoheilPx/pxpanel/internal/vpn/defaults"

	"github.com/op/go-logging"
	"layeh.com/radius"
	"layeh.com/radius/rfc2759"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

func TestHandleAuthIKEv2EAPMSCHAPv2(t *testing.T) {
	logger.InitLogger(logging.DEBUG)
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	vpn.SetDB(database.GetDB)
	db := database.GetDB()

	settings := `{"clients":[{"id":"ikuser","password":"ikpass","email":"","enable":true}],"ipRanges":[],"userLimit":1,"userLimitStrategy":"accept"}`
	ib := &model.Inbound{Enable: true, Port: 500, Protocol: defaults.ProtoIKEv2, Settings: settings, Tag: "inbound-ikev2-500"}
	if err := db.Create(ib).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	const secret = "testsecret"
	const user, pass = "ikuser", "ikpass"
	s := &RadiusService{
		sessions:    map[string]*radiusSession{},
		pending:     map[string]time.Time{},
		stationIP:   map[string]string{},
		stationSeen: map[string]time.Time{},
		secret:      []byte(secret),
	}
	nasID := fmt.Sprintf("ikev2-%d", ib.Id)

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
	assertEAPMsgAuth(t, w2.resp, secret)

	// --- RT3: EAP-Response/MSCHAPv2 (Success ack) -> Access-Accept ---
	ackMS := []byte{mschapOpSuccess, chapID, 0, 4}
	w3 := &capRW{}
	s.handleAuth(w3, newReq(buildEAPPacket(eapCodeResponse, 3, eapTypeMSCHAPv2, ackMS), state2))
	if w3.resp == nil || w3.resp.Code != radius.CodeAccessAccept {
		t.Fatalf("RT3: got %v, want Access-Accept", codeOrNil(w3.resp))
	}
	if rfc2865.FramedIPAddress_Get(w3.resp) == nil {
		t.Fatal("RT3: Access-Accept has no Framed-IP-Address (strongSwan pools=radius needs it)")
	}
	finalEAP := getEAPMessage(w3.resp)
	if len(finalEAP) < 4 || finalEAP[0] != eapCodeSuccess {
		t.Fatalf("RT3: expected EAP-Success, got %x", finalEAP)
	}
	if getRadiusAttr(w3.resp, 26) == nil { // Vendor-Specific = MS-MPPE keys
		t.Fatal("RT3: Access-Accept carries no MS-MPPE keys (strongSwan needs the MSK)")
	}
	assertEAPMsgAuth(t, w3.resp, secret)
}
