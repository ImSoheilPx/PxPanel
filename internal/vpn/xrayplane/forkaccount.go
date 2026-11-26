// fork-account encoding, ported verbatim from vpn-ui xray/api.go (the fork
// half of AddUser). Import rewrite only: mhsanaei/3x-ui/v2 -> ImSoheilPx/pxpanel,
// logger -> internal/vpn/log.
package xrayplane

import (
	"context"
	"fmt"
	"time"

	"github.com/ImSoheilPx/pxpanel/internal/vpn/log"
	"github.com/ImSoheilPx/pxpanel/internal/xray"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
)

// Proto FULL NAMES of the account messages carried by anytls/tuic/naive. These are the
// type URLs the running core resolves through serial.GetInstance, so they must match the
// `package` + `message` of the core's own .proto byte for byte. See forkAccount.
const (
	anytlsAccountType = "xray.proxy.anytls.Account"
	tuicAccountType   = "xray.proxy.tuic.Account"
	naiveAccountType  = "xray.proxy.naive.Account"
)

// Field numbers in xray.proxy.naive.Account. Named because they are the one part of
// this encoder that fails SILENTLY when it drifts (a renumbered field lands in
// unknownFields and the account authenticates with an empty value), and naming them
// lets TestNaiveAccountFieldNumbersMatchTheCore read the core's generated tags and
// compare, rather than a human having to notice.
const (
	naiveAccountPasswordField = 1
	naiveAccountUsernameField = 2
)

type protoStringField struct {
	number int
	value  string
}

// forkAccount builds the same *serial.TypedMessage that serial.ToTypedMessage would,
// for an account message the panel cannot import.
//
// anytls/tuic/naive live only in the PATCHED core (third_party/Xray-core), which the
// panel does not link: go.mod pins the published github.com/xtls/xray-core and the fork
// is compiled separately into the embedded xray binary. So there is no
// proxy/anytls.Account type to hand to serial.ToTypedMessage the way vmess/trojan do,
// and the message has to be encoded here.
//
// That is safe because a TypedMessage is only a type URL plus the message's proto3
// bytes, and all three of these accounts are strings and nothing else. Neither half
// fails to compile if the core moves, so it is worth knowing how each one breaks:
//
//   - A renamed proto package is LOUD. AddUserOperation.ApplyInbound calls
//     User.ToMemoryUser, which resolves the type URL through the proto registry and
//     returns "failed to parse user" for a name it does not know, so AlterInbound
//     surfaces a gRPC error.
//   - A RENUMBERED field is silent. proto.Unmarshal files an unrecognised field number
//     under unknownFields and leaves the credential at its zero value, so the account
//     is accepted with an empty password and simply never authenticates.
//
// Change these in lockstep with the core's .proto.
func forkAccount(messageType string, fields ...protoStringField) *serial.TypedMessage {
	var value []byte
	for _, f := range fields {
		value = appendProtoStringField(value, f.number, f.value)
	}
	return &serial.TypedMessage{Type: messageType, Value: value}
}

// appendProtoStringField appends one proto3 string field: a varint tag of
// (number<<3 | 2 /* length-delimited */), a varint byte count, then the bytes. An empty
// value is skipped, which is exactly what protoc-gen-go emits for a proto3 scalar
// sitting at its zero value.
func appendProtoStringField(buf []byte, number int, value string) []byte {
	if value == "" {
		return buf
	}
	buf = appendProtoVarint(buf, uint64(number)<<3|2)
	buf = appendProtoVarint(buf, uint64(len(value)))
	return append(buf, value...)
}

func appendProtoVarint(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}

func getRequiredUserString(user map[string]any, key string) (string, error) {
	value, ok := user[key]
	if !ok || value == nil {
		return "", fmt.Errorf("missing required user field %q", key)
	}

	strValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("invalid type for user field %q: %T", key, value)
	}

	return strValue, nil
}

func getOptionalUserString(user map[string]any, key string) (string, error) {
	value, ok := user[key]
	if !ok || value == nil {
		return "", nil
	}

	strValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("invalid type for user field %q: %T", key, value)
	}

	return strValue, nil
}

// AddUser adds a client to a LIVE inbound, fork protocols included. It is the
// vpn-side entry point over internal/xray's (*XrayAPI).AddUser: the target's
// buildUserAccount covers the Xray-native protocols (vmess/vless/trojan/ss/
// hysteria/masque/wireguard) and returns nil for anytls/tuic/naive, whose account
// messages exist only in the patched core binary — so those three are encoded here
// (forkAccount) and submitted with the same AlterInbound RPC. Everything else is
// delegated unchanged, so the two entry points can never disagree about a native
// protocol's account shape.
//
// vpn-ui carried this switch inside XrayAPI.AddUser; it lives outside here only
// because internal/xray is the shared 3x-ui-lineage package and this wave does not
// edit it.
func AddUser(api *xray.XrayAPI, Protocol string, inboundTag string, user map[string]any) error {
	if api == nil {
		return fmt.Errorf("xray api is not connected")
	}

	userEmail, err := getRequiredUserString(user, "email")
	if err != nil {
		return err
	}

	var account *serial.TypedMessage
	switch Protocol {
	case "anytls":
		password, err := getRequiredUserString(user, "password")
		if err != nil {
			return err
		}

		account = forkAccount(anytlsAccountType, protoStringField{1, password})
	case "tuic":
		userID, err := getRequiredUserString(user, "id")
		if err != nil {
			return err
		}

		password, err := getRequiredUserString(user, "password")
		if err != nil {
			return err
		}

		account = forkAccount(tuicAccountType,
			protoStringField{1, userID},
			protoStringField{2, password},
		)
	case "naive":
		password, err := getRequiredUserString(user, "password")
		if err != nil {
			return err
		}

		// Optional, and the empty case is not a degenerate one: the core falls back to
		// protocol.User.Email, which is what every account created before naive had a
		// username field authenticates with. appendProtoStringField skips an empty
		// value, so the wire bytes for such an account are byte-identical to what this
		// emitted before the field existed.
		username, err := getOptionalUserString(user, "username")
		if err != nil {
			return err
		}

		account = forkAccount(naiveAccountType,
			protoStringField{naiveAccountPasswordField, password},
			protoStringField{naiveAccountUsernameField, username},
		)
	default:
		// Xray-native protocol: the target's own builder knows it (and no-ops on
		// one it does not, exactly as vpn-ui's switch did).
		return api.AddUser(Protocol, inboundTag, user)
	}

	// Nil-safe on purpose, mirroring the vpn-ui guard: Init is allowed to fail (core
	// not running, API port 0) and dereferencing a nil client here would panic on the
	// request goroutine and take the whole panel with it.
	if api.HandlerServiceClient == nil {
		return fmt.Errorf("xray api is not connected")
	}
	client := *api.HandlerServiceClient

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.AlterInbound(ctx, &command.AlterInboundRequest{
		Tag: inboundTag,
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Email:   userEmail,
				Account: account,
			},
		}),
	})
	if err != nil {
		log.Debug("Failed to add fork account:", err)
	}
	return err
}

// compile-time pin that the command/protocol imports stay the ones the running
// core speaks (a drift here is a runtime AlterInbound failure, not a build break).
var (
	_ = command.AddUserOperation{}
	_ = protocol.User{}
)
