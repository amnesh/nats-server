package authverify

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/nats-io/jwt/v2"
)

// Authentication verification callout: when enabled via
// `authorization { auth_verification: true }`, every JWT-based CLIENT/LEAF
// connection (except in-process and system-account connections) is verified by a
// service in the system account after the server has verified its nkey signature
// and JWT chain. The service may reject the connection or narrow its claims; it
// can never escalate them (see package server/authverify). The transport subject
// and timeout are fixed; only the on/off switch is configurable.
const (
	// AuthVerificationSubject is the system-account subject the server publishes
	// verification requests on; the verification service subscribes to it.
	AuthVerificationSubject = "$SYS.REQ.USER.VERIFY"
	// AuthVerificationTimeout bounds the wait for a response. On expiry the
	// connection is rejected (fail-closed).
	AuthVerificationTimeout = 2 * time.Second
)

// AuthVerifyRequest is the plain-JSON request published in the system account. It
// carries the verified user's identity, the bound account, and all submitted
// credentials plus connection and TLS information. It is not a signed JWT: it is
// published only inside the trusted system account.
type AuthVerifyRequest struct {
	Server   jwt.ServerID          `json:"server"`
	Nonce    string                `json:"request_nonce"`
	UserNkey string                `json:"user_nkey"`
	Account  string                `json:"account"`
	Client   jwt.ClientInformation `json:"client_info"`
	Connect  jwt.ConnectOptions    `json:"connect_opts"`
	TLS      *jwt.ClientTLS        `json:"client_tls,omitempty"`
}

// AuthVerifyResponse is the plain-JSON verdict from the verification service.
// Reject denies the connection; otherwise the connection is admitted, optionally
// with a narrowing override (Permissions and/or a sooner Expires). Any override is
// applied narrowing-only and can never escalate the verified claims.
type AuthVerifyResponse struct {
	Nonce       string           `json:"request_nonce,omitempty"`
	Reject      bool             `json:"reject,omitempty"`
	Reason      string           `json:"reason,omitempty"`
	Permissions *jwt.Permissions `json:"permissions,omitempty"`
	Expires     int64            `json:"expires,omitempty"`
}

// ParseAuthVerifyResponse parses a verification service response. Internal account
// messages carry a trailing CRLF, which is stripped before decoding.
func ParseAuthVerifyResponse(msg []byte) (*AuthVerifyResponse, error) {
	msg = bytes.TrimRight(msg, "\r\n")
	if len(msg) == 0 {
		return nil, errors.New("empty response")
	}
	var resp AuthVerifyResponse
	if err := json.Unmarshal(msg, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
