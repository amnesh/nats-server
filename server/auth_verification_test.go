// Copyright 2026 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server/authverify"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// Auth verification applies only to JWT-based CLIENT and LEAF connections that are
// not in-process and not bound to the system account.
func TestAuthVerifyInScope(t *testing.T) {
	tests := []struct {
		name          string
		kind          int
		iproc         bool
		systemAccount bool
		hasJWT        bool
		want          bool
	}{
		{"jwt client", CLIENT, false, false, true, true},
		{"jwt leaf", LEAF, false, false, true, true},
		{"router excluded", ROUTER, false, false, true, false},
		{"gateway excluded", GATEWAY, false, false, true, false},
		{"in-process excluded", CLIENT, true, false, true, false},
		{"system-account excluded", CLIENT, false, true, true, false},
		{"non-jwt excluded", CLIENT, false, false, false, false},
		{"in-process leaf excluded", LEAF, true, false, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := AuthVerifyInScope(tc.kind, tc.iproc, tc.systemAccount, tc.hasJWT); got != tc.want {
				t.Fatalf("authVerifyInScope(kind=%d, iproc=%v, sys=%v, jwt=%v) = %v, want %v",
					tc.kind, tc.iproc, tc.systemAccount, tc.hasJWT, got, tc.want)
			}
		})
	}
}

func TestAuthVerifyConfigEnabled(t *testing.T) {
	conf := createConfFile(t, []byte(`
		authorization {
		  auth_verification: true
		}`))
	opts, err := ProcessConfigFile(conf)
	if err != nil {
		t.Fatalf("error reading config: %v", err)
	}
	if !opts.AuthVerification {
		t.Fatal("expected auth verification to be enabled")
	}
}

func TestAuthVerifyConfigDefaultDisabled(t *testing.T) {
	conf := createConfFile(t, []byte(`
		authorization {
		  user: "a"
		  password: "b"
		}`))
	opts, err := ProcessConfigFile(conf)
	if err != nil {
		t.Fatalf("error reading config: %v", err)
	}
	if opts.AuthVerification {
		t.Fatal("expected auth verification to be disabled by default")
	}
}

// runAuthVerifyOperatorServer starts an operator-mode server with a system
// account, a TEST account, and auth verification enabled. It returns the server
// and the system + TEST account keypairs.
func runAuthVerifyOperatorServer(t *testing.T, modify ...func(*jwt.AccountClaims)) (*Server, nkeys.KeyPair, nkeys.KeyPair) {
	t.Helper()
	skp, spub := createKey(t)
	sysClaim := jwt.NewAccountClaims(spub)
	sysClaim.Name = "$SYS"
	sysJwt, err := sysClaim.Encode(oKp)
	require_NoError(t, err)

	tkp, tpub := createKey(t)
	accClaim := jwt.NewAccountClaims(tpub)
	accClaim.Name = "TEST"
	for _, m := range modify {
		m(accClaim)
	}
	accJwt, err := accClaim.Encode(oKp)
	require_NoError(t, err)

	conf := createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:-1
		operator: %s
		system_account: %s
		resolver: MEM
		resolver_preload: {
			%s: %s
			%s: %s
		}
		authorization { auth_verification: true }
	`, ojwt, spub, spub, sysJwt, tpub, accJwt)))
	s, _ := RunServerWithConfig(conf)
	return s, skp, tkp
}

// A verification service in the system account that branches on the connecting
// user's token: "reject" denies, "narrow" tightens publish to allowed.>, "deny"
// only adds a publish deny on allowed.blocked, anything else admits unchanged.
func startAuthVerifyResponder(t *testing.T, s *Server, skp nkeys.KeyPair) *nats.Conn {
	t.Helper()
	rc, err := nats.Connect(s.ClientURL(), createUserCreds(t, s, skp))
	require_NoError(t, err)
	_, err = rc.Subscribe(authverify.AuthVerificationSubject, func(m *nats.Msg) {
		var req authverify.AuthVerifyRequest
		if err := json.Unmarshal(m.Data, &req); err != nil {
			return
		}
		resp := authverify.AuthVerifyResponse{Nonce: req.Nonce}
		switch req.Connect.Token {
		case "reject":
			resp.Reject = true
			resp.Reason = "denied by test"
		case "narrow":
			resp.Permissions = &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"allowed.>"}}}
		case "deny":
			resp.Permissions = &jwt.Permissions{Pub: jwt.Permission{Deny: jwt.StringList{"allowed.blocked"}}}
		}
		b, _ := json.Marshal(resp)
		m.Respond(b)
	})
	require_NoError(t, err)
	require_NoError(t, rc.Flush())
	return rc
}

func TestAuthVerifyOperatorAdmit(t *testing.T) {
	s, skp, tkp := runAuthVerifyOperatorServer(t)
	defer s.Shutdown()
	rc := startAuthVerifyResponder(t, s, skp)
	defer rc.Close()

	nc, err := nats.Connect(s.ClientURL(), createUserCreds(t, s, tkp), nats.Token("ok"))
	require_NoError(t, err)
	nc.Close()
}

func TestAuthVerifyOperatorReject(t *testing.T) {
	s, skp, tkp := runAuthVerifyOperatorServer(t)
	defer s.Shutdown()
	rc := startAuthVerifyResponder(t, s, skp)
	defer rc.Close()

	nc, err := nats.Connect(s.ClientURL(), createUserCreds(t, s, tkp), nats.Token("reject"))
	if err == nil {
		nc.Close()
		t.Fatal("expected connection to be rejected by the verification service")
	}
}

func TestAuthVerifyOperatorNarrow(t *testing.T) {
	s, skp, tkp := runAuthVerifyOperatorServer(t)
	defer s.Shutdown()
	rc := startAuthVerifyResponder(t, s, skp)
	defer rc.Close()

	errCh := make(chan error, 4)
	nc, err := nats.Connect(s.ClientURL(), createUserCreds(t, s, tkp), nats.Token("narrow"),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) { errCh <- e }))
	require_NoError(t, err)
	defer nc.Close()

	// Allowed by the narrowed permission.
	require_NoError(t, nc.Publish("allowed.foo", nil))
	require_NoError(t, nc.Flush())

	// Denied by the narrowed permission -> permissions violation.
	require_NoError(t, nc.Publish("denied.foo", nil))
	nc.Flush()
	select {
	case e := <-errCh:
		if !strings.Contains(strings.ToLower(e.Error()), "permission") {
			t.Fatalf("expected a permissions violation, got %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected a permissions violation error after narrowing")
	}
}

// A user JWT without permissions gets the account default permissions. A
// narrowing override must start from those defaults, not from allow-all: a
// deny-only override must not drop the account's publish restriction.
func TestAuthVerifyOverrideKeepsAccountDefaultPermissions(t *testing.T) {
	s, skp, tkp := runAuthVerifyOperatorServer(t, func(ac *jwt.AccountClaims) {
		ac.DefaultPermissions.Pub.Allow.Add("allowed.>")
	})
	defer s.Shutdown()
	rc := startAuthVerifyResponder(t, s, skp)
	defer rc.Close()

	errCh := make(chan error, 4)
	nc, err := nats.Connect(s.ClientURL(), createUserCreds(t, s, tkp), nats.Token("deny"),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) { errCh <- e }))
	require_NoError(t, err)
	defer nc.Close()

	expectDenied := func(subj string) {
		t.Helper()
		require_NoError(t, nc.Publish(subj, nil))
		nc.Flush()
		select {
		case e := <-errCh:
			if !strings.Contains(strings.ToLower(e.Error()), "permission") {
				t.Fatalf("expected a permissions violation on %q, got %v", subj, e)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("expected a permissions violation on %q", subj)
		}
	}
	// Outside the account default: still denied.
	expectDenied("other.foo")
	// Denied by the override.
	expectDenied("allowed.blocked")
	// Allowed by the account default and not denied by the override.
	require_NoError(t, nc.Publish("allowed.ok", nil))
	require_NoError(t, nc.Flush())
	select {
	case e := <-errCh:
		t.Fatalf("unexpected error on allowed.ok: %v", e)
	case <-time.After(250 * time.Millisecond):
	}
}

// A reload re-authenticates existing clients (reloadAuthorization -> per-client
// isClientAuthorized). Verification must reuse the verdict cached at admission and
// re-apply the narrowing locally, with no second network round-trip: a reload
// re-registers from the raw JWT (dropping the narrowing) and a slow/absent
// verifier would otherwise fail closed and disconnect an already-admitted client.
// Here the verifier is stopped before the re-auth to prove no round-trip happens.
func TestAuthVerifyReloadReusesCachedVerdict(t *testing.T) {
	s, skp, tkp := runAuthVerifyOperatorServer(t)
	defer s.Shutdown()
	rc := startAuthVerifyResponder(t, s, skp)

	errCh := make(chan error, 8)
	nc, err := nats.Connect(s.ClientURL(), createUserCreds(t, s, tkp), nats.Token("narrow"),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) { errCh <- e }))
	require_NoError(t, err)
	defer nc.Close()
	require_NoError(t, nc.Flush())

	// Locate the server-side client for this (non system-account) connection.
	var c *client
	checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
		sys := s.SystemAccount()
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, cl := range s.clients {
			cl.mu.Lock()
			acc, kind := cl.acc, cl.kind
			cl.mu.Unlock()
			if kind == CLIENT && acc != nil && acc != sys {
				c = cl
				return nil
			}
		}
		return fmt.Errorf("client not registered yet")
	})

	// Stop the verification service. A re-auth that did another round-trip would
	// now fail closed.
	rc.Close()

	// Re-authenticate exactly as a config reload would.
	if ok := s.isClientAuthorized(c); !ok {
		t.Fatal("re-auth should reuse the cached verdict and admit without the verifier")
	}

	// Narrowing must still be in force after the re-auth.
	require_NoError(t, nc.Publish("allowed.foo", nil))
	require_NoError(t, nc.Flush())
	require_NoError(t, nc.Publish("denied.foo", nil))
	nc.Flush()
	select {
	case e := <-errCh:
		if !strings.Contains(strings.ToLower(e.Error()), "permission") {
			t.Fatalf("expected a permissions violation, got %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected a permissions violation after reload (narrowing preserved)")
	}
}

func TestAuthVerifyOperatorFailClosedOnTimeout(t *testing.T) {
	s, _, tkp := runAuthVerifyOperatorServer(t)
	defer s.Shutdown()
	// No responder subscribed -> fail closed after the verification timeout.
	nc, err := nats.Connect(s.ClientURL(), createUserCreds(t, s, tkp), nats.Token("ok"),
		nats.Timeout(5*time.Second))
	if err == nil {
		nc.Close()
		t.Fatal("expected connection to fail closed when no verification service responds")
	}
}

// The static callout can classify a rejection with the same codes as grant
// mode. The connection gets the wire text and close state of the code, and
// both $SYS auth error events carry the exact reason. An absent, unknown, or
// malformed code is a denial. A code without reject does not reject.
func TestAuthVerifyCalloutRejectCodes(t *testing.T) {
	s, skp, tkp := runAuthVerifyOperatorServer(t)
	defer s.Shutdown()
	rc, err := nats.Connect(s.ClientURL(), createUserCreds(t, s, skp))
	require_NoError(t, err)
	defer rc.Close()
	// The client token selects the raw response fields after the nonce.
	_, err = rc.Subscribe(authverify.AuthVerificationSubject, func(m *nats.Msg) {
		var req authverify.AuthVerifyRequest
		if err := json.Unmarshal(m.Data, &req); err != nil {
			return
		}
		m.Respond([]byte(fmt.Sprintf(`{"request_nonce":%q,%s}`, req.Nonce, req.Connect.Token)))
	})
	require_NoError(t, err)
	serverEvents, err := rc.SubscribeSync(fmt.Sprintf(authErrorEventSubj, s.ID()))
	require_NoError(t, err)
	require_NoError(t, rc.Flush())
	// The account event goes to the account of the connection, not to $SYS.
	ac, err := nats.Connect(s.ClientURL(), createUserCreds(t, s, tkp), nats.Token(`"reject":false`))
	require_NoError(t, err)
	defer ac.Close()
	accountEvents, err := ac.SubscribeSync(authErrorAccountEventSubj)
	require_NoError(t, err)
	require_NoError(t, ac.Flush())

	for _, test := range []struct {
		name     string
		response string
		wire     string
		reason   ClosedState
	}{
		{"absent", `"reject":true`, "-ERR 'Authorization Violation'\r\n", AuthenticationViolation},
		{"denied", `"reject":true,"code":0`, "-ERR 'Authorization Violation'\r\n", AuthenticationViolation},
		{"resource limit", `"reject":true,"code":1`, "-ERR 'maximum connections exceeded'\r\n", ResourceLimit},
		{"retry", `"reject":true,"code":2`, "-ERR 'Authorization Temporarily Unavailable'\r\n", AuthorizationUnavailable},
		{"quarantined", `"reject":true,"code":3`, "-ERR 'Account Quarantined'\r\n", AccountQuarantined},
		{"revoked", `"reject":true,"code":4`, "-ERR 'User Authentication Revoked'\r\n", Revocation},
		{"unknown", `"reject":true,"code":99`, "-ERR 'Authorization Violation'\r\n", AuthenticationViolation},
		{"negative", `"reject":true,"code":-1`, "-ERR 'Authorization Violation'\r\n", AuthenticationViolation},
		{"malformed", `"reject":true,"code":"4"`, "-ERR 'Authorization Violation'\r\n", AuthenticationViolation},
		{"admit ignores code", `"code":4`, "PONG\r\n", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", s.Addr().String(), time.Second)
			require_NoError(t, err)
			defer conn.Close()
			require_NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			reader := bufio.NewReader(conn)
			line, err := reader.ReadString('\n')
			require_NoError(t, err)
			var info Info
			require_NoError(t, json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "INFO "))), &info))
			options := nats.GetDefaultOptions()
			require_NoError(t, createUserCreds(t, s, tkp)(&options))
			token, err := options.UserJWT()
			require_NoError(t, err)
			sig, err := options.SignatureCB([]byte(info.Nonce))
			require_NoError(t, err)
			connect, err := json.Marshal(map[string]any{"jwt": token, "sig": base64.RawURLEncoding.EncodeToString(sig),
				"auth_token": test.response, "verbose": false})
			require_NoError(t, err)
			_, err = fmt.Fprintf(conn, "CONNECT %s\r\nPING\r\n", connect)
			require_NoError(t, err)
			line, err = reader.ReadString('\n')
			require_NoError(t, err)
			require_Equal(t, line, test.wire)
			if test.reason == 0 {
				return
			}
			_, err = reader.ReadByte()
			require_Equal(t, err, io.EOF)
			var events [2]DisconnectEventMsg
			for i, sub := range []*nats.Subscription{serverEvents, accountEvents} {
				msg, err := sub.NextMsg(2 * time.Second)
				require_NoError(t, err)
				require_NoError(t, json.Unmarshal(msg.Data, &events[i]))
				require_Equal(t, events[i].Reason, test.reason.String())
			}
			require_Equal(t, events[0].Client.ID, events[1].Client.ID)
			grantTransportClosedReason(t, s, events[0].Client.ID, test.reason)
		})
	}
}
