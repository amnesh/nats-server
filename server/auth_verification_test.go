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
	"encoding/json"
	"fmt"
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
