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

	"github.com/nats-io/nats-server/v2/server/authverify"
	"github.com/nats-io/nats.go"
)

// pendingConnz returns the open connection cid from Connz, or nil.
func pendingConnz(t *testing.T, s *Server, opts ConnzOptions, cid uint64) *ConnInfo {
	t.Helper()
	opts.CID, opts.Username, opts.State = cid, true, ConnOpen
	connz, err := s.Connz(&opts)
	require_NoError(t, err)
	if len(connz.Conns) == 0 {
		return nil
	}
	return connz.Conns[0]
}

// pendingConnzRequest returns the raw JSON of the open connection cid from
// $SYS.REQ.SERVER.<id>.CONNZ.
func pendingConnzRequest(t *testing.T, nc *nats.Conn, s *Server, cid uint64) string {
	t.Helper()
	req, err := json.Marshal(&ConnzEventOptions{ConnzOptions: ConnzOptions{CID: cid, Username: true}})
	require_NoError(t, err)
	msg, err := nc.Request(fmt.Sprintf(serverDirectReqSubj, s.ID(), "CONNZ"), req, 2*time.Second)
	require_NoError(t, err)
	var resp struct {
		Data struct {
			Conns []json.RawMessage `json:"connections"`
		} `json:"data"`
	}
	require_NoError(t, json.Unmarshal(msg.Data, &resp))
	if len(resp.Data.Conns) != 1 {
		t.Fatalf("system request listed %d connections for cid %d", len(resp.Data.Conns), cid)
	}
	return string(resp.Data.Conns[0])
}

func requirePendingMarker(t *testing.T, ci *ConnInfo, want bool, account string) {
	t.Helper()
	if ci == nil {
		t.Fatalf("connection not in the open list")
	}
	if ci.VerificationPending != want {
		t.Fatalf("verification pending %v, want %v", ci.VerificationPending, want)
	}
	if ci.Account != account || ci.AuthorizedUser == _EMPTY_ {
		t.Fatalf("connection lists account %q and user %q, want account %q and a user", ci.Account, ci.AuthorizedUser, account)
	}
}

// requireReauthNoMarker authenticates the open client cid again, as a config
// reload does, and checks that it has no marker.
func requireReauthNoMarker(t *testing.T, s *Server, cid uint64, account string) {
	t.Helper()
	s.mu.RLock()
	c := s.clients[cid]
	s.mu.RUnlock()
	if c == nil {
		t.Fatalf("client %d not open", cid)
	}
	if !s.isClientAuthorized(c) {
		t.Fatalf("authentication again rejected client %d", cid)
	}
	requirePendingMarker(t, pendingConnz(t, s, ConnzOptions{}, cid), false, account)
}

// A connection that waits for the verdict of the auth verification service
// is in the open list with its account and user, and with the marker. The
// marker is absent after the verdict admits it. A rejected connection leaves
// the open list.
func TestAuthVerifyConnzVerificationPending(t *testing.T) {
	s, skp, tkp := runAuthVerifyOperatorServer(t)
	defer s.Shutdown()
	rc, err := nats.Connect(s.ClientURL(), createUserCreds(t, s, skp))
	require_NoError(t, err)
	defer rc.Close()
	held := make(chan *nats.Msg, 4)
	_, err = rc.Subscribe(authverify.AuthVerificationSubject, func(m *nats.Msg) { held <- m })
	require_NoError(t, err)
	require_NoError(t, rc.Flush())

	verdict := func(t *testing.T, m *nats.Msg, reject bool) {
		t.Helper()
		var req authverify.AuthVerifyRequest
		require_NoError(t, json.Unmarshal(m.Data, &req))
		require_NoError(t, m.Respond([]byte(fmt.Sprintf(`{"request_nonce":%q,"reject":%t}`, req.Nonce, reject))))
	}
	waitHeld := func(t *testing.T) (*nats.Msg, authverify.AuthVerifyRequest) {
		t.Helper()
		select {
		case m := <-held:
			var req authverify.AuthVerifyRequest
			require_NoError(t, json.Unmarshal(m.Data, &req))
			return m, req
		case <-time.After(2 * time.Second):
			t.Fatal("no verification request")
		}
		return nil, authverify.AuthVerifyRequest{}
	}

	t.Run("admit", func(t *testing.T) {
		_, reader := grantTransportRawConnect(t, s, createUserCreds(t, s, tkp))
		m, req := waitHeld(t)
		requirePendingMarker(t, pendingConnz(t, s, ConnzOptions{}, req.Client.ID), true, req.Account)
		requirePendingMarker(t, pendingConnz(t, s, ConnzOptions{Account: req.Account}, req.Client.ID), true, req.Account)
		if raw := pendingConnzRequest(t, rc, s, req.Client.ID); !strings.Contains(raw, `"verification_pending":true`) {
			t.Fatalf("system request has no marker: %s", raw)
		}

		verdict(t, m, false)
		line, err := reader.ReadString('\n')
		require_NoError(t, err)
		require_Equal(t, line, "PONG\r\n")
		requirePendingMarker(t, pendingConnz(t, s, ConnzOptions{}, req.Client.ID), false, req.Account)
		if raw := pendingConnzRequest(t, rc, s, req.Client.ID); strings.Contains(raw, "verification_pending") {
			t.Fatalf("system request of an admitted connection has the marker: %s", raw)
		}

		// A config reload authenticates the connection again with the cached
		// verdict. The marker does not come back.
		requireReauthNoMarker(t, s, req.Client.ID, req.Account)
	})

	t.Run("reject", func(t *testing.T) {
		_, reader := grantTransportRawConnect(t, s, createUserCreds(t, s, tkp))
		m, req := waitHeld(t)
		requirePendingMarker(t, pendingConnz(t, s, ConnzOptions{}, req.Client.ID), true, req.Account)
		verdict(t, m, true)
		line, err := reader.ReadString('\n')
		require_NoError(t, err)
		require_Equal(t, line, "-ERR 'Authorization Violation'\r\n")
		checkFor(t, 2*time.Second, 10*time.Millisecond, func() error {
			if ci := pendingConnz(t, s, ConnzOptions{}, req.Client.ID); ci != nil {
				return fmt.Errorf("rejected connection %d is still open", req.Client.ID)
			}
			return nil
		})
	})
}

// The same for a client and a leaf connection that wait for the verdict of
// the grant hook. The accepting hub lists a leaf only in the account list
// before its CONNECT completes.
func TestAuthGrantConnzVerificationPending(t *testing.T) {
	type held struct {
		request *authverify.GrantRequest
		admit   chan bool
	}
	for _, kind := range []string{"client", "leaf"} {
		for _, admit := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s admit %t", kind, admit), func(t *testing.T) {
				requests := make(chan held, 4)
				done := make(chan struct{})
				reject := &authverify.GrantVerdict{Reject: true, Code: authverify.CodeAccountDisabled}
				hook := &testGrantHook{verify: func(request *authverify.GrantRequest) *authverify.GrantVerdict {
					h := held{request: request, admit: make(chan bool, 1)}
					select {
					case requests <- h:
					default:
						return reject
					}
					select {
					case ok := <-h.admit:
						if ok {
							return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
						}
					case <-done:
					}
					return reject
				}}
				f := newGrantFixture(t, hook)
				hub := grantTransportCloneHub(t, f, hook, kind == "leaf")
				// Runs before the server shutdowns, so no hook call blocks them.
				t.Cleanup(func() { close(done) })
				var leaf *Server
				if kind == "leaf" {
					leaf = grantTransportLeaf(t, grantTransportCredentials(t, f, false), hub)
				} else {
					grantTransportRawConnect(t, hub, f.creds(t, f.signer, true, "", 0))
				}
				h := grantRecv(t, requests)
				cid := h.request.Client.ID
				opts := ConnzOptions{Account: f.acc.Name}
				requirePendingMarker(t, pendingConnz(t, hub, opts, cid), true, f.acc.Name)

				h.admit <- admit
				if !admit {
					checkFor(t, 2*time.Second, 10*time.Millisecond, func() error {
						if ci := pendingConnz(t, hub, opts, cid); ci != nil {
							return fmt.Errorf("rejected connection %d is still open", cid)
						}
						return nil
					})
					return
				}
				if leaf != nil {
					checkLeafNodeConnected(t, hub)
					checkLeafNodeConnected(t, leaf)
					requirePendingMarker(t, pendingConnz(t, hub, ConnzOptions{}, cid), false, f.acc.Name)
				}
				checkFor(t, 2*time.Second, 10*time.Millisecond, func() error {
					ci := pendingConnz(t, hub, opts, cid)
					if ci == nil || ci.VerificationPending {
						return fmt.Errorf("connection %d not open without the marker: %+v", cid, ci)
					}
					return nil
				})
				if kind == "client" {
					requireReauthNoMarker(t, hub, cid, f.acc.Name)
				}
			})
		}
	}
}
