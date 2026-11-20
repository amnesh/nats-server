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
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server/authverify"
	"github.com/nats-io/nats.go"
)

func TestAuthGrantClientAccountDisabledCodeStops(t *testing.T) {
	t.Run("connect rejection", func(t *testing.T) {
		_, nc, attempts, _, closed := grantCodeClient(t, authverify.CodeAccountDisabled, 100)
		grantRecv(t, closed)
		require_True(t, nc.IsClosed())
		require_Equal(t, nc.LastError().Error(), "nats: Authorization Violation - Account Disabled")
		grantStableCount(t, attempts, 2)
	})
	t.Run("planned disconnect", func(t *testing.T) {
		var attempts atomic.Int32
		requests := make(chan *authverify.GrantRequest, 8)
		f := newGrantFixture(t, &testGrantHook{verify: func(request *authverify.GrantRequest) *authverify.GrantVerdict {
			requests <- request
			if attempts.Add(1) > 1 {
				return &authverify.GrantVerdict{Reject: true, Code: authverify.CodeAccountDisabled}
			}
			return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
		}})
		closed := make(chan struct{}, 1)
		errs := make(chan error, 8)
		nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", 0),
			nats.DontRandomize(), nats.MaxReconnects(20), nats.ReconnectWait(10*time.Millisecond),
			nats.ReconnectJitter(0, 0), nats.ClosedHandler(func(*nats.Conn) { closed <- struct{}{} }),
			nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { errs <- err }))
		require_NoError(t, err)
		defer nc.Close()
		first := grantRecv(t, requests)
		require_NoError(t, f.s.DisconnectClient(first.Client.ID, authverify.CodeAccountDisabled))
		// nats.go classifies the text as an authorization error and stops
		// after the second equal error.
		require_Equal(t, grantRecv(t, errs), nats.ErrAuthorization)
		grantRecv(t, closed)
		require_Equal(t, nc.LastError().Error(), "nats: Authorization Violation - Account Disabled")
		grantTransportClosedReason(t, f.s, first.Client.ID, AccountDisabled)
		grantStableCount(t, &attempts, 2)
	})
}

// accountDisabledHub is a grant hub whose hook rejects every connection with
// code while disabled is set, and admits it otherwise. It keeps the time of
// each rejected attempt.
type accountDisabledHub struct {
	f        *grantFixture
	hub      *Server
	disabled atomic.Bool
	admitted chan *authverify.GrantRequest
	mu       sync.Mutex
	rejects  []time.Time
}

func newAccountDisabledHub(t *testing.T, code authverify.RejectCode) *accountDisabledHub {
	t.Helper()
	h := &accountDisabledHub{admitted: make(chan *authverify.GrantRequest, 16)}
	hook := &testGrantHook{verify: func(request *authverify.GrantRequest) *authverify.GrantVerdict {
		if h.disabled.Load() {
			h.mu.Lock()
			h.rejects = append(h.rejects, time.Now())
			h.mu.Unlock()
			return &authverify.GrantVerdict{Reject: true, Code: code}
		}
		select {
		case h.admitted <- request:
		default:
		}
		return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
	}}
	h.f = newGrantFixture(t, hook)
	h.hub = grantTransportCloneHub(t, h.f, hook, true)
	return h
}

// waitRejects waits for n rejected attempts and returns their times.
func (h *accountDisabledHub) waitRejects(t *testing.T, n int, within time.Duration) []time.Time {
	t.Helper()
	var got []time.Time
	checkFor(t, within, 10*time.Millisecond, func() error {
		h.mu.Lock()
		got = append([]time.Time(nil), h.rejects...)
		h.mu.Unlock()
		if len(got) < n {
			return fmt.Errorf("%d of %d rejected attempts", len(got), n)
		}
		return nil
	})
	return got
}

// accountDisabledLeaf runs a leaf whose remote retries every 25ms, with the
// test-only connect delay delay in place of the production delays.
func accountDisabledLeaf(t *testing.T, h *accountDisabledHub, delay time.Duration) *Server {
	t.Helper()
	u, err := url.Parse(fmt.Sprintf("nats://127.0.0.1:%d", h.hub.getOpts().LeafNode.Port))
	require_NoError(t, err)
	options := DefaultOptions()
	options.Host, options.Port = "127.0.0.1", -1
	options.LeafNode.ReconnectInterval = 25 * time.Millisecond
	options.LeafNode.connDelay = delay
	options.LeafNode.Remotes = []*RemoteLeafOpts{{URLs: []*url.URL{u}, Credentials: grantTransportCredentials(t, h.f, false), NoRandomize: true}}
	s := RunServer(options)
	t.Cleanup(s.Shutdown)
	return s
}

// A leaf remote that gets the account disabled code waits the long connect
// delay before each next attempt. It connects again, with the same JWT and no
// restart, when the hook admits the account again.
func TestAuthGrantLeafAccountDisabledWaitsAndReconnects(t *testing.T) {
	const delay = 500 * time.Millisecond
	checkGaps := func(t *testing.T, times []time.Time, min time.Duration) {
		t.Helper()
		for i := 1; i < len(times); i++ {
			if gap := times[i].Sub(times[i-1]); gap < min {
				t.Fatalf("attempt %d came %v after the previous one, expected at least %v", i, gap, min)
			}
		}
	}

	t.Run("connect rejection", func(t *testing.T) {
		h := newAccountDisabledHub(t, authverify.CodeAccountDisabled)
		h.disabled.Store(true)
		leaf := accountDisabledLeaf(t, h, delay)
		checkGaps(t, h.waitRejects(t, 3, 5*time.Second), delay)
		h.disabled.Store(false)
		grantRecv(t, h.admitted)
		checkLeafNodeConnected(t, h.hub)
		checkLeafNodeConnected(t, leaf)
	})

	t.Run("planned disconnect", func(t *testing.T) {
		h := newAccountDisabledHub(t, authverify.CodeAccountDisabled)
		leaf := accountDisabledLeaf(t, h, delay)
		first := grantRecv(t, h.admitted)
		checkLeafNodeConnected(t, h.hub)
		h.disabled.Store(true)
		closedAt := time.Now()
		require_NoError(t, h.hub.DisconnectClient(first.Client.ID, authverify.CodeAccountDisabled))
		grantTransportClosedReason(t, h.hub, first.Client.ID, AccountDisabled)
		checkGaps(t, append([]time.Time{closedAt}, h.waitRejects(t, 2, 5*time.Second)...), delay)
		h.disabled.Store(false)
		second := grantRecv(t, h.admitted)
		require_True(t, second.Client.ID != first.Client.ID)
		require_Equal(t, second.Connect.JWT, first.Connect.JWT)
		checkLeafNodeConnected(t, h.hub)
		checkLeafNodeConnected(t, leaf)
	})

	t.Run("denied control retries at the reconnect interval", func(t *testing.T) {
		h := newAccountDisabledHub(t, authverify.CodeDenied)
		h.disabled.Store(true)
		accountDisabledLeaf(t, h, delay)
		times := h.waitRejects(t, 4, 5*time.Second)
		if total := times[3].Sub(times[0]); total >= delay {
			t.Fatalf("three denied retries took %v, expected less than %v", total, delay)
		}
	})
}
