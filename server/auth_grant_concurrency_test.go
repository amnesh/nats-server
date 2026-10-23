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
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server/authverify"
	"github.com/nats-io/nats.go"
)

func TestAuthGrantConcurrentReloadUpdate(t *testing.T) {
	requests := make(chan *authverify.GrantRequest, 1)
	f := newGrantFixture(t, &testGrantHook{verify: func(r *authverify.GrantRequest) *authverify.GrantVerdict {
		requests <- r
		return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
	}})
	nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	r := grantRecv(t, requests)
	updated := make(chan error, 1)
	go func() {
		for generation := uint64(2); generation < 1002; generation++ {
			g := grantAll()
			g.Pub.Deny = []string{"denied"}
			g.Sub.Deny = []string{"denied"}
			if err := f.s.UpdateClientGrant(authverify.GrantUpdate{
				ClientID: r.Client.ID, Account: r.Account, UserNkey: r.UserNkey,
				Generation: generation, Grant: g,
			}); err != nil {
				updated <- err
				return
			}
		}
		updated <- nil
	}()
	for range 100 {
		f.s.reloadAuthorization()
	}
	require_NoError(t, grantRecv(t, updated))
	require_NoError(t, nc.FlushTimeout(time.Second))
}

func TestAuthGrantConnectDuringObsoleteExpiration(t *testing.T) {
	requests := make(chan *authverify.GrantRequest, 1)
	f := newGrantFixture(t, &testGrantHook{verify: func(r *authverify.GrantRequest) *authverify.GrantVerdict {
		requests <- r
		return &authverify.GrantVerdict{
			Generation: 1, Grant: grantAll(), Expires: time.Now().Add(time.Hour).Unix(), Done: func(bool) {},
		}
	}})
	nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	r := grantRecv(t, requests)
	c := f.s.grantClient(r.Client.ID)
	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	c.mu.Lock()
	st := c.authGrant
	st.expirationTimer.Stop()
	version := st.timerVersion
	st.expirationTimer = time.AfterFunc(0, func() {
		defer close(finished)
		close(started)
		<-release
		c.expireAuthGrant(st, version)
	})
	c.mu.Unlock()
	releaseCallback := sync.OnceFunc(func() {
		close(release)
		grantRecv(t, finished)
	})
	defer releaseCallback()
	grantRecv(t, started)

	connected := make(chan error, 1)
	go func() { connected <- c.processConnect([]byte("{")) }()
	select {
	case err := <-connected:
		if err == nil {
			t.Fatal("expected invalid CONNECT JSON to be rejected")
		}
	case <-time.After(time.Second):
		c.closeConnection(ClientClosed)
		releaseCallback()
		grantRecv(t, connected)
		t.Fatal("CONNECT waited for a grant expiration callback")
	}

	require_NoError(t, f.s.UpdateClientGrant(authverify.GrantUpdate{
		ClientID: r.Client.ID, Account: r.Account, UserNkey: r.UserNkey,
		Generation: 2, Grant: grantAll(),
	}))
	releaseCallback()
	c.mu.Lock()
	hasTimer, hasExpiry := st.expirationTimer != nil, !c.expires.IsZero()
	c.mu.Unlock()
	if hasTimer || hasExpiry {
		t.Fatalf("expiry removal retained timer=%v deadline=%v", hasTimer, hasExpiry)
	}
	require_NoError(t, nc.FlushTimeout(time.Second))
}

func TestAuthGrantCloseStopsExpirationTimer(t *testing.T) {
	requests := make(chan *authverify.GrantRequest, 1)
	closed := make(chan uint64, 2)
	f := newGrantFixture(t, &testGrantHook{verify: func(r *authverify.GrantRequest) *authverify.GrantVerdict {
		requests <- r
		return &authverify.GrantVerdict{
			Generation: 1, Grant: grantAll(), Expires: time.Now().Add(time.Hour).Unix(), Done: func(bool) {},
		}
	}, closed: func(_ string, id uint64) { closed <- id }})
	nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	r := grantRecv(t, requests)
	c := f.s.grantClient(r.Client.ID)
	c.mu.Lock()
	st, timer, version := c.authGrant, c.authGrant.expirationTimer, c.authGrant.timerVersion
	c.mu.Unlock()
	if timer == nil {
		t.Fatal("missing grant expiration timer")
	}
	c.closeConnection(ClientClosed)
	if timer.Stop() {
		t.Fatal("connection close left grant expiration timer running")
	}
	c.expireAuthGrant(st, version)
	if id := grantRecv(t, closed); id != r.Client.ID {
		t.Fatalf("wrong closed client: %d", id)
	}
	c.mu.Lock()
	hasTimer := st.expirationTimer != nil
	c.mu.Unlock()
	if hasTimer {
		t.Fatal("connection close retained grant expiration timer")
	}
}
