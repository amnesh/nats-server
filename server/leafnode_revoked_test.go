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
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server/authverify"
	"github.com/nats-io/nkeys"
)

// The check period of the revoked-credential tests. It replaces the 30 s
// production delay through the test-only LeafNode.connDelay option.
const leafRevokedTestPeriod = 100 * time.Millisecond

// leafRevokedHub is a grant hub whose hook rejects one JWT with CodeRevoked
// and admits every other JWT. It counts authentication attempts (hook calls),
// not TCP accepts.
type leafRevokedHub struct {
	f        *grantFixture
	hub      *Server
	revoked  atomic.Pointer[string]
	attempts atomic.Int32
	requests chan *authverify.GrantRequest
}

func newLeafRevokedHub(t *testing.T) *leafRevokedHub {
	t.Helper()
	h := &leafRevokedHub{requests: make(chan *authverify.GrantRequest, 64)}
	hook := &testGrantHook{verify: func(request *authverify.GrantRequest) *authverify.GrantVerdict {
		h.attempts.Add(1)
		// Never block the hub: a failing run can make many attempts.
		select {
		case h.requests <- request:
		default:
		}
		if revoked := h.revoked.Load(); revoked != nil && request.Connect.JWT == *revoked {
			return &authverify.GrantVerdict{Reject: true, Code: authverify.CodeRevoked}
		}
		return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
	}}
	h.f = newGrantFixture(t, hook)
	h.hub = grantTransportCloneHub(t, h.f, hook, true)
	return h
}

// leafRevokedUser issues JWTs for one user key.
type leafRevokedUser struct {
	kp nkeys.KeyPair
}

func newLeafRevokedUser(t *testing.T) *leafRevokedUser {
	t.Helper()
	kp, err := nkeys.CreateUser()
	require_NoError(t, err)
	return &leafRevokedUser{kp: kp}
}

// issue returns a new scoped JWT. It first waits for a new second, because
// the encoder sets iat to the current second and derives the JWT ID from the
// claims, so two JWTs issued in the same second are equal.
func (u *leafRevokedUser) issue(t *testing.T, f *grantFixture) string {
	t.Helper()
	start := time.Now().Unix()
	for time.Now().Unix() == start {
		time.Sleep(10 * time.Millisecond)
	}
	public, err := u.kp.PublicKey()
	require_NoError(t, err)
	claims := jwt.NewUserClaims(public)
	claims.IssuerAccount = f.acc.Name
	claims.SetScoped(true)
	token, err := claims.Encode(f.signer)
	require_NoError(t, err)
	return token
}

func (u *leafRevokedUser) writeCreds(t *testing.T, path, token string) {
	t.Helper()
	seed, err := u.kp.Seed()
	require_NoError(t, err)
	data, err := jwt.FormatUserConfig(token, seed)
	require_NoError(t, err)
	require_NoError(t, os.WriteFile(path, data, 0600))
}

// leafRevokedDialer counts the TCP dials of the leaf remote. It is the
// positive control: the remote keeps dialing while it sends no CONNECT.
type leafRevokedDialer struct {
	dials atomic.Int32
}

func (d *leafRevokedDialer) Dial(network, address string) (net.Conn, error) {
	d.dials.Add(1)
	return net.DialTimeout(network, address, time.Second)
}

// leafRevokedSource is one credential source of a leaf remote.
type leafRevokedSource struct {
	name string
	// set makes token the JWT that the remote sends next.
	set func(t *testing.T, token string)
	// remote returns the remote options for the source.
	remote func(t *testing.T, urls []*url.URL) *RemoteLeafOpts
}

var leafRevokedSourceNames = []string{"credentials file", "signature callback"}

func newLeafRevokedSource(t *testing.T, user *leafRevokedUser, name string) *leafRevokedSource {
	t.Helper()
	switch name {
	case "credentials file":
		path := filepath.Join(t.TempDir(), "user.creds")
		return &leafRevokedSource{
			name: name,
			set:  func(t *testing.T, token string) { user.writeCreds(t, path, token) },
			remote: func(t *testing.T, urls []*url.URL) *RemoteLeafOpts {
				return &RemoteLeafOpts{URLs: urls, Credentials: path, NoRandomize: true}
			},
		}
	case "signature callback":
		var current atomic.Pointer[string]
		return &leafRevokedSource{
			name: name,
			set:  func(t *testing.T, token string) { current.Store(&token) },
			remote: func(t *testing.T, urls []*url.URL) *RemoteLeafOpts {
				return &RemoteLeafOpts{URLs: urls, NoRandomize: true, SignatureCB: func(nonce []byte) (string, []byte, error) {
					sig, err := user.kp.Sign(nonce)
					return *current.Load(), sig, err
				}}
			},
		}
	}
	t.Fatalf("unknown credential source %q", name)
	return nil
}

func runLeafRevokedLeaf(t *testing.T, h *leafRevokedHub, source *leafRevokedSource) (*Server, *leafRevokedDialer) {
	t.Helper()
	u, err := url.Parse(fmt.Sprintf("nats://127.0.0.1:%d", h.hub.getOpts().LeafNode.Port))
	require_NoError(t, err)
	dialer := &leafRevokedDialer{}
	options := DefaultOptions()
	options.Host, options.Port = "127.0.0.1", -1
	options.LeafNode.ReconnectInterval = 25 * time.Millisecond
	options.LeafNode.connDelay = leafRevokedTestPeriod
	options.LeafNode.CustomDialer = dialer
	options.LeafNode.Remotes = []*RemoteLeafOpts{source.remote(t, []*url.URL{u})}
	leaf := RunServer(options)
	t.Cleanup(leaf.Shutdown)
	return leaf, dialer
}

// leafRevokedRequireNoConnect checks over three check periods that the hub
// gets no further authentication attempt while the remote keeps dialing.
func leafRevokedRequireNoConnect(t *testing.T, h *leafRevokedHub, dialer *leafRevokedDialer, attempts int32) {
	t.Helper()
	dials := dialer.dials.Load()
	time.Sleep(3*leafRevokedTestPeriod + 200*time.Millisecond)
	require_Equal(t, h.attempts.Load(), attempts)
	if got := dialer.dials.Load(); got < dials+2 {
		t.Fatalf("leaf remote dialed %d times in three check periods, want at least 2", got-dials)
	}
	checkLeafNodeConnectedCount(t, h.hub, 0)
}

// revokeLeaf brings the remote to the blocked state and returns the hub
// attempt count. With atConnect, the hub rejects the first CONNECT. Otherwise
// the hub admits the leaf and then closes it with CodeRevoked.
func revokeLeaf(t *testing.T, h *leafRevokedHub, source *leafRevokedSource, token string, atConnect bool) (*Server, *leafRevokedDialer) {
	t.Helper()
	if atConnect {
		h.revoked.Store(&token)
	}
	source.set(t, token)
	leaf, dialer := runLeafRevokedLeaf(t, h, source)
	first := grantRecv(t, h.requests)
	require_Equal(t, first.Connect.JWT, token)
	if atConnect {
		grantTransportClosedReason(t, h.hub, first.Client.ID, Revocation)
	} else {
		checkLeafNodeConnected(t, h.hub)
		checkLeafNodeConnected(t, leaf)
		h.revoked.Store(&token)
		require_NoError(t, h.hub.DisconnectClient(first.Client.ID, authverify.CodeRevoked))
		grantTransportClosedReason(t, h.hub, first.Client.ID, Revocation)
	}
	leafRevokedRequireNoConnect(t, h, dialer, 1)
	return leaf, dialer
}

func TestLeafRemoteRevokedCredentialNoRedial(t *testing.T) {
	for _, atConnect := range []bool{true, false} {
		moment := "planned disconnect"
		if atConnect {
			moment = "connect rejection"
		}
		for _, name := range leafRevokedSourceNames {
			t.Run(name+" "+moment, func(t *testing.T) {
				h := newLeafRevokedHub(t)
				user := newLeafRevokedUser(t)
				source := newLeafRevokedSource(t, user, name)
				revokeLeaf(t, h, source, user.issue(t, h.f), atConnect)
			})
		}
	}
}

func TestLeafRemoteRevokedCredentialRedialsAfterReissue(t *testing.T) {
	for _, atConnect := range []bool{true, false} {
		moment := "planned disconnect"
		if atConnect {
			moment = "connect rejection"
		}
		for _, name := range leafRevokedSourceNames {
			t.Run(name+" "+moment, func(t *testing.T) {
				h := newLeafRevokedHub(t)
				user := newLeafRevokedUser(t)
				source := newLeafRevokedSource(t, user, name)
				revokedToken := user.issue(t, h.f)
				leaf, _ := revokeLeaf(t, h, source, revokedToken, atConnect)
				reissued := user.issue(t, h.f)
				require_True(t, reissued != revokedToken)
				source.set(t, reissued)
				second := grantRecv(t, h.requests)
				require_Equal(t, second.Connect.JWT, reissued)
				checkLeafNodeConnected(t, h.hub)
				checkLeafNodeConnected(t, leaf)
				require_Equal(t, h.attempts.Load(), int32(2))
				revokedClaims, err := jwt.DecodeUserClaims(revokedToken)
				require_NoError(t, err)
				require_Equal(t, second.UserNkey, revokedClaims.Subject)
			})
		}
	}
}
