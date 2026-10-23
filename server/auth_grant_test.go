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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server/authverify"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

type testGrantHook struct {
	verify func(*authverify.GrantRequest) *authverify.GrantVerdict
	closed func(string, uint64)
}

func (h *testGrantHook) Verify(r *authverify.GrantRequest) *authverify.GrantVerdict {
	return h.verify(r)
}
func (h *testGrantHook) Closed(s string, id uint64) {
	if h.closed != nil {
		h.closed(s, id)
	}
}

func authGrantJWTBlock(t *testing.T, token string, signer nkeys.KeyPair, block string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	require_NoError(t, err)
	var root map[string]json.RawMessage
	require_NoError(t, json.Unmarshal(data, &root))
	var natsFields map[string]json.RawMessage
	require_NoError(t, json.Unmarshal(root["nats"], &natsFields))
	natsFields["authverify"] = json.RawMessage(block)
	root["nats"] = mustMarshalJSON(t, natsFields)
	payload := parts[0] + "." + base64.RawURLEncoding.EncodeToString(mustMarshalJSON(t, root))
	sig, err := signer.Sign([]byte(payload))
	require_NoError(t, err)
	return payload + "." + base64.RawURLEncoding.EncodeToString(sig)
}

type grantFixture struct {
	s               *Server
	acc             *Account
	account, signer nkeys.KeyPair
	claims          *jwt.AccountClaims
	scope           *jwt.UserScope
}

func newGrantFixture(t *testing.T, hook authverify.GrantHook, modify ...func(*jwt.AccountClaims, *jwt.UserScope)) *grantFixture {
	t.Helper()
	ak, ap := createKey(t)
	sk, sp := createKey(t)
	ac := jwt.NewAccountClaims(ap)
	scope := jwt.NewUserScope()
	scope.Key = sp
	scope.Role = "device"
	scope.Template.Pub.Deny.Add(">")
	scope.Template.Sub.Deny.Add(">")
	ac.SigningKeys.AddScopedSigner(scope)
	for _, f := range modify {
		f(ac, scope)
	}
	raw, err := ac.Encode(oKp)
	require_NoError(t, err)
	raw = authGrantJWTBlock(t, raw, oKp, `{"mode":"grant"}`)
	conf := createConfFile(t, []byte(fmt.Sprintf(`listen: 127.0.0.1:-1
 operator: %s
 resolver: MEM
 resolver_preload: { %s: %s }
 `, ojwt, ap, raw)))
	opts, err := ProcessConfigFile(conf)
	require_NoError(t, err)
	opts.AuthGrant = hook
	opts.NoLog = true
	s := RunServer(opts)
	t.Cleanup(s.Shutdown)
	acc, err := s.LookupAccount(ap)
	require_NoError(t, err)
	return &grantFixture{s: s, acc: acc, account: ak, signer: sk, claims: ac, scope: scope}
}
func (f *grantFixture) creds(t *testing.T, signer nkeys.KeyPair, scoped bool, block string, expiry int64) nats.Option {
	t.Helper()
	uk, err := nkeys.CreateUser()
	require_NoError(t, err)
	up, err := uk.PublicKey()
	require_NoError(t, err)
	uc := jwt.NewUserClaims(up)
	uc.IssuerAccount = f.acc.Name
	uc.Expires = expiry
	if scoped {
		uc.SetScoped(true)
	} else {
		uc.Pub.Allow.Add("static")
		uc.Sub.Allow.Add("static")
	}
	raw, err := uc.Encode(signer)
	require_NoError(t, err)
	if block != "" {
		raw = authGrantJWTBlock(t, raw, signer, block)
	}
	return nats.UserJWT(func() (string, error) { return raw, nil }, func(nonce []byte) ([]byte, error) { return uk.Sign(nonce) })
}
func grantRecv[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for grant callback")
		var zero T
		return zero
	}
}
func grantAll() authverify.Grant {
	return authverify.Grant{Pub: authverify.SubjectGrant{Allow: []string{">"}}, Sub: authverify.SubjectGrant{Allow: []string{">"}}}
}

func TestAuthGrantConnectAndLiveUpdate(t *testing.T) {
	requests := make(chan *authverify.GrantRequest, 4)
	done := make(chan bool, 4)
	closed := make(chan uint64, 4)
	hook := &testGrantHook{verify: func(r *authverify.GrantRequest) *authverify.GrantVerdict {
		requests <- r
		return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(ok bool) { done <- ok }}
	}, closed: func(_ string, id uint64) { closed <- id }}
	f := newGrantFixture(t, hook)
	errs := make(chan error, 8)
	nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.NoReconnect(), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) { errs <- e }))
	require_NoError(t, err)
	defer nc.Close()
	req := grantRecv(t, requests)
	require_True(t, grantRecv(t, done))
	require_Equal(t, req.ScopeRole, "device")
	require_Equal(t, req.Account, f.acc.Name)
	_, err = nc.SubscribeSync("old")
	require_NoError(t, err)
	require_NoError(t, nc.Flush())
	require_NoError(t, nc.Publish("old", nil))
	require_NoError(t, nc.Flush())
	c := f.s.grantClient(req.Client.ID)
	c.mu.Lock()
	require_True(t, c.pubAllowedFullCheck("old", true, true))
	c.mu.Unlock()
	u := authverify.GrantUpdate{ClientID: req.Client.ID, Account: req.Account, UserNkey: req.UserNkey, Generation: 2,
		Grant: authverify.Grant{Pub: authverify.SubjectGrant{Allow: []string{"new"}}, Sub: authverify.SubjectGrant{Allow: []string{"new"}}}}
	require_NoError(t, f.s.UpdateClientGrant(u))
	require_Contains(t, grantRecv(t, errs).Error(), "Permissions Violation")
	c.mu.Lock()
	require_False(t, c.pubAllowedFullCheck("old", true, true))
	require_True(t, c.pubAllowedFullCheck("new", true, true))
	require_Len(t, len(c.subs), 0)
	c.mu.Unlock()
	sub, err := nc.SubscribeSync("new")
	require_NoError(t, err)
	require_NoError(t, nc.Flush())
	require_NoError(t, nc.Publish("new", []byte("live")))
	_, err = sub.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, f.s.UpdateClientGrant(u), ErrStaleGeneration)
	u.Generation++
	u.UserNkey = "wrong"
	require_Equal(t, f.s.UpdateClientGrant(u), ErrUnknownClient)
	u.UserNkey = req.UserNkey
	u.Account = "wrong"
	require_Equal(t, f.s.UpdateClientGrant(u), ErrUnknownClient)
	u.Account = req.Account
	u.Grant.Pub.Allow = []string{"bad..subject"}
	require_Equal(t, f.s.UpdateClientGrant(u), ErrGrantRejected)
	require_Equal(t, grantRecv(t, closed), req.Client.ID)
	checkFor(t, time.Second, 10*time.Millisecond, func() error {
		cz, err := f.s.Connz(&ConnzOptions{State: ConnClosed, CID: req.Client.ID})
		if err != nil {
			return err
		}
		if len(cz.Conns) != 1 || cz.Conns[0].Reason != GrantRejected.String() {
			return errors.New("grant close reason not recorded")
		}
		return nil
	})
	require_Equal(t, f.s.UpdateClientGrant(u), ErrUnknownClient)
	select {
	case <-done:
		t.Fatal("duplicate Done")
	default:
	}
	select {
	case <-closed:
		t.Fatal("duplicate Closed")
	default:
	}
}

func TestAuthGrantRejects(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hook     *testGrantHook
		wantDone bool
	}{
		{"nil hook", nil, false},
		{"panic", &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict { panic("test") }}, false},
		{"nil verdict", &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict { return nil }}, false},
		{"zero generation", &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict { return &authverify.GrantVerdict{} }}, true},
		{"invalid grant", &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict {
			return &authverify.GrantVerdict{Generation: 1, Grant: authverify.Grant{Pub: authverify.SubjectGrant{Allow: []string{"a..b"}}}}
		}}, true},
		{"denied", &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict { return &authverify.GrantVerdict{Reject: true} }}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan bool, 2)
			var h authverify.GrantHook
			if tc.hook != nil {
				original := tc.hook.verify
				tc.hook.verify = func(r *authverify.GrantRequest) *authverify.GrantVerdict {
					v := original(r)
					if v != nil {
						v.Done = func(ok bool) { done <- ok }
					}
					return v
				}
				h = tc.hook
			}
			f := newGrantFixture(t, h)
			nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.NoReconnect())
			if nc != nil {
				nc.Close()
			}
			require_Error(t, err)
			if tc.wantDone {
				require_False(t, grantRecv(t, done))
			}
			select {
			case <-done:
				t.Fatal("unexpected Done")
			default:
			}
		})
	}
}

func TestAuthGrantStaticAndScopedUsers(t *testing.T) {
	var calls atomic.Int32
	h := &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict {
		calls.Add(1)
		return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
	}}
	plain, plainPub := createKey(t)
	f := newGrantFixture(t, h, func(ac *jwt.AccountClaims, _ *jwt.UserScope) { ac.SigningKeys.Add(plainPub) })
	for _, tc := range []struct {
		name   string
		signer nkeys.KeyPair
		scoped bool
		block  string
		allow  bool
	}{
		{"identity static", f.account, false, `{"mode":"static"}`, true},
		{"identity missing block", f.account, false, "", false},
		{"plain signer", plain, false, "", false},
		{"plain static", plain, false, `{"mode":"static"}`, false},
		{"scoped static", f.signer, true, `{"mode":"static"}`, false},
		{"unknown mode", f.account, false, `{"mode":"other"}`, false},
		{"scoped grant", f.signer, true, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, tc.signer, tc.scoped, tc.block, 0), nats.NoReconnect())
			if nc != nil {
				defer nc.Close()
			}
			if tc.allow {
				require_NoError(t, err)
			} else {
				require_Error(t, err)
			}
		})
	}
	require_Equal(t, calls.Load(), int32(1))
}

func TestAuthGrantEmptyAndReload(t *testing.T) {
	var calls atomic.Int32
	requests := make(chan *authverify.GrantRequest, 1)
	f := newGrantFixture(t, &testGrantHook{verify: func(r *authverify.GrantRequest) *authverify.GrantVerdict {
		calls.Add(1)
		requests <- r
		return &authverify.GrantVerdict{Generation: 1, Done: func(bool) {}}
	}})
	nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	req := grantRecv(t, requests)
	c := f.s.grantClient(req.Client.ID)
	check := func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		require_False(t, c.pubAllowedFullCheck("any", true, true))
		require_False(t, c.canSubscribe("any"))
		require_False(t, c.user.defaultPerms)
	}
	check()
	require_NoError(t, f.s.Reload())
	f.s.reloadAuthorization()
	check()
	require_Equal(t, calls.Load(), int32(1))
}

func TestAuthGrantCloseDuringVerify(t *testing.T) {
	done := make(chan bool, 1)
	closed := make(chan uint64, 1)
	var s *Server
	h := &testGrantHook{verify: func(r *authverify.GrantRequest) *authverify.GrantVerdict {
		_ = s.DisconnectClient(r.Client.ID, authverify.CodeDenied)
		return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(ok bool) { done <- ok }}
	}, closed: func(_ string, id uint64) { closed <- id }}
	f := newGrantFixture(t, h)
	s = f.s
	nc, err := nats.Connect(s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.NoReconnect())
	if nc != nil {
		nc.Close()
	}
	require_Error(t, err)
	require_False(t, grantRecv(t, done))
	select {
	case <-closed:
		t.Fatal("Closed for failed admission")
	default:
	}
}

func TestAuthGrantExpiryAndReplyTracking(t *testing.T) {
	reqs := make(chan *authverify.GrantRequest, 1)
	f := newGrantFixture(t, &testGrantHook{verify: func(r *authverify.GrantRequest) *authverify.GrantVerdict {
		reqs <- r
		g := grantAll()
		g.Resp = &jwt.ResponsePermission{MaxMsgs: 2, Expires: time.Minute}
		return &authverify.GrantVerdict{Generation: 1, Expires: time.Now().Unix() + 2, Grant: g, Done: func(bool) {}}
	}})
	jwtExpiry := time.Now().Unix() + 30
	nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", jwtExpiry), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	req := grantRecv(t, reqs)
	c := f.s.grantClient(req.Client.ID)
	c.mu.Lock()
	require_True(t, c.expires.Unix() < jwtExpiry)
	c.replies["reply"] = &resp{n: 1}
	g := c.authGrant.grant
	c.mu.Unlock()
	u := authverify.GrantUpdate{ClientID: req.Client.ID, Account: req.Account, UserNkey: req.UserNkey, Generation: 2, Expires: jwtExpiry + 10, Grant: g}
	require_NoError(t, f.s.UpdateClientGrant(u))
	c.mu.Lock()
	require_Equal(t, c.expires.Unix(), jwtExpiry)
	require_Equal(t, c.replies["reply"].n, 1)
	c.mu.Unlock()
	time.Sleep(2100 * time.Millisecond)
	require_NoError(t, nc.Flush())
	u.Generation++
	u.Grant.Resp = nil
	require_NoError(t, f.s.UpdateClientGrant(u))
	c.mu.Lock()
	require_True(t, c.replies == nil)
	c.mu.Unlock()
	u.Generation++
	u.Expires = time.Now().Unix() - 1
	require_NoError(t, f.s.UpdateClientGrant(u))
	checkFor(t, time.Second, 10*time.Millisecond, func() error {
		if !nc.IsClosed() {
			return errors.New("connection not expired")
		}
		return nil
	})
}

func TestAuthGrantIgnoresStaticPermissions(t *testing.T) {
	for _, name := range []string{"template deny", "template expansion", "account defaults", "xpermissions"} {
		t.Run(name, func(t *testing.T) {
			reqs := make(chan *authverify.GrantRequest, 1)
			h := &testGrantHook{verify: func(r *authverify.GrantRequest) *authverify.GrantVerdict {
				reqs <- r
				return &authverify.GrantVerdict{Generation: 1, Grant: authverify.Grant{Pub: authverify.SubjectGrant{Allow: []string{"granted"}}, Sub: authverify.SubjectGrant{Allow: []string{"granted"}}}, Done: func(bool) {}}
			}}
			f := newGrantFixture(t, h, func(ac *jwt.AccountClaims, scope *jwt.UserScope) {
				if name == "template expansion" {
					scope.Template.Pub.Deny = []string{"{{tag(missing)}}"}
				}
				if name == "account defaults" {
					scope.Template.Permissions = jwt.Permissions{}
					ac.DefaultPermissions.Pub.Deny.Add(">")
					ac.DefaultPermissions.Sub.Deny.Add(">")
				}
			})
			if name == "xpermissions" {
				raw := encodeAccountClaimWithXPermissions(t, f.claims, map[string]string{f.scope.Key: `{"kv":[{"op":"rw","bucket":"{{tag(missing)}}"}]}`})
				raw = authGrantJWTBlock(t, raw, oKp, `{"mode":"grant"}`)
				require_NoError(t, f.s.updateAccountWithClaimJWT(f.acc, raw))
			}
			nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.NoReconnect())
			require_NoError(t, err)
			defer nc.Close()
			req := grantRecv(t, reqs)
			c := f.s.grantClient(req.Client.ID)
			c.mu.Lock()
			defer c.mu.Unlock()
			require_True(t, c.pubAllowedFullCheck("granted", true, true))
			require_True(t, c.canSubscribe("granted"))
			require_False(t, c.pubAllowedFullCheck("other", true, true))
			require_False(t, c.canSubscribe("other"))
			require_False(t, c.user.defaultPerms)
		})
	}
}

func TestAuthGrantInProcess(t *testing.T) {
	requests := make(chan *authverify.GrantRequest, 1)
	f := newGrantFixture(t, &testGrantHook{verify: func(r *authverify.GrantRequest) *authverify.GrantVerdict {
		requests <- r
		return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
	}})
	nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.InProcessServer(f.s))
	require_NoError(t, err)
	defer nc.Close()
	req := grantRecv(t, requests)
	c := f.s.grantClient(req.Client.ID)
	require_True(t, c.iproc)
}

func TestAuthGrantAdmissionCloseOrdering(t *testing.T) {
	doneStarted := make(chan struct{})
	release := make(chan struct{})
	closed := make(chan uint64, 1)
	reqs := make(chan *authverify.GrantRequest, 1)
	f := newGrantFixture(t, &testGrantHook{verify: func(r *authverify.GrantRequest) *authverify.GrantVerdict {
		reqs <- r
		return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(ok bool) {
			if ok {
				close(doneStarted)
				<-release
			}
		}}
	}, closed: func(_ string, id uint64) { closed <- id }})
	connected := make(chan error, 1)
	creds := f.creds(t, f.signer, true, "", 0)
	go func() {
		nc, err := nats.Connect(f.s.ClientURL(), creds, nats.NoReconnect())
		if nc != nil {
			nc.Close()
		}
		connected <- err
	}()
	req := grantRecv(t, reqs)
	grantRecv(t, doneStarted)
	require_NoError(t, f.s.DisconnectClient(req.Client.ID, authverify.CodeDenied))
	select {
	case <-closed:
		t.Fatal("Closed preceded Done completion")
	default:
	}
	close(release)
	require_Equal(t, grantRecv(t, closed), req.Client.ID)
	grantRecv(t, connected)
}

func TestAuthGrantInvalidUpdateLists(t *testing.T) {
	for _, list := range []string{"publish allow", "publish deny", "subscribe allow", "subscribe deny", "publish prefix", "subscribe prefix", "budget"} {
		t.Run(list, func(t *testing.T) {
			reqs := make(chan *authverify.GrantRequest, 1)
			f := newGrantFixture(t, &testGrantHook{verify: func(r *authverify.GrantRequest) *authverify.GrantVerdict {
				reqs <- r
				return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
			}})
			nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.NoReconnect())
			require_NoError(t, err)
			defer nc.Close()
			req := grantRecv(t, reqs)
			g := grantAll()
			switch list {
			case "publish allow":
				g.Pub.Allow = []string{"a..b"}
			case "publish deny":
				g.Pub.Deny = []string{"a..b"}
			case "subscribe allow":
				g.Sub.Allow = []string{"a..b"}
			case "subscribe deny":
				g.Sub.Deny = []string{"a..b"}
			case "publish prefix":
				g.Pub.AllowPrefix = []string{"a.>"}
			case "subscribe prefix":
				g.Sub.AllowPrefix = []string{"a.>"}
			case "budget":
				g.Sub.AllowPrefix = make([]string, 4097)
			}
			require_Equal(t, f.s.UpdateClientGrant(authverify.GrantUpdate{ClientID: req.Client.ID, Account: req.Account, UserNkey: req.UserNkey, Generation: 2, Grant: g}), ErrGrantRejected)
		})
	}
}

func TestAuthGrantReauthenticationKeepsPermissions(t *testing.T) {
	reqs := make(chan *authverify.GrantRequest, 1)
	f := newGrantFixture(t, &testGrantHook{verify: func(r *authverify.GrantRequest) *authverify.GrantVerdict {
		reqs <- r
		return &authverify.GrantVerdict{Generation: 1, Grant: authverify.Grant{Resp: &jwt.ResponsePermission{MaxMsgs: 1, Expires: time.Minute}}, Done: func(bool) {}}
	}})
	nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	req := grantRecv(t, reqs)
	c := f.s.grantClient(req.Client.ID)
	c.mu.Lock()
	u := *c.user
	c.replies["reply"] = &resp{n: 1}
	c.mu.Unlock()
	u.Permissions = nil
	u.defaultPerms = true
	require_NoError(t, c.registerGrantUser(&u))
	c.mu.Lock()
	require_False(t, c.pubAllowedFullCheck("forbidden", false, true))
	require_False(t, c.canSubscribe("forbidden"))
	require_Equal(t, c.replies["reply"].n, 1)
	c.mu.Unlock()
	stop := make(chan struct{})
	observed := make(chan bool, 1)
	go func() {
		for {
			select {
			case <-stop:
				observed <- false
				return
			default:
			}
			c.mu.Lock()
			allowed := c.pubAllowedFullCheck("forbidden", false, true) || c.canSubscribe("forbidden")
			c.mu.Unlock()
			if allowed {
				observed <- true
				return
			}
		}
	}()
	for range 20 {
		f.s.reloadAuthorization()
	}
	close(stop)
	require_False(t, grantRecv(t, observed))
	c.mu.Lock()
	require_Equal(t, c.replies["reply"].n, 1)
	c.mu.Unlock()
}

func TestAuthGrantEmptyLeafInternalSubjects(t *testing.T) {
	c := &client{kind: LEAF, leaf: &leaf{}, authGrant: &authGrantState{}, user: &NkeyUser{}}
	p, pub, sub, err := compileAuthGrant(authverify.Grant{})
	require_NoError(t, err)
	c.installAuthGrant(p, pub, sub)
	c.opts.Export = p.Publish
	for _, subject := range []string{"ordinary", "$MQTT.test", "_R_.test", "$JS.ACK.stream.consumer.1.2.3.4.5"} {
		c.pa.subject = []byte(subject)
		require_False(t, c.leafMsgAllowed())
		require_False(t, c.pubAllowedFullCheck(subject, false, true))
		require_False(t, c.canSubscribe(subject))
	}
	c.leaf.isSpoke = true
	c.pa.subject = []byte("_GR_.cluster.server.forbidden")
	require_False(t, c.leafMsgAllowed())
}

func TestAuthGrantReinstallKeepsDeliveryDeny(t *testing.T) {
	c := &client{kind: CLIENT, user: &NkeyUser{}, subs: map[string]*subscription{"1": {subject: []byte("events.>"), sid: []byte("1")}}}
	p, pub, sub, err := compileAuthGrant(authverify.Grant{Sub: authverify.SubjectGrant{Allow: []string{"events.>"}, Deny: []string{"events.secret"}}})
	require_NoError(t, err)
	c.installAuthGrant(p, pub, sub)
	require_True(t, c.mperms != nil)
	c.installAuthGrant(p, pub, sub)
	require_True(t, c.mperms != nil)
}

func TestAuthGrantReauthenticationRefreshesExpiry(t *testing.T) {
	reqs := make(chan *authverify.GrantRequest, 1)
	f := newGrantFixture(t, &testGrantHook{verify: func(r *authverify.GrantRequest) *authverify.GrantVerdict {
		reqs <- r
		return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
	}})
	nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	req := grantRecv(t, reqs)
	c := f.s.grantClient(req.Client.ID)
	uc, err := jwt.DecodeUserClaims(req.Connect.JWT)
	require_NoError(t, err)
	uc.Expires = time.Now().Unix() + 20
	require_True(t, f.s.authGrantConnection(c, uc, f.acc, req.Connect.JWT, nil))
	c.mu.Lock()
	require_Equal(t, c.expires.Unix(), uc.Expires)
	c.mu.Unlock()
	uc.Times = []jwt.TimeRange{{Start: "00:00:00", End: "00:00:00"}}
	require_False(t, f.s.authGrantConnection(c, uc, f.acc, req.Connect.JWT, nil))
}

func TestAuthGrantScopedUserValidation(t *testing.T) {
	var calls atomic.Int32
	f := newGrantFixture(t, &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict {
		calls.Add(1)
		return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
	}})
	uk, err := nkeys.CreateUser()
	require_NoError(t, err)
	up, err := uk.PublicKey()
	require_NoError(t, err)
	uc := jwt.NewUserClaims(up)
	uc.IssuerAccount = f.acc.Name
	uc.SetScoped(true)
	uc.Pub.Allow.Add(">")
	raw, err := uc.Encode(f.signer)
	require_NoError(t, err)
	nc, err := nats.Connect(f.s.ClientURL(), nats.UserJWT(func() (string, error) { return raw, nil }, uk.Sign), nats.NoReconnect())
	if nc != nil {
		nc.Close()
	}
	require_Error(t, err)
	require_Equal(t, calls.Load(), int32(0))
}

func TestAuthGrantRetainsTemplateRestrictions(t *testing.T) {
	for _, name := range []string{"connection type", "proxy", "source", "time"} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			f := newGrantFixture(t, &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict {
				calls.Add(1)
				return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
			}}, func(_ *jwt.AccountClaims, scope *jwt.UserScope) {
				switch name {
				case "connection type":
					scope.Template.AllowedConnectionTypes = []string{"WEBSOCKET"}
				case "proxy":
					scope.Template.ProxyRequired = true
				case "source":
					scope.Template.Src = []string{"192.0.2.0/24"}
				case "time":
					scope.Template.Times = []jwt.TimeRange{{Start: "00:00:00", End: "00:00:00"}}
				}
			})
			nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.NoReconnect())
			if nc != nil {
				nc.Close()
			}
			require_Error(t, err)
			require_Equal(t, calls.Load(), int32(0))
		})
	}
}

func TestAuthGrantMissingDone(t *testing.T) {
	f := newGrantFixture(t, &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict {
		return &authverify.GrantVerdict{Generation: 1, Grant: grantAll()}
	}})
	nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.NoReconnect())
	if nc != nil {
		nc.Close()
	}
	require_Error(t, err)
}

func TestAuthGrantJWTExpiryCloses(t *testing.T) {
	reqs := make(chan *authverify.GrantRequest, 1)
	closed := make(chan uint64, 1)
	f := newGrantFixture(t, &testGrantHook{verify: func(r *authverify.GrantRequest) *authverify.GrantVerdict {
		reqs <- r
		return &authverify.GrantVerdict{Generation: 1, Expires: time.Now().Unix() + 60, Grant: grantAll(), Done: func(bool) {}}
	}, closed: func(_ string, id uint64) { closed <- id }})
	nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", time.Now().Unix()+2), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	req := grantRecv(t, reqs)
	require_Equal(t, grantRecv(t, closed), req.Client.ID)
	grantTransportClosedReason(t, f.s, req.Client.ID, AuthenticationExpired)
}
