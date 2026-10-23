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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server/authverify"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func grantTransportRawConnect(t *testing.T, s *Server, credentials nats.Option) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", s.Addr().String(), time.Second)
	require_NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require_NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	require_NoError(t, err)
	require_True(t, strings.HasPrefix(line, "INFO "))
	var info Info
	require_NoError(t, json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "INFO "))), &info))
	options := nats.GetDefaultOptions()
	require_NoError(t, credentials(&options))
	token, err := options.UserJWT()
	require_NoError(t, err)
	sig, err := options.SignatureCB([]byte(info.Nonce))
	require_NoError(t, err)
	connect := map[string]any{"jwt": token, "sig": base64.RawURLEncoding.EncodeToString(sig), "verbose": false}
	data, err := json.Marshal(connect)
	require_NoError(t, err)
	_, err = fmt.Fprintf(conn, "CONNECT %s\r\nPING\r\n", data)
	require_NoError(t, err)
	return conn, reader
}

func grantTransportClosedReason(t *testing.T, s *Server, id uint64, reason ClosedState) {
	t.Helper()
	checkFor(t, 3*time.Second, 10*time.Millisecond, func() error {
		connections, err := s.Connz(&ConnzOptions{State: ConnClosed, CID: id})
		if err != nil {
			return err
		}
		if len(connections.Conns) != 1 {
			return fmt.Errorf("closed connection %d not recorded", id)
		}
		if got := connections.Conns[0].Reason; got != reason.String() {
			return fmt.Errorf("close reason %q, want %q", got, reason.String())
		}
		return nil
	})
}

func grantTransportCloneHub(t *testing.T, f *grantFixture, hook authverify.GrantHook, leaf bool) *Server {
	t.Helper()
	options, err := ProcessConfigFile(f.s.getOpts().ConfigFile)
	require_NoError(t, err)
	options.Port = -1
	options.AuthGrant = hook
	if leaf {
		options.LeafNode.Host = "127.0.0.1"
		options.LeafNode.Port = -1
	}
	s := RunServer(options)
	t.Cleanup(s.Shutdown)
	return s
}

func grantTransportCredentials(t *testing.T, f *grantFixture, static bool) string {
	t.Helper()
	user, err := nkeys.CreateUser()
	require_NoError(t, err)
	public, err := user.PublicKey()
	require_NoError(t, err)
	claims := jwt.NewUserClaims(public)
	claims.IssuerAccount = f.acc.Name
	signer := f.signer
	if static {
		signer = f.account
		claims.Pub.Allow.Add(">")
		claims.Sub.Allow.Add(">")
	} else {
		claims.SetScoped(true)
	}
	token, err := claims.Encode(signer)
	require_NoError(t, err)
	if static {
		token = authGrantJWTBlock(t, token, signer, `{"mode":"static"}`)
	}
	seed, err := user.Seed()
	require_NoError(t, err)
	data, err := jwt.FormatUserConfig(token, seed)
	require_NoError(t, err)
	path := filepath.Join(t.TempDir(), "user.creds")
	require_NoError(t, os.WriteFile(path, data, 0600))
	return path
}

func grantTransportLeaf(t *testing.T, credentials string, hubs ...*Server) *Server {
	t.Helper()
	urls := make([]*url.URL, len(hubs))
	for i, hub := range hubs {
		var err error
		urls[i], err = url.Parse(fmt.Sprintf("nats://127.0.0.1:%d", hub.getOpts().LeafNode.Port))
		require_NoError(t, err)
	}
	options := DefaultOptions()
	options.Host, options.Port = "127.0.0.1", -1
	options.LeafNode.ReconnectInterval = 25 * time.Millisecond
	options.LeafNode.Remotes = []*RemoteLeafOpts{{URLs: urls, Credentials: credentials, NoRandomize: true}}
	s := RunServer(options)
	t.Cleanup(s.Shutdown)
	return s
}

func TestAuthGrantRejectWire(t *testing.T) {
	for _, test := range []struct {
		name   string
		code   authverify.RejectCode
		wire   string
		reason ClosedState
	}{
		{"denied", authverify.CodeDenied, "-ERR 'Authorization Violation'\r\n", AuthenticationViolation},
		{"resource limit", authverify.CodeResourceLimit, "-ERR 'maximum connections exceeded'\r\n", ResourceLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := make(chan *authverify.GrantRequest, 1)
			closed := make(chan uint64, 1)
			f := newGrantFixture(t, &testGrantHook{verify: func(request *authverify.GrantRequest) *authverify.GrantVerdict {
				requests <- request
				return &authverify.GrantVerdict{Reject: true, Code: test.code, Reason: "private rejection detail"}
			}, closed: func(_ string, id uint64) { closed <- id }})
			_, reader := grantTransportRawConnect(t, f.s, f.creds(t, f.signer, true, "", 0))
			line, err := reader.ReadString('\n')
			require_NoError(t, err)
			require_Equal(t, line, test.wire)
			_, err = reader.ReadByte()
			require_Equal(t, err, io.EOF)
			request := grantRecv(t, requests)
			grantTransportClosedReason(t, f.s, request.Client.ID, test.reason)
			select {
			case id := <-closed:
				t.Fatalf("Closed called for rejected connection %d", id)
			default:
			}
		})
	}
}

func TestAuthGrantDisconnectWire(t *testing.T) {
	for _, test := range []struct {
		name   string
		code   authverify.RejectCode
		wire   string
		reason ClosedState
	}{
		{"denied", authverify.CodeDenied, "-ERR 'Authorization Violation'\r\n", GrantRejected},
		{"resource limit", authverify.CodeResourceLimit, "-ERR 'maximum connections exceeded'\r\n", ResourceLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := make(chan *authverify.GrantRequest, 1)
			closed := make(chan uint64, 2)
			f := newGrantFixture(t, &testGrantHook{verify: func(request *authverify.GrantRequest) *authverify.GrantVerdict {
				requests <- request
				return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
			}, closed: func(_ string, id uint64) { closed <- id }})
			_, reader := grantTransportRawConnect(t, f.s, f.creds(t, f.signer, true, "", 0))
			line, err := reader.ReadString('\n')
			require_NoError(t, err)
			require_Equal(t, line, "PONG\r\n")
			request := grantRecv(t, requests)
			require_NoError(t, f.s.DisconnectClient(request.Client.ID, test.code))
			line, err = reader.ReadString('\n')
			require_NoError(t, err)
			require_Equal(t, line, test.wire)
			_, err = reader.ReadByte()
			require_Equal(t, err, io.EOF)
			require_Equal(t, grantRecv(t, closed), request.Client.ID)
			grantTransportClosedReason(t, f.s, request.Client.ID, test.reason)
			require_Equal(t, f.s.DisconnectClient(request.Client.ID, test.code), ErrUnknownClient)
			select {
			case <-closed:
				t.Fatal("duplicate Closed callback")
			default:
			}
		})
	}
}

func TestAuthGrantClientResourceLimitFailover(t *testing.T) {
	for _, rejectAtConnect := range []bool{true, false} {
		name := "planned disconnect"
		if rejectAtConnect {
			name = "connect rejection"
		}
		t.Run(name, func(t *testing.T) {
			firstRequests := make(chan *authverify.GrantRequest, 8)
			secondRequests := make(chan *authverify.GrantRequest, 8)
			f := newGrantFixture(t, &testGrantHook{verify: func(request *authverify.GrantRequest) *authverify.GrantVerdict {
				firstRequests <- request
				if rejectAtConnect {
					return &authverify.GrantVerdict{Reject: true, Code: authverify.CodeResourceLimit}
				}
				return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
			}})
			second := grantTransportCloneHub(t, f, &testGrantHook{verify: func(request *authverify.GrantRequest) *authverify.GrantVerdict {
				secondRequests <- request
				return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
			}}, false)
			reconnected := make(chan struct{}, 4)
			nc, err := nats.Connect(f.s.ClientURL()+","+second.ClientURL(), f.creds(t, f.signer, true, "", 0),
				nats.DontRandomize(), nats.ReconnectWait(10*time.Millisecond), nats.MaxReconnects(10),
				nats.ReconnectHandler(func(*nats.Conn) { reconnected <- struct{}{} }))
			require_NoError(t, err)
			defer nc.Close()
			first := grantRecv(t, firstRequests)
			if !rejectAtConnect {
				require_Equal(t, nc.ConnectedUrl(), f.s.ClientURL())
				require_NoError(t, f.s.DisconnectClient(first.Client.ID, authverify.CodeResourceLimit))
				grantRecv(t, reconnected)
				grantTransportClosedReason(t, f.s, first.Client.ID, ResourceLimit)
			}
			secondRequest := grantRecv(t, secondRequests)
			require_Equal(t, secondRequest.UserNkey, first.UserNkey)
			require_Equal(t, nc.ConnectedUrl(), second.ClientURL())
			sub, err := nc.SubscribeSync("after.failover")
			require_NoError(t, err)
			require_NoError(t, nc.Publish("after.failover", []byte("second server")))
			message, err := sub.NextMsg(time.Second)
			require_NoError(t, err)
			require_Equal(t, string(message.Data), "second server")
		})
	}
}

func TestAuthGrantLeafResourceLimitFailover(t *testing.T) {
	firstRequests := make(chan *authverify.GrantRequest, 16)
	secondRequests := make(chan *authverify.GrantRequest, 16)
	reject := &testGrantHook{verify: func(request *authverify.GrantRequest) *authverify.GrantVerdict {
		firstRequests <- request
		return &authverify.GrantVerdict{Reject: true, Code: authverify.CodeResourceLimit}
	}}
	f := newGrantFixture(t, reject)
	first := grantTransportCloneHub(t, f, reject, true)
	second := grantTransportCloneHub(t, f, &testGrantHook{verify: func(request *authverify.GrantRequest) *authverify.GrantVerdict {
		secondRequests <- request
		return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
	}}, true)
	leaf := grantTransportLeaf(t, grantTransportCredentials(t, f, false), first, second)
	rejected := grantRecv(t, firstRequests)
	accepted := grantRecv(t, secondRequests)
	require_Equal(t, rejected.Client.Kind, "Leafnode")
	require_Equal(t, accepted.UserNkey, rejected.UserNkey)
	checkLeafNodeConnectedCount(t, first, 0)
	checkLeafNodeConnected(t, second)
	checkLeafNodeConnected(t, leaf)
	grantTransportClosedReason(t, first, rejected.Client.ID, ResourceLimit)
	t.Log("leaf remote rotates to the second configured URL after a resource-limit rejection")
}

func TestAuthGrantLeafUpdateReconnects(t *testing.T) {
	requests := make(chan *authverify.GrantRequest, 16)
	closed := make(chan uint64, 16)
	hook := &testGrantHook{verify: func(request *authverify.GrantRequest) *authverify.GrantVerdict {
		requests <- request
		return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
	}, closed: func(_ string, id uint64) { closed <- id }}
	f := newGrantFixture(t, hook)
	hub := grantTransportCloneHub(t, f, hook, true)
	leaf := grantTransportLeaf(t, grantTransportCredentials(t, f, false), hub)
	first := grantRecv(t, requests)
	checkLeafNodeConnected(t, hub)
	checkLeafNodeConnected(t, leaf)
	require_NoError(t, hub.UpdateClientGrant(authverify.GrantUpdate{
		ClientID: first.Client.ID, Account: first.Account, UserNkey: first.UserNkey, Generation: 2, Grant: grantAll(),
	}))
	require_Equal(t, grantRecv(t, closed), first.Client.ID)
	grantTransportClosedReason(t, hub, first.Client.ID, AuthorizationChanged)
	second := grantRecv(t, requests)
	require_True(t, second.Client.ID != first.Client.ID)
	require_Equal(t, second.UserNkey, first.UserNkey)
	checkLeafNodeConnected(t, hub)
	checkLeafNodeConnected(t, leaf)
}

func TestAuthGrantLeafPrefixMessages(t *testing.T) {
	requests := make(chan *authverify.GrantRequest, 1)
	hook := &testGrantHook{verify: func(request *authverify.GrantRequest) *authverify.GrantVerdict {
		select {
		case requests <- request:
		default:
		}
		return &authverify.GrantVerdict{Generation: 1, Grant: authverify.Grant{
			Pub: authverify.SubjectGrant{Allow: []string{"out.standard"}, AllowPrefix: []string{"out.device-*.>"}, Deny: []string{"out.device-denied.>"}},
			Sub: authverify.SubjectGrant{Allow: []string{"in.standard"}, AllowPrefix: []string{"in.device-*.>"}, Deny: []string{"in.device-denied.>"}},
		}, Done: func(bool) {}}
	}}
	f := newGrantFixture(t, hook)
	hub := grantTransportCloneHub(t, f, hook, true)
	leaf := grantTransportLeaf(t, grantTransportCredentials(t, f, false), hub)
	grantRecv(t, requests)
	checkLeafNodeConnected(t, hub)
	checkLeafNodeConnected(t, leaf)
	hubClient, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
	require_NoError(t, err)
	defer hubClient.Close()
	leafClient, err := nats.Connect(leaf.ClientURL(), nats.NoReconnect())
	require_NoError(t, err)
	defer leafClient.Close()
	for _, test := range []struct {
		name      string
		sender    *nats.Conn
		receiver  *nats.Conn
		subject   string
		subscribe string
		allowed   bool
	}{
		{"leaf standard", leafClient, hubClient, "out.standard", "out.standard", true},
		{"hub standard", hubClient, leafClient, "in.standard", "in.standard", true},
		{"leaf prefix", leafClient, hubClient, "out.device-123.value", "out.device-123.>", true},
		{"leaf prefix with broad hub interest", leafClient, hubClient, "out.device-123.value", "out.>", true},
		{"hub prefix", hubClient, leafClient, "in.device-123.value", "in.device-123.>", true},
		{"leaf wrong prefix", leafClient, hubClient, "out.other.value", "out.other.>", false},
		{"leaf wrong prefix with broad hub interest", leafClient, hubClient, "out.other.value", "out.>", false},
		{"hub wrong prefix", hubClient, leafClient, "in.other.value", "in.other.>", false},
		{"leaf empty suffix", leafClient, hubClient, "out.device-.value", "out.device-.>", false},
		{"hub empty suffix", hubClient, leafClient, "in.device-.value", "in.device-.>", false},
		{"leaf deny wins", leafClient, hubClient, "out.device-denied.value", "out.device-denied.>", false},
		{"leaf deny wins with broad hub interest", leafClient, hubClient, "out.device-denied.value", "out.>", false},
		{"hub deny wins", hubClient, leafClient, "in.device-denied.value", "in.device-denied.>", false},
		{"leaf cannot use hub permission", leafClient, hubClient, "in.device-123.value", "in.device-123.>", false},
		{"hub cannot use leaf permission", hubClient, leafClient, "out.device-123.value", "out.device-123.>", false},
		{"hub wildcard at prefix", hubClient, leafClient, "in.device-123.value", "in.*.>", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			sub, err := test.receiver.SubscribeSync(test.subscribe)
			require_NoError(t, err)
			defer func() {
				require_NoError(t, sub.Unsubscribe())
				require_NoError(t, test.receiver.Flush())
			}()
			require_NoError(t, test.receiver.Flush())
			if test.allowed {
				server, account := hub, f.acc.Name
				if test.sender == leafClient {
					server, account = leaf, globalAccountName
				}
				checkAccountLeafInterest(t, server, account, test.subject)
			}
			require_NoError(t, test.sender.Publish(test.subject, []byte(test.name)))
			require_NoError(t, test.sender.Flush())
			wait := 150 * time.Millisecond
			if test.allowed {
				wait = time.Second
			}
			message, err := sub.NextMsg(wait)
			if test.allowed {
				require_NoError(t, err)
				require_Equal(t, string(message.Data), test.name)
			} else {
				require_Equal(t, err, nats.ErrTimeout)
			}
		})
	}
	checkLeafNodeConnected(t, hub)
	checkLeafNodeConnected(t, leaf)
}

func TestAuthGrantClosedCanUpdateAnotherClient(t *testing.T) {
	requests := make(chan *authverify.GrantRequest, 4)
	type callbackResult struct {
		id      uint64
		removed bool
		err     error
	}
	results := make(chan callbackResult, 4)
	var server atomic.Pointer[Server]
	var watched atomic.Uint64
	var update atomic.Pointer[authverify.GrantUpdate]
	hook := &testGrantHook{verify: func(request *authverify.GrantRequest) *authverify.GrantVerdict {
		requests <- request
		return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
	}, closed: func(_ string, id uint64) {
		if id == watched.Load() {
			s := server.Load()
			removed := s.grantClient(id) == nil
			results <- callbackResult{id, removed, s.UpdateClientGrant(*update.Load())}
		}
	}}
	f := newGrantFixture(t, hook)
	server.Store(f.s)
	first, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.NoReconnect())
	require_NoError(t, err)
	defer first.Close()
	firstRequest := grantRecv(t, requests)
	second, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.NoReconnect())
	require_NoError(t, err)
	defer second.Close()
	secondRequest := grantRecv(t, requests)
	update.Store(&authverify.GrantUpdate{ClientID: secondRequest.Client.ID, Account: secondRequest.Account,
		UserNkey: secondRequest.UserNkey, Generation: 2, Grant: authverify.Grant{
			Pub: authverify.SubjectGrant{Allow: []string{"updated"}}, Sub: authverify.SubjectGrant{Allow: []string{"updated"}},
		}})
	watched.Store(firstRequest.Client.ID)
	first.Close()
	result := grantRecv(t, results)
	require_Equal(t, result.id, firstRequest.Client.ID)
	require_True(t, result.removed)
	require_NoError(t, result.err)
	sub, err := second.SubscribeSync("updated")
	require_NoError(t, err)
	require_NoError(t, second.Publish("updated", []byte("callback applied grant")))
	message, err := sub.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, string(message.Data), "callback applied grant")
	select {
	case <-results:
		t.Fatal("duplicate Closed callback")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestAuthGrantLeafResponseMessages(t *testing.T) {
	for _, test := range []struct {
		name string
		pub  []string
	}{
		{"empty publish allow", []string{}},
		{"unrelated publish allow", []string{"commands"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := make(chan *authverify.GrantRequest, 16)
			hook := &testGrantHook{verify: func(request *authverify.GrantRequest) *authverify.GrantVerdict {
				requests <- request
				return &authverify.GrantVerdict{Generation: 1, Grant: authverify.Grant{
					Pub:  authverify.SubjectGrant{Allow: test.pub},
					Sub:  authverify.SubjectGrant{Allow: []string{">"}},
					Resp: &jwt.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second},
				}, Done: func(bool) {}}
			}}
			f := newGrantFixture(t, hook)
			hub := grantTransportCloneHub(t, f, hook, true)
			leaf := grantTransportLeaf(t, grantTransportCredentials(t, f, false), hub)
			grantRecv(t, requests)
			checkLeafNodeConnected(t, hub)
			checkLeafNodeConnected(t, leaf)
			hubClient, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
			require_NoError(t, err)
			defer hubClient.Close()
			leafClient, err := nats.Connect(leaf.ClientURL(), nats.NoReconnect())
			require_NoError(t, err)
			defer leafClient.Close()
			service, err := leafClient.SubscribeSync("service")
			require_NoError(t, err)
			require_NoError(t, leafClient.Flush())
			checkAccountLeafInterest(t, hub, f.acc.Name, "service")
			inbox := nats.NewInbox()
			replies, err := hubClient.SubscribeSync(inbox)
			require_NoError(t, err)
			require_NoError(t, hubClient.Flush())
			require_NoError(t, hubClient.PublishRequest("service", inbox, []byte("request")))
			received, err := service.NextMsg(time.Second)
			require_NoError(t, err)
			require_Equal(t, received.Reply, inbox)
			require_Equal(t, string(received.Data), "request")
			require_NoError(t, leafClient.Publish(received.Reply, []byte("response")))
			response, err := replies.NextMsg(time.Second)
			require_NoError(t, err)
			require_Equal(t, string(response.Data), "response")
			checkLeafNodeConnected(t, hub)
			checkLeafNodeConnected(t, leaf)
		})
	}
}

func TestAuthGrantLeafStandardWildcardInterest(t *testing.T) {
	h := &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict {
		return &authverify.GrantVerdict{Generation: 1, Grant: authverify.Grant{Sub: authverify.SubjectGrant{Allow: []string{"foo"}}}, Done: func(bool) {}}
	}}
	f := newGrantFixture(t, h)
	hub := grantTransportCloneHub(t, f, h, true)
	leaf := grantTransportLeaf(t, grantTransportCredentials(t, f, false), hub)
	checkLeafNodeConnected(t, hub)
	checkLeafNodeConnected(t, leaf)
	hubClient, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
	require_NoError(t, err)
	defer hubClient.Close()
	leafClient, err := nats.Connect(leaf.ClientURL(), nats.NoReconnect())
	require_NoError(t, err)
	defer leafClient.Close()
	sub, err := leafClient.SubscribeSync(">")
	require_NoError(t, err)
	require_NoError(t, leafClient.Flush())
	checkAccountLeafInterest(t, hub, f.acc.Name, "foo")
	require_NoError(t, hubClient.Publish("foo", []byte("allowed")))
	m, err := sub.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, m.Subject, "foo")
	require_NoError(t, hubClient.Publish("bar", nil))
	require_NoError(t, hubClient.Flush())
	_, err = sub.NextMsg(100 * time.Millisecond)
	require_Equal(t, err, nats.ErrTimeout)
	checkLeafNodeConnected(t, hub)
}
