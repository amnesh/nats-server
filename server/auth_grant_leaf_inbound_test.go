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
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server/authverify"
	"github.com/nats-io/nats.go"
)

type authGrantInboundLogEntry struct {
	level, message string
}

type authGrantInboundLogger struct {
	DummyLogger
	mu      sync.Mutex
	entries []authGrantInboundLogEntry
}

func (l *authGrantInboundLogger) add(level, format string, args ...any) {
	l.mu.Lock()
	l.entries = append(l.entries, authGrantInboundLogEntry{level, fmt.Sprintf(format, args...)})
	l.mu.Unlock()
}

func (l *authGrantInboundLogger) Warnf(format string, args ...any)  { l.add("warn", format, args...) }
func (l *authGrantInboundLogger) Debugf(format string, args ...any) { l.add("debug", format, args...) }
func (l *authGrantInboundLogger) Errorf(format string, args ...any) { l.add("error", format, args...) }

type authGrantInboundFixture struct {
	f         *grantFixture
	hub, leaf *Server
	hc, nc    *nats.Conn
}

func authGrantInboundGrant() authverify.Grant {
	return authverify.Grant{
		Pub: authverify.SubjectGrant{Allow: []string{"out.barrier"}},
		Sub: authverify.SubjectGrant{AllowPrefix: []string{"in.device-*.>"}, Allow: []string{"_INBOX.>"}},
	}
}

func newAuthGrantInboundFixture(t *testing.T, hook *testGrantHook) *authGrantInboundFixture {
	t.Helper()
	f := newGrantFixture(t, hook)
	hub := grantTransportCloneHub(t, f, hook, true)
	hc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
	require_NoError(t, err)
	t.Cleanup(hc.Close)
	_, err = hc.Subscribe("out.barrier", func(m *nats.Msg) { m.Respond(m.Data) })
	require_NoError(t, err)
	require_NoError(t, hc.Flush())
	leaf := grantTransportLeaf(t, grantTransportCredentials(t, f, false), hub)
	checkLeafNodeConnected(t, hub)
	checkLeafNodeConnected(t, leaf)
	nc, err := nats.Connect(leaf.ClientURL(), nats.NoReconnect())
	require_NoError(t, err)
	t.Cleanup(nc.Close)
	checkAccountLeafInterest(t, leaf, globalAccountName, "out.barrier")
	return &authGrantInboundFixture{f, hub, leaf, hc, nc}
}

func (f *authGrantInboundFixture) barrier(t *testing.T, payload string) {
	t.Helper()
	m, err := f.nc.Request("out.barrier", []byte(payload), time.Second)
	require_NoError(t, err)
	require_Equal(t, string(m.Data), payload)
}

func (f *authGrantInboundFixture) allowedControl(t *testing.T) *nats.Subscription {
	t.Helper()
	sub, err := f.nc.SubscribeSync("in.device-123.value")
	require_NoError(t, err)
	require_NoError(t, f.nc.Flush())
	checkAccountLeafInterest(t, f.hub, f.f.acc.Name, "in.device-123.value")
	require_NoError(t, f.hc.Publish("in.device-123.value", []byte("allowed control")))
	require_NoError(t, f.hc.Flush())
	m, err := sub.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, string(m.Data), "allowed control")
	return sub
}

func authGrantInboundNoInterest(t *testing.T, hub *Server, account, subject string) {
	t.Helper()
	acc, err := hub.LookupAccount(account)
	require_NoError(t, err)
	result := acc.sl.Match(subject)
	if len(result.psubs) != 0 || len(result.qsubs) != 0 {
		t.Errorf("hub retained unauthorized account interest on %s", subject)
	}
	z, err := hub.Leafz(&LeafzOptions{Subscriptions: true})
	require_NoError(t, err)
	if len(z.Leafs) != 1 {
		t.Fatalf("expected one accepted leaf, got %d", len(z.Leafs))
	}
	if slices.Contains(z.Leafs[0].Subs, subject) {
		t.Errorf("Leafz retained unauthorized interest on %s", subject)
	}
}

// Inserting a denied literal after dropping it leaks account interest even if
// the later delivery guard still prevents its payload.
func TestAuthGrantLeafImportPrefixSupersetNoLeak(t *testing.T) {
	f := newAuthGrantInboundFixture(t, authGrantInterestHook(authGrantInboundGrant()))
	log := &authGrantInboundLogger{}
	f.hub.SetLogger(log, true, false)
	allowed := f.allowedControl(t)
	id := authGrantSingleLeafID(t, f.hub)
	denied, err := f.nc.SubscribeSync("in.other.value")
	require_NoError(t, err)
	second, err := f.nc.SubscribeSync("in.other.second")
	require_NoError(t, err)
	require_NoError(t, f.nc.Flush())
	f.barrier(t, "ordered denied-interest barrier")
	authGrantInboundNoInterest(t, f.hub, f.f.acc.Name, "in.other.value")
	authGrantInboundNoInterest(t, f.hub, f.f.acc.Name, "in.other.second")
	require_NoError(t, f.hc.Publish("in.other.value", []byte("must not arrive")))
	require_NoError(t, f.hc.Publish("in.device-123.value", []byte("ordered payload barrier")))
	require_NoError(t, f.hc.Flush())
	m, err := allowed.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, string(m.Data), "ordered payload barrier")
	pending, _, err := denied.Pending()
	require_NoError(t, err)
	require_Equal(t, pending, 0)
	require_NoError(t, denied.Unsubscribe())
	require_NoError(t, second.Unsubscribe())
	require_NoError(t, f.nc.Flush())
	f.barrier(t, "ordered dropped-unsubscribe barrier")
	require_Equal(t, authGrantSingleLeafID(t, f.hub), id)
	log.mu.Lock()
	entries := slices.Clone(log.entries)
	log.mu.Unlock()
	var warnings, laterDebug int
	for _, entry := range entries {
		if strings.Contains(entry.message, "Violation") {
			t.Errorf("dropped interest logged a violation: %s", entry.message)
		}
		if !strings.Contains(entry.message, "Dropped literal leaf interest") {
			continue
		}
		if entry.level == "warn" {
			warnings++
		} else if entry.level == "debug" {
			laterDebug++
		}
	}
	require_Equal(t, warnings, 1)
	require_Equal(t, laterDebug, 1)
	t.Logf("denied literals retained no interest or payload; CID %d unchanged; warning=%d debug=%d", id, warnings, laterDebug)
}

// The drop exception must not weaken an ordinary static account's close.
func TestAuthGrantLeafImportPrefixSupersetStatic(t *testing.T) {
	acc := NewAccount("INBOUND_STATIC")
	opts := DefaultOptions()
	opts.Host, opts.Port = "127.0.0.1", -1
	opts.Accounts = []*Account{acc}
	opts.LeafNode.Host, opts.LeafNode.Port = "127.0.0.1", -1
	opts.Users = []*User{{Username: "inbound-test", Password: "synthetic-password", Account: acc,
		Permissions: &Permissions{Publish: &SubjectPermission{Allow: []string{"out.barrier"}}, Subscribe: &SubjectPermission{Allow: []string{"in.device-123.value"}}}}}
	hub := RunServer(opts)
	t.Cleanup(hub.Shutdown)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", hub.getOpts().LeafNode.Port), time.Second)
	require_NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require_NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	r := bufio.NewReader(conn)
	_, err = r.ReadString('\n')
	require_NoError(t, err)
	_, err = fmt.Fprint(conn, "CONNECT {\"user\":\"inbound-test\",\"pass\":\"synthetic-password\",\"name\":\"static-inbound-test\"}\r\nPING\r\n")
	require_NoError(t, err)
	fields := authGrantInfoFields(t, authGrantLeafUntilPong(t, r))
	authGrantRequireJSON(t, fields["import"], `{"allow":["in.device-123.value"]}`)
	id := authGrantSingleLeafID(t, hub)
	_, err = fmt.Fprint(conn, "LS+ in.device-123.value\r\nPING\r\n")
	require_NoError(t, err)
	authGrantLeafUntilPong(t, r)
	checkAccountLeafInterest(t, hub, acc.Name, "in.device-123.value")
	_, err = fmt.Fprint(conn, "LS+ in.other.value\r\nPING\r\n")
	require_NoError(t, err)
	line := authGrantLeafUntilErr(t, r)
	require_Contains(t, line, "Permissions Violation for Subscription")
	_, err = r.ReadByte()
	require_Equal(t, err, io.EOF)
	grantTransportClosedReason(t, hub, id, ProtocolViolation)
	t.Log("static exact Import retained -ERR and close for unauthorized literal LS+")
}

// Wildcard interest stays registered while exact prefix and deny checks prune
// payloads. The allowed message orders each denied publication on the link.
func TestAuthGrantLeafImportPrefixSupersetWildcard(t *testing.T) {
	grant := authGrantInboundGrant()
	grant.Sub.Deny = []string{"in.device-secret.>"}
	f := newAuthGrantInboundFixture(t, authGrantInterestHook(grant))
	f.allowedControl(t)
	id := authGrantSingleLeafID(t, f.hub)
	sub, err := f.nc.SubscribeSync("in.>")
	require_NoError(t, err)
	require_NoError(t, f.nc.Flush())
	f.barrier(t, "wildcard registration barrier")
	z, err := f.hub.Leafz(&LeafzOptions{Subscriptions: true})
	require_NoError(t, err)
	if !slices.Contains(z.Leafs[0].Subs, "in.>") {
		t.Errorf("wildcard interest in.> was not registered on the hub")
	}
	require_NoError(t, f.hc.Publish("in.device-1.x", []byte("wildcard allowed control")))
	require_NoError(t, f.hc.Flush())
	m, err := sub.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, m.Subject, "in.device-1.x")
	for _, subject := range []string{"in.other.value", "in.device-.value", "in.device-secret.value"} {
		require_NoError(t, f.hc.Publish(subject, []byte("must not arrive")))
		require_NoError(t, f.hc.Publish("in.device-1.x", []byte(subject)))
		require_NoError(t, f.hc.Flush())
		m, err := sub.NextMsg(time.Second)
		require_NoError(t, err)
		require_Equal(t, m.Subject, "in.device-1.x")
		require_Equal(t, string(m.Data), subject)
		pending, _, err := sub.Pending()
		require_NoError(t, err)
		require_Equal(t, pending, 0)
	}
	require_Equal(t, authGrantSingleLeafID(t, f.hub), id)
	t.Logf("wildcard stayed registered without wrong-prefix, empty-prefix, or denied payload; CID %d unchanged", id)
}

// The authoritative hook must widen before the public updater closes the old
// session. Reconnect must replay the same local subscription without recreating it.
func TestAuthGrantLeafImportPrefixSupersetWidening(t *testing.T) {
	var widened atomic.Bool
	requests := make(chan *authverify.GrantRequest, 8)
	grant := func() authverify.Grant {
		g := authGrantInboundGrant()
		if widened.Load() {
			g.Sub.Allow = append(g.Sub.Allow, "in.other.>")
		}
		return g
	}
	hook := &testGrantHook{verify: func(r *authverify.GrantRequest) *authverify.GrantVerdict {
		requests <- r
		return &authverify.GrantVerdict{Generation: 1, Grant: grant(), Done: func(bool) {}}
	}}
	f := newAuthGrantInboundFixture(t, hook)
	first := grantRecv(t, requests)
	allowed := f.allowedControl(t)
	sub, err := f.nc.SubscribeSync("in.other.value")
	require_NoError(t, err)
	require_NoError(t, f.nc.Flush())
	f.barrier(t, "before widening drop barrier")
	authGrantInboundNoInterest(t, f.hub, f.f.acc.Name, "in.other.value")
	require_NoError(t, f.hc.Publish("in.other.value", []byte("before widening")))
	require_NoError(t, f.hc.Publish("in.device-123.value", []byte("before widening payload barrier")))
	require_NoError(t, f.hc.Flush())
	_, err = allowed.NextMsg(time.Second)
	require_NoError(t, err)
	pending, _, err := sub.Pending()
	require_NoError(t, err)
	require_Equal(t, pending, 0)
	require_Equal(t, authGrantSingleLeafID(t, f.hub), first.Client.ID)
	widened.Store(true)
	require_NoError(t, f.hub.UpdateClientGrant(authverify.GrantUpdate{
		ClientID: first.Client.ID, Account: first.Account, UserNkey: first.UserNkey, Generation: 2, Grant: grant(),
	}))
	second := grantRecv(t, requests)
	require_True(t, second.Client.ID != first.Client.ID)
	checkLeafNodeConnected(t, f.hub)
	checkLeafNodeConnected(t, f.leaf)
	checkAccountLeafInterest(t, f.hub, f.f.acc.Name, "in.other.value")
	require_NoError(t, f.hc.Publish("in.other.value", []byte("widened replay")))
	require_NoError(t, f.hc.Flush())
	m, err := sub.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, string(m.Data), "widened replay")
	require_Equal(t, authGrantSingleLeafID(t, f.hub), second.Client.ID)
	t.Logf("previously dropped local subscription replayed on widening reconnect %d -> %d", first.Client.ID, second.Client.ID)
}

// The grant-only LS+ exception must never absorb an unauthorized LMSG.
func TestAuthGrantLeafImportPrefixSupersetPublishViolation(t *testing.T) {
	hook := authGrantInterestHook(authGrantInboundGrant())
	f := newGrantFixture(t, hook)
	hub := grantTransportCloneHub(t, f, hook, true)
	hc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
	require_NoError(t, err)
	defer hc.Close()
	sub, err := hc.SubscribeSync("out.>")
	require_NoError(t, err)
	require_NoError(t, hc.Flush())
	conn, r := authGrantRawLeaf(t, hub, f.creds(t, f.signer, true, "", 0))
	authGrantLeafUntilPong(t, r)
	id := authGrantSingleLeafID(t, hub)
	_, err = fmt.Fprint(conn, "LMSG out.barrier 7\r\ncontrol\r\nPING\r\n")
	require_NoError(t, err)
	authGrantLeafUntilPong(t, r)
	m, err := sub.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, string(m.Data), "control")
	_, err = fmt.Fprint(conn, "LS+ in.other.value\r\nPING\r\n")
	require_NoError(t, err)
	authGrantLeafUntilPong(t, r)
	require_Equal(t, authGrantSingleLeafID(t, hub), id)
	_, err = fmt.Fprint(conn, "LMSG out.denied 6\r\ndenied\r\nPING\r\n")
	require_NoError(t, err)
	line := authGrantLeafUntilErr(t, r)
	require_Contains(t, line, "Permissions Violation for Publish")
	_, err = r.ReadByte()
	require_Equal(t, err, io.EOF)
	grantTransportClosedReason(t, hub, id, ProtocolViolation)
	pending, _, err := sub.Pending()
	require_NoError(t, err)
	require_Equal(t, pending, 0)
	t.Log("grant leaf dropped denied LS+ but unauthorized LMSG retained -ERR and close")
}

// A response-authorized LS+ must reach the full dynamic allowance check before
// the grant-only drop. Ordinary response tests send LMSG and miss this ordering.
func TestAuthGrantLeafResponseImportPrefixSupersetAllowance(t *testing.T) {
	g := authGrantInboundGrant()
	g.Resp = &jwt.ResponsePermission{MaxMsgs: 2, Expires: 5 * time.Second}
	hook := authGrantInterestHook(g)
	f := newGrantFixture(t, hook)
	hub := grantTransportCloneHub(t, f, hook, true)
	hc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
	require_NoError(t, err)
	defer hc.Close()
	conn, r := authGrantRawLeaf(t, hub, f.creds(t, f.signer, true, "", 0))
	authGrantLeafUntilPong(t, r)
	_, err = fmt.Fprint(conn, "LS+ in.device-123.value\r\nPING\r\n")
	require_NoError(t, err)
	authGrantLeafUntilPong(t, r)
	checkAccountLeafInterest(t, hub, f.acc.Name, "in.device-123.value")
	const reply = "response.inbound.ordering"
	require_NoError(t, hc.PublishRequest("in.device-123.value", reply, []byte("request")))
	require_NoError(t, hc.Flush())
	for {
		line, err := r.ReadString('\n')
		require_NoError(t, err)
		if strings.HasPrefix(line, "LMSG in.device-123.value ") {
			payload, err := r.ReadString('\n')
			require_NoError(t, err)
			require_Equal(t, strings.TrimSpace(payload), "request")
			break
		}
	}
	id := authGrantSingleLeafID(t, hub)
	_, err = fmt.Fprint(conn, "LS+ "+reply+"\r\nPING\r\n")
	require_NoError(t, err)
	authGrantLeafUntilPong(t, r)
	checkAccountLeafInterest(t, hub, f.acc.Name, reply)
	require_NoError(t, hc.Publish(reply, []byte("allowed response interest")))
	require_NoError(t, hc.Flush())
	for {
		line, err := r.ReadString('\n')
		require_NoError(t, err)
		if strings.HasPrefix(line, "LMSG "+reply+" ") {
			payload, err := r.ReadString('\n')
			require_NoError(t, err)
			require_Equal(t, strings.TrimSpace(payload), "allowed response interest")
			break
		}
	}
	require_Equal(t, authGrantSingleLeafID(t, hub), id)
	t.Log("dynamic response allowance admitted an out-of-static-Sub LS+ before the grant-only drop")
}

func TestSublistReverseMatchNestedWildcard(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(fmt.Sprintf("cached=%t", cached), func(t *testing.T) {
			s := NewSublistNoCache()
			if cached {
				s = NewSublistWithCache()
			}
			subjects := []string{"in", "in.*", "in.*.>", "in.*.*.tail", "in.literal.>", "other.*.>"}
			for _, subject := range subjects {
				require_NoError(t, s.Insert(newSub(subject)))
			}
			for _, test := range []struct {
				query string
				want  []string
			}{
				{"in.>", subjects[1:5]},
				{">", subjects},
				{"absent.>", nil},
			} {
				var got []string
				for _, sub := range s.ReverseMatch(test.query).psubs {
					got = append(got, string(sub.subject))
				}
				want := slices.Clone(test.want)
				slices.Sort(got)
				slices.Sort(want)
				if !slices.Equal(got, want) {
					t.Errorf("ReverseMatch(%q) = %q, want %q", test.query, got, want)
				}
			}
		})
	}
}
