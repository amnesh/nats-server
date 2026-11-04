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
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server/authverify"
	"github.com/nats-io/nats.go"
)

func authGrantRawLeaf(t *testing.T, hub *Server, credentials nats.Option, hubRole ...bool) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, r, fields := authGrantDialLeaf(t, hub, credentials)
	if len(hubRole) > 0 {
		fields["is_hub"] = hubRole[0]
	}
	connect, err := json.Marshal(fields)
	require_NoError(t, err)
	_, err = fmt.Fprintf(conn, "CONNECT %s\r\nPING\r\n", connect)
	require_NoError(t, err)
	return conn, r
}

// authGrantDialLeaf reads the hub INFO and returns the signed CONNECT fields
// without sending them.
func authGrantDialLeaf(t *testing.T, hub *Server, credentials nats.Option) (net.Conn, *bufio.Reader, map[string]any) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", hub.getOpts().LeafNode.Port), time.Second)
	require_NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require_NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	require_NoError(t, err)
	var info Info
	require_NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(line), "INFO ")), &info))
	opts := nats.GetDefaultOptions()
	require_NoError(t, credentials(&opts))
	token, err := opts.UserJWT()
	require_NoError(t, err)
	sig, err := opts.SignatureCB([]byte(info.Nonce))
	require_NoError(t, err)
	return conn, r, map[string]any{"jwt": token, "sig": base64.RawURLEncoding.EncodeToString(sig), "name": "grant-test-leaf", "headers": true}
}

func authGrantLeafUntilPong(t *testing.T, r *bufio.Reader) []string {
	t.Helper()
	var lines []string
	for {
		line, err := r.ReadString('\n')
		require_NoError(t, err)
		line = strings.TrimSpace(line)
		if line == "PONG" {
			return lines
		}
		if strings.HasPrefix(line, "-ERR") {
			t.Fatalf("leaf rejected: %s", line)
		}
		lines = append(lines, line)
	}
}

func authGrantLeafUntilErr(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	for {
		line, err := r.ReadString('\n')
		require_NoError(t, err)
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "-ERR") {
			return line
		}
	}
}

// A grant leaf has no built-in exception for service-import replies: it needs
// a grant for the reply subject.
func TestAuthGrantLeafServiceReplyNeedsGrant(t *testing.T) {
	for _, test := range []struct {
		name      string
		pub       []string
		delivered bool
	}{
		{"no grant", nil, false},
		{"exact grant", []string{"_R_.grant.service"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			hook := &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict {
				return &authverify.GrantVerdict{Generation: 1, Grant: authverify.Grant{
					Pub: authverify.SubjectGrant{Allow: test.pub},
				}, Done: func(bool) {}}
			}}
			f := newGrantFixture(t, hook)
			hub := grantTransportCloneHub(t, f, hook, true)
			nc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
			require_NoError(t, err)
			defer nc.Close()
			sub, err := nc.SubscribeSync("_R_.grant.service")
			require_NoError(t, err)
			require_NoError(t, nc.Flush())
			conn, r := authGrantRawLeaf(t, hub, f.creds(t, f.signer, true, "", 0))
			authGrantLeafUntilPong(t, r)
			_, err = fmt.Fprint(conn, "LMSG _R_.grant.service 5\r\nreply\r\nPING\r\n")
			require_NoError(t, err)
			if test.delivered {
				m, err := sub.NextMsg(time.Second)
				require_NoError(t, err)
				require_Equal(t, string(m.Data), "reply")
				authGrantLeafUntilPong(t, r)
				return
			}
			require_Contains(t, authGrantLeafUntilErr(t, r), "Permissions Violation for Publish")
			_, err = sub.NextMsg(250 * time.Millisecond)
			require_Error(t, err, nats.ErrTimeout)
		})
	}
}

// A grant leaf has no built-in exception for JetStream acknowledgements. The
// exact ack row that the NCDL JS-API table emits for a granted stream is enough.
func TestAuthGrantLeafJetStreamAckNeedsGrant(t *testing.T) {
	for _, test := range []struct {
		name  string
		pub   []string
		acked bool
	}{
		{"no ack grant", nil, false},
		{"exact ack row", []string{"$JS.ACK.GRANT_ACK.*.*.*.*.*.*"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			hook := &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict {
				return &authverify.GrantVerdict{Generation: 1, Grant: authverify.Grant{
					Pub: authverify.SubjectGrant{Allow: test.pub},
					Sub: authverify.SubjectGrant{Allow: []string{"delivery"}},
				}, Done: func(bool) {}}
			}}
			f := newGrantFixture(t, hook, func(ac *jwt.AccountClaims, _ *jwt.UserScope) {
				ac.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: jwt.NoLimit, DiskStorage: jwt.NoLimit, Streams: jwt.NoLimit, Consumer: jwt.NoLimit}
			})
			hub := grantTransportCloneHub(t, f, hook, true)
			_, systemKey := createKey(t)
			systemJWT, err := jwt.NewAccountClaims(systemKey).Encode(oKp)
			require_NoError(t, err)
			require_NoError(t, hub.AccountResolver().Store(systemKey, systemJWT))
			require_NoError(t, hub.SetSystemAccount(systemKey))
			require_NoError(t, hub.EnableJetStream(&JetStreamConfig{StoreDir: t.TempDir(), MaxMemory: 64 << 20, MaxStore: 64 << 20}))
			nc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
			require_NoError(t, err)
			defer nc.Close()
			js, err := nc.JetStream()
			require_NoError(t, err)
			_, err = js.AddStream(&nats.StreamConfig{Name: "GRANT_ACK", Subjects: []string{"events"}, Storage: nats.MemoryStorage})
			require_NoError(t, err)
			_, err = js.AddConsumer("GRANT_ACK", &nats.ConsumerConfig{Durable: "worker", DeliverSubject: "delivery", AckPolicy: nats.AckExplicitPolicy, AckWait: time.Minute})
			require_NoError(t, err)
			conn, r := authGrantRawLeaf(t, hub, f.creds(t, f.signer, true, "", 0))
			authGrantLeafUntilPong(t, r)
			_, err = fmt.Fprint(conn, "LS+ delivery\r\nPING\r\n")
			require_NoError(t, err)
			authGrantLeafUntilPong(t, r)
			_, err = js.Publish("events", []byte("event"))
			require_NoError(t, err)
			var ack string
			for ack == "" {
				line, err := r.ReadString('\n')
				require_NoError(t, err)
				if strings.HasPrefix(line, "LMSG delivery ") {
					ack = strings.Fields(line)[2]
					_, err = r.ReadString('\n')
					require_NoError(t, err)
				}
			}
			require_True(t, strings.HasPrefix(ack, "$JS.ACK.GRANT_ACK."))
			_, err = fmt.Fprintf(conn, "LMSG %s 4\r\n+ACK\r\nPING\r\n", ack)
			require_NoError(t, err)
			if !test.acked {
				require_Contains(t, authGrantLeafUntilErr(t, r), "Permissions Violation for Publish")
				time.Sleep(100 * time.Millisecond)
				ci, err := js.ConsumerInfo("GRANT_ACK", "worker")
				require_NoError(t, err)
				require_Equal(t, ci.NumAckPending, 1)
				return
			}
			authGrantLeafUntilPong(t, r)
			checkFor(t, time.Second, 10*time.Millisecond, func() error {
				ci, err := js.ConsumerInfo("GRANT_ACK", "worker")
				if err != nil {
					return err
				}
				if ci.NumAckPending != 0 || ci.AckFloor.Stream != 1 {
					return fmt.Errorf("ack did not advance consumer: pending=%d floor=%d", ci.NumAckPending, ci.AckFloor.Stream)
				}
				return nil
			})
		})
	}
}

// A grant connection has no built-in exception for service-import replies,
// JetStream acknowledgements, or gateway-routed replies. A non-grant leaf keeps
// the upstream exceptions.
func TestAuthGrantLeafMessageExceptionsStrict(t *testing.T) {
	for _, subject := range []string{"_R_.abc.def", "$JS.ACK.S.C.1.1.1.1.0", "_GR_.abcdef.ghijkl.reply.subject"} {
		for _, grant := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/grant=%t", subject, grant), func(t *testing.T) {
				c := &client{kind: LEAF, leaf: &leaf{isSpoke: true}, user: &NkeyUser{}}
				p, pub, sub, err := compileAuthGrant(authverify.Grant{})
				require_NoError(t, err)
				c.installAuthGrant(p, pub, sub)
				c.opts.Export = p.Publish
				c.authGrantMode.Store(grant)
				c.pa.subject = []byte(subject)
				require_Equal(t, c.leafMsgAllowed(), !grant)
			})
		}
	}
}

func TestAuthGrantLeafResponseInterestPrivacy(t *testing.T) {
	hook := &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict {
		return &authverify.GrantVerdict{Generation: 1, Grant: authverify.Grant{
			Pub:  authverify.SubjectGrant{Allow: []string{"allowed.>"}, AllowPrefix: []string{"prefix.device-*"}, Deny: []string{"allowed.secret"}},
			Sub:  authverify.SubjectGrant{Allow: []string{"service"}},
			Resp: &jwt.ResponsePermission{MaxMsgs: 1, Expires: time.Second},
		}, Done: func(bool) {}}
	}}
	f := newGrantFixture(t, hook)
	hub := grantTransportCloneHub(t, f, hook, true)
	nc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	for _, subject := range []string{"allowed.public", "allowed.secret", "secret.outside", "prefix.device-1", "prefix.other-1"} {
		_, err = nc.SubscribeSync(subject)
		require_NoError(t, err)
	}
	require_NoError(t, nc.Flush())
	conn, r := authGrantRawLeaf(t, hub, f.creds(t, f.signer, true, "", 0))
	lines := authGrantLeafUntilPong(t, r)
	interest := make(map[string]bool)
	for _, line := range lines {
		if strings.HasPrefix(line, "LS+ ") {
			interest[strings.Fields(line)[1]] = true
		}
	}
	for _, subject := range []string{"allowed.secret", "secret.outside", "prefix.other-1"} {
		if interest[subject] {
			t.Errorf("grant leaf learned forbidden subscription %q", subject)
		}
	}
	for _, subject := range []string{"allowed.public", "prefix.device-1"} {
		if !interest[subject] {
			t.Errorf("grant leaf missed allowed subscription %q", subject)
		}
	}
	_, err = fmt.Fprint(conn, "PING\r\n")
	require_NoError(t, err)
	authGrantLeafUntilPong(t, r)
}

// A grant connection has no built-in exception for MQTT subjects. Upstream
// v2.15.2 also removed the exception for leaf connections, so a leaf has none
// with or without a grant.
func TestAuthGrantLeafMQTTExceptionsStrict(t *testing.T) {
	for _, grant := range []bool{false, true} {
		t.Run(fmt.Sprintf("grant=%t", grant), func(t *testing.T) {
			c := &client{kind: LEAF, leaf: &leaf{}, authGrant: &authGrantState{}, user: &NkeyUser{}}
			p, pub, sub, err := compileAuthGrant(authverify.Grant{})
			require_NoError(t, err)
			c.installAuthGrant(p, pub, sub)
			c.opts.Export = p.Publish
			c.authGrantMode.Store(grant)
			for _, subject := range []string{"$MQTT.sub.test", "$MQTT.deliver.pubrel.test", "$MQTT.JSA.test"} {
				require_False(t, c.canSubscribeInternal(subject))
				require_False(t, c.pubAllowedFullCheck(subject, false, true))
				require_False(t, c.leafSendAllowed([]byte(subject)))
			}
		})
	}
}

func TestAuthGrantLeafResponseHubRole(t *testing.T) {
	hook := &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict {
		return &authverify.GrantVerdict{Generation: 1, Grant: authverify.Grant{
			Sub:  authverify.SubjectGrant{Allow: []string{"service"}},
			Resp: &jwt.ResponsePermission{MaxMsgs: 1, Expires: time.Second},
		}, Done: func(bool) {}}
	}}
	f := newGrantFixture(t, hook)
	hub := grantTransportCloneHub(t, f, hook, true)
	nc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	sub, err := nc.SubscribeSync("_INBOX.grant.response")
	require_NoError(t, err)
	require_NoError(t, nc.Flush())
	conn, r := authGrantRawLeaf(t, hub, f.creds(t, f.signer, true, "", 0), true)
	authGrantLeafUntilPong(t, r)
	_, err = fmt.Fprint(conn, "LS+ service\r\nPING\r\n")
	require_NoError(t, err)
	authGrantLeafUntilPong(t, r)
	require_NoError(t, nc.PublishRequest("service", "_INBOX.grant.response", []byte("request")))
	require_NoError(t, nc.Flush())
	_, err = fmt.Fprint(conn, "PING\r\n")
	require_NoError(t, err)
	lines := authGrantLeafUntilPong(t, r)
	advertised := false
	for _, line := range lines {
		if line == "LS+ _INBOX.grant.response" {
			advertised = true
		}
		if strings.HasPrefix(line, "LMSG service ") && !advertised {
			t.Fatal("request arrived before response interest was advertised")
		}
	}
	require_True(t, advertised)
	_, err = fmt.Fprint(conn, "LMSG _INBOX.grant.response 8\r\nresponse\r\n")
	require_NoError(t, err)
	m, err := sub.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, string(m.Data), "response")
}

// A reply subject that the leaf can learn through standard interest keeps that
// interest. A delivered request neither duplicates its LS+ nor removes it.
func TestAuthGrantLeafResponseKeepsStandardInterest(t *testing.T) {
	hook := &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict {
		return &authverify.GrantVerdict{Generation: 1, Grant: authverify.Grant{
			Pub:  authverify.SubjectGrant{Allow: []string{"_INBOX.grant.>"}},
			Sub:  authverify.SubjectGrant{Allow: []string{"service"}},
			Resp: &jwt.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second},
		}, Done: func(bool) {}}
	}}
	f := newGrantFixture(t, hook)
	hub := grantTransportCloneHub(t, f, hook, true)
	nc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	const inbox = "_INBOX.grant.response"
	replies, err := nc.SubscribeSync(inbox)
	require_NoError(t, err)
	require_NoError(t, nc.Flush())
	conn, r := authGrantRawLeaf(t, hub, f.creds(t, f.signer, true, "", 0))
	require_True(t, slices.Contains(authGrantLeafUntilPong(t, r), "LS+ "+inbox))
	_, err = fmt.Fprint(conn, "LS+ service\r\nPING\r\n")
	require_NoError(t, err)
	authGrantLeafUntilPong(t, r)

	require_NoError(t, nc.PublishRequest("service", inbox, []byte("request")))
	require_NoError(t, nc.Flush())
	_, err = fmt.Fprint(conn, "PING\r\n")
	require_NoError(t, err)
	lines := authGrantLeafUntilPong(t, r)
	require_True(t, slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, "LMSG service ") }))
	if slices.Contains(lines, "LS+ "+inbox) {
		t.Fatal("request duplicated the standard reply interest")
	}

	for _, data := range []string{"response", "again"} {
		_, err = fmt.Fprintf(conn, "LMSG %s %d\r\n%s\r\nPING\r\n", inbox, len(data), data)
		require_NoError(t, err)
		if slices.Contains(authGrantLeafUntilPong(t, r), "LS- "+inbox) {
			t.Fatal("reply removed the standard reply interest")
		}
		m, err := replies.NextMsg(time.Second)
		require_NoError(t, err)
		require_Equal(t, string(m.Data), data)
	}
}

// Reply interest that only a delivered request authorizes is removed when the
// response permission is used, at the next reply-permission prune.
func TestAuthGrantLeafResponseInterestRemovedAfterUse(t *testing.T) {
	hook := &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict {
		return &authverify.GrantVerdict{Generation: 1, Grant: authverify.Grant{
			Sub:  authverify.SubjectGrant{Allow: []string{"service"}},
			Resp: &jwt.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second},
		}, Done: func(bool) {}}
	}}
	f := newGrantFixture(t, hook)
	hub := grantTransportCloneHub(t, f, hook, true)
	nc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	const first, second = "_INBOX.grant.first", "_INBOX.grant.second"
	replies, err := nc.SubscribeSync("_INBOX.grant.*")
	require_NoError(t, err)
	require_NoError(t, nc.Flush())
	conn, r := authGrantRawLeaf(t, hub, f.creds(t, f.signer, true, "", 0))
	authGrantLeafUntilPong(t, r)
	_, err = fmt.Fprint(conn, "LS+ service\r\nPING\r\n")
	require_NoError(t, err)
	authGrantLeafUntilPong(t, r)

	request := func(reply string) []string {
		t.Helper()
		require_NoError(t, nc.PublishRequest("service", reply, []byte("request")))
		require_NoError(t, nc.Flush())
		_, err := fmt.Fprint(conn, "PING\r\n")
		require_NoError(t, err)
		return authGrantLeafUntilPong(t, r)
	}
	require_True(t, slices.Contains(request(first), "LS+ "+first))
	_, err = fmt.Fprintf(conn, "LMSG %s 8\r\nresponse\r\nPING\r\n", first)
	require_NoError(t, err)
	authGrantLeafUntilPong(t, r)
	m, err := replies.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, string(m.Data), "response")

	// The next request after replyPruneTime prunes the used permission.
	time.Sleep(replyPruneTime + 100*time.Millisecond)
	lines := request(second)
	require_True(t, slices.Contains(lines, "LS+ "+second))
	require_True(t, slices.Contains(lines, "LS- "+first))
}

// A second CONNECT on an admitted grant leaf decodes its export field into
// c.opts before re-authentication installs the grant again. JSON decoding
// writes into the existing permission or replaces it. Interest that the hub
// projects for its subscriptions in that interval must still follow the
// grant.
func TestAuthGrantLeafSecondConnectExportKeepsInterestConfined(t *testing.T) {
	for _, test := range []struct{ name, export, decoded string }{
		{"allow_all", `{"allow":[">"]}`, `{"allow":["\u003e"]}`},
		{"allow_null", `{"allow":null}`, `{}`},
		{"null", `null`, `null`},
	} {
		t.Run(test.name, func(t *testing.T) {
			hook := authGrantOrdinaryInterestHook()
			f := newGrantFixture(t, hook)
			hub := grantTransportCloneHub(t, f, hook, true)
			nc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
			require_NoError(t, err)
			defer nc.Close()

			conn, reader, fields := authGrantDialLeaf(t, hub, f.creds(t, f.signer, true, "", 0))
			first, err := json.Marshal(fields)
			require_NoError(t, err)
			_, err = fmt.Fprintf(conn, "CONNECT %s\r\nPING\r\n", first)
			require_NoError(t, err)
			authGrantLeafUntilPong(t, reader)
			lc := hub.GetLeafNode(authGrantSingleLeafID(t, hub))
			require_True(t, lc != nil)
			fields["export"] = json.RawMessage(test.export)
			second, err := json.Marshal(fields)
			require_NoError(t, err)

			// After the second CONNECT is decoded, clearAccountSubs and
			// re-authentication take the server lock. Hold it to keep the
			// leaf in its account with the decoded CONNECT fields.
			hub.mu.Lock()
			defer hub.mu.Unlock()
			_, err = fmt.Fprintf(conn, "CONNECT %s\r\n", second)
			require_NoError(t, err)
			checkFor(t, 2*time.Second, time.Millisecond, func() error {
				lc.mu.Lock()
				got, err := json.Marshal(lc.opts.Export)
				lc.mu.Unlock()
				if err != nil || string(got) != test.decoded {
					return fmt.Errorf("second CONNECT export = %s, want %s", got, test.decoded)
				}
				return nil
			})

			// A hub SUB reaches the leaf projection without the server lock.
			// Rows leave in order, so the in-grant row is a barrier for any
			// earlier row of the subject outside the grant.
			_, err = nc.SubscribeSync("secret.value")
			require_NoError(t, err)
			_, err = nc.SubscribeSync("out.allowed")
			require_NoError(t, err)
			var lines []string
			for !slices.Contains(lines, "LS+ out.allowed") {
				line, err := reader.ReadString('\n')
				require_NoError(t, err)
				lines = append(lines, strings.TrimSpace(line))
			}
			authGrantRequireInterestRows(t, lines, "LS+", "secret.", nil)
		})
	}
}
