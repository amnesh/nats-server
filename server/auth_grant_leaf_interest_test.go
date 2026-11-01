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
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server/authverify"
	"github.com/nats-io/nats.go"
)

// Only report subject interest: the handshake contains credentials and must
// never appear in test output.
func authGrantInterestRows(lines []string, operation, prefix string) []string {
	var subjects []string
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == operation && strings.HasPrefix(fields[1], prefix) {
			subjects = append(subjects, fields[1])
		}
	}
	slices.Sort(subjects)
	return subjects
}

func authGrantRequireInterestRows(t *testing.T, lines []string, operation, prefix string, want []string) {
	t.Helper()
	got := authGrantInterestRows(lines, operation, prefix)
	t.Logf("%s %s interest through PONG: %q", operation, prefix, got)
	if !slices.Equal(got, want) {
		t.Errorf("%s %s interest = %q, want %q", operation, prefix, got, want)
	}
}

func TestAuthGrantLeafMappingInterestConfined(t *testing.T) {
	hook := &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict {
		return &authverify.GrantVerdict{Generation: 1, Grant: authverify.Grant{
			Pub: authverify.SubjectGrant{
				Allow:       []string{"map.allowed", "map.*.wild"},
				Deny:        []string{"map.secret.wild"},
				AllowPrefix: []string{"map.device-*"},
			},
			Resp: &jwt.ResponsePermission{MaxMsgs: 1, Expires: time.Second},
		}, Done: func(bool) {}}
	}}
	f := newGrantFixture(t, hook, func(ac *jwt.AccountClaims, _ *jwt.UserScope) {
		for _, source := range []string{"map.>", "map.device-1", "map.other-1", "map.secret.wild"} {
			ac.AddMapping(jwt.Subject(source), jwt.WeightedMapping{Subject: jwt.Subject(strings.Replace(source, "map.", "destination.", 1))})
		}
	})
	hub := grantTransportCloneHub(t, f, hook, true)
	credentials := f.creds(t, f.signer, true, "", 0)
	want := []string{"map.*", "map.*.wild", "map.allowed", "map.device-1"}
	for _, phase := range []string{"initial", "reconnect"} {
		t.Run(phase, func(t *testing.T) {
			conn, reader := authGrantRawLeaf(t, hub, credentials)
			lines := authGrantLeafUntilPong(t, reader)
			authGrantRequireInterestRows(t, lines, "LS+", "map.", want)
			var export *SubjectPermission
			for _, line := range lines {
				if strings.HasPrefix(line, "INFO ") {
					var info Info
					require_NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(line, "INFO ")), &info))
					if info.Export != nil {
						export = info.Export
					}
				}
			}
			if export == nil || !slices.Contains(export.Allow, ">") || !slices.Contains(export.Deny, "map.secret.wild") {
				t.Fatal("finite response authority or partial deny missing from INFO.Export")
			}
			t.Log("INFO.Export preserves finite-response broad allow and map.secret.wild deny")
			fields := authGrantInfoFields(t, lines)
			authGrantRequireJSON(t, fields["export_grant"], `{"allow":["map.allowed","map.*.wild"],"deny":["map.secret.wild"],"allow_prefix":["map.device-*"]}`)
			t.Logf("legacy INFO.Import=%s INFO.Export=%s", fields["import"], fields["export"])
			authGrantRequireJSON(t, fields["export"], `{"allow":[">"],"deny":["map.secret.wild"]}`)
			require_NoError(t, conn.Close())
		})
		checkFor(t, time.Second, 10*time.Millisecond, func() error {
			z, err := hub.Leafz(nil)
			if err != nil {
				return err
			}
			if z.NumLeafs != 0 {
				return fmt.Errorf("closed raw leaf still present: %d", z.NumLeafs)
			}
			return nil
		})
	}
	t.Run("static", func(t *testing.T) {
		_, reader := authGrantRawLeaf(t, hub, nats.UserCredentials(grantTransportCredentials(t, f, true)))
		lines := authGrantLeafUntilPong(t, reader)
		authGrantRequireInterestRows(t, lines, "LS+", "map.",
			[]string{"map.>", "map.device-1", "map.other-1", "map.secret.wild"})
		if len(authGrantInfoFields(t, lines)["export_grant"]) != 0 {
			t.Error("static INFO unexpectedly contains export_grant")
		}
	})
}

// The destination subscription cannot itself create source-namespace interest.
// Delivery therefore proves that the virtual mapping carries a future prefix.
func TestAuthGrantLeafMappingFuturePrefixMessages(t *testing.T) {
	hook := &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict {
		return &authverify.GrantVerdict{Generation: 1, Grant: authverify.Grant{
			Pub:  authverify.SubjectGrant{AllowPrefix: []string{"out.device-*.>"}},
			Sub:  authverify.SubjectGrant{Allow: []string{">"}},
			Resp: &jwt.ResponsePermission{MaxMsgs: 1, Expires: time.Second},
		}, Done: func(bool) {}}
	}}
	f := newGrantFixture(t, hook, func(ac *jwt.AccountClaims, _ *jwt.UserScope) {
		ac.AddMapping("out.>", jwt.WeightedMapping{Subject: "destination.>"})
	})
	hub := grantTransportCloneHub(t, f, hook, true)
	hubClient, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
	require_NoError(t, err)
	defer hubClient.Close()
	sub, err := hubClient.SubscribeSync("destination.>")
	require_NoError(t, err)
	require_NoError(t, hubClient.Flush())
	leaf := grantTransportLeaf(t, grantTransportCredentials(t, f, false), hub)
	checkLeafNodeConnected(t, hub)
	checkLeafNodeConnected(t, leaf)
	leafClient, err := nats.Connect(leaf.ClientURL(), nats.NoReconnect())
	require_NoError(t, err)
	defer leafClient.Close()
	checkAccountLeafInterest(t, leaf, globalAccountName, "out.device-123.value")
	id := authGrantSingleLeafID(t, hub)
	require_NoError(t, leafClient.Publish("out.device-123.value", []byte("mapped future prefix")))
	require_NoError(t, leafClient.Flush())
	message, err := sub.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, message.Subject, "destination.device-123.value")
	require_Equal(t, string(message.Data), "mapped future prefix")
	require_Equal(t, authGrantSingleLeafID(t, hub), id)
	t.Logf("future prefix delivered out.device-123.value -> %s with accepted leaf CID %d unchanged", message.Subject, id)
}

func authGrantSingleLeafID(t *testing.T, s *Server) uint64 {
	t.Helper()
	z, err := s.Leafz(nil)
	require_NoError(t, err)
	if z.NumLeafs != 1 || len(z.Leafs) != 1 {
		t.Fatalf("expected one leaf, got %d", z.NumLeafs)
	}
	return z.Leafs[0].ID
}

func TestAuthGrantLeafOrdinaryWildcardInterestConfined(t *testing.T) {
	for _, initial := range []bool{true, false} {
		t.Run(fmt.Sprintf("initial=%t/raw", initial), func(t *testing.T) {
			hook := authGrantOrdinaryInterestHook()
			f := newGrantFixture(t, hook)
			hub := grantTransportCloneHub(t, f, hook, true)
			hubClient, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
			require_NoError(t, err)
			defer hubClient.Close()
			var sub *nats.Subscription
			if initial {
				sub, err = hubClient.SubscribeSync("out.>")
				require_NoError(t, err)
				require_NoError(t, hubClient.Flush())
			}
			conn, reader := authGrantRawLeaf(t, hub, f.creds(t, f.signer, true, "", 0))
			lines := authGrantLeafUntilPong(t, reader)
			if !initial {
				authGrantRequireInterestRows(t, lines, "LS+", "out.", nil)
				sub, err = hubClient.SubscribeSync("out.>")
				require_NoError(t, err)
				require_NoError(t, hubClient.Flush())
				_, err = fmt.Fprint(conn, "PING\r\n")
				require_NoError(t, err)
				lines = authGrantLeafUntilPong(t, reader)
			}
			authGrantRequireInterestRows(t, lines, "LS+", "out.", []string{"out.allowed"})
			require_NoError(t, sub.Unsubscribe())
			require_NoError(t, hubClient.Flush())
			_, err = fmt.Fprint(conn, "PING\r\n")
			require_NoError(t, err)
			authGrantRequireInterestRows(t, authGrantLeafUntilPong(t, reader), "LS-", "out.", []string{"out.allowed"})
		})
		t.Run(fmt.Sprintf("initial=%t/real_spoke", initial), func(t *testing.T) {
			hook := authGrantOrdinaryInterestHook()
			f := newGrantFixture(t, hook)
			hub := grantTransportCloneHub(t, f, hook, true)
			hubClient, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
			require_NoError(t, err)
			defer hubClient.Close()
			var unknown atomic.Int32
			install := func() *nats.Subscription {
				sub, err := hubClient.Subscribe("out.>", func(m *nats.Msg) {
					if m.Subject == "out.unknown" {
						unknown.Add(1)
					}
					m.Respond(m.Data)
				})
				require_NoError(t, err)
				require_NoError(t, hubClient.Flush())
				return sub
			}
			var sub *nats.Subscription
			if initial {
				sub = install()
			}
			leaf := grantTransportLeaf(t, grantTransportCredentials(t, f, false), hub)
			checkLeafNodeConnected(t, hub)
			checkLeafNodeConnected(t, leaf)
			if !initial {
				sub = install()
			}
			defer sub.Unsubscribe()
			leafClient, err := nats.Connect(leaf.ClientURL(), nats.NoReconnect())
			require_NoError(t, err)
			defer leafClient.Close()
			checkAccountLeafInterest(t, leaf, globalAccountName, "out.allowed")
			id := authGrantSingleLeafID(t, hub)
			z, err := leaf.Leafz(&LeafzOptions{Subscriptions: true})
			require_NoError(t, err)
			var interest []string
			for _, subject := range z.Leafs[0].Subs {
				if strings.HasPrefix(subject, "out.") {
					interest = append(interest, subject)
				}
			}
			slices.Sort(interest)
			t.Logf("real spoke received out. interest: %q; accepted hub CID %d", interest, id)
			if !slices.Equal(interest, []string{"out.allowed"}) {
				t.Errorf("ordinary wildcard interest = %q, want [out.allowed]", interest)
			}
			// Prove the unknown branch exists on the same single callback, then
			// finish it before the denied call. Both later barriers use that
			// callback too; the spoke barrier traverses the tested leaf link.
			control, err := hubClient.Request("out.unknown", []byte("unknown handler control"), time.Second)
			require_NoError(t, err)
			require_Equal(t, string(control.Data), "unknown handler control")
			require_Equal(t, unknown.Load(), int32(1))
			allowed, err := leafClient.Request("out.allowed", []byte("initial allowed barrier"), time.Second)
			require_NoError(t, err)
			require_Equal(t, string(allowed.Data), "initial allowed barrier")
			_, deniedErr := leafClient.Request("out.unknown", []byte("denied call"), 300*time.Millisecond)
			t.Logf("out.unknown request result: %v", deniedErr)
			if deniedErr != nats.ErrNoResponders {
				t.Errorf("out.unknown request = %v, want %v", deniedErr, nats.ErrNoResponders)
			}
			barrier, barrierErr := leafClient.Request("out.allowed", []byte("post-denial ordered barrier"), time.Second)
			if barrierErr != nil {
				t.Errorf("same-handler spoke barrier failed: %v", barrierErr)
			} else if string(barrier.Data) != "post-denial ordered barrier" {
				t.Errorf("same-handler spoke barrier payload = %q", barrier.Data)
			} else {
				t.Log("post-denial ordered barrier completed on same out.> callback")
			}
			if got := unknown.Load(); got != 1 {
				t.Errorf("denied unknown handler calls = %d, want 0", got-1)
			}
			checkLeafNodeConnected(t, hub)
			after := authGrantSingleLeafID(t, hub)
			t.Logf("accepted hub leaf CID before=%d after=%d; denied unknown handler calls=%d", id, after, unknown.Load()-1)
			if after != id {
				t.Errorf("accepted leaf CID changed from %d to %d", id, after)
			}
			require_NoError(t, sub.Unsubscribe())
			require_NoError(t, hubClient.Flush())
			checkFor(t, time.Second, 10*time.Millisecond, func() error {
				z, err := leaf.Leafz(&LeafzOptions{Subscriptions: true})
				if err != nil {
					return err
				}
				if len(z.Leafs) != 1 {
					return fmt.Errorf("expected one spoke link")
				}
				for _, subject := range z.Leafs[0].Subs {
					if strings.HasPrefix(subject, "out.") {
						return fmt.Errorf("interest retained after removal: %s", subject)
					}
				}
				return nil
			})
		})
	}
}

func authGrantOrdinaryInterestHook() *testGrantHook {
	return &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict {
		return &authverify.GrantVerdict{Generation: 1, Grant: authverify.Grant{
			Pub:  authverify.SubjectGrant{Allow: []string{"out.allowed"}},
			Sub:  authverify.SubjectGrant{Allow: []string{">"}},
			Resp: &jwt.ResponsePermission{MaxMsgs: 1, Expires: time.Second},
		}, Done: func(bool) {}}
	}}
}

func authGrantInfoFields(t *testing.T, lines []string) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	for _, line := range lines {
		if strings.HasPrefix(line, "INFO ") {
			var next map[string]json.RawMessage
			require_NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(line, "INFO ")), &next))
			if next["export"] != nil || next["export_grant"] != nil {
				fields = next
			}
		}
	}
	return fields
}

func authGrantRequireJSON(t *testing.T, raw json.RawMessage, want string) {
	t.Helper()
	var got, expected any
	if len(raw) == 0 {
		t.Errorf("missing INFO field, want %s", want)
		return
	}
	require_NoError(t, json.Unmarshal(raw, &got))
	require_NoError(t, json.Unmarshal([]byte(want), &expected))
	g, err := json.Marshal(got)
	require_NoError(t, err)
	w, err := json.Marshal(expected)
	require_NoError(t, err)
	if string(g) != string(w) {
		t.Errorf("INFO field = %s, want %s", g, w)
	}
}

func TestAuthGrantLeafImportPrefixSupersetInterest(t *testing.T) {
	hook := authGrantInterestHook(authverify.Grant{
		Pub: authverify.SubjectGrant{Allow: []string{"out.allowed"}},
		Sub: authverify.SubjectGrant{AllowPrefix: []string{"in.device-*.>"}},
	})
	f := newGrantFixture(t, hook)
	hub := grantTransportCloneHub(t, f, hook, true)
	conn, reader := authGrantRawLeaf(t, hub, f.creds(t, f.signer, true, "", 0))
	fields := authGrantInfoFields(t, authGrantLeafUntilPong(t, reader))
	authGrantRequireJSON(t, fields["import"], `{"allow":["in.*.>"]}`)
	id := authGrantSingleLeafID(t, hub)
	_, err := fmt.Fprint(conn, "LS+ in.device-123.value\r\nPING\r\n")
	require_NoError(t, err)
	authGrantLeafUntilPong(t, reader)
	checkAccountLeafInterest(t, hub, f.acc.Name, "in.device-123.value")
	t.Logf("allowed literal interest accepted with hub CID %d", id)
	_, err = fmt.Fprint(conn, "LS+ in.other.value\r\nPING\r\n")
	require_NoError(t, err)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Errorf("Import-superset literal closed accepted leaf %d: %v", id, err)
			return
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-ERR") {
			t.Errorf("Import-superset literal rejected by closing accepted leaf %d: %s", id, line)
			return
		}
		if line == "PONG" {
			break
		}
	}
	require_Equal(t, authGrantSingleLeafID(t, hub), id)
	acc, err := hub.LookupAccount(f.acc.Name)
	require_NoError(t, err)
	if result := acc.sl.Match("in.other.value"); len(result.psubs) != 0 {
		t.Error("Import-superset literal retained unauthorized hub interest")
	}
}

func authGrantInterestHook(grant authverify.Grant) *testGrantHook {
	return &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict {
		return &authverify.GrantVerdict{Generation: 1, Grant: grant, Done: func(bool) {}}
	}}
}

func TestAuthGrantLeafPrefixSupersetLocalReject(t *testing.T) {
	for _, response := range []bool{false, true} {
		t.Run(fmt.Sprintf("response=%t", response), func(t *testing.T) {
			grant := authverify.Grant{Pub: authverify.SubjectGrant{AllowPrefix: []string{"out.device-*.>"}}, Sub: authverify.SubjectGrant{Allow: []string{">"}}}
			if response {
				grant.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: time.Second}
			}
			hook := authGrantInterestHook(grant)
			f := newGrantFixture(t, hook, func(ac *jwt.AccountClaims, _ *jwt.UserScope) {
				ac.AddMapping("out.>", jwt.WeightedMapping{Subject: "destination.>"})
			})
			hub := grantTransportCloneHub(t, f, hook, true)
			t.Run("raw", func(t *testing.T) {
				_, reader := authGrantRawLeaf(t, hub, f.creds(t, f.signer, true, "", 0))
				authGrantRequireInterestRows(t, authGrantLeafUntilPong(t, reader), "LS+", "out.", []string{"out.*.>"})
			})
			checkFor(t, time.Second, time.Millisecond, func() error {
				z, err := hub.Leafz(nil)
				if err == nil && z.NumLeafs != 0 {
					return fmt.Errorf("raw leaf remains connected")
				}
				return err
			})
			hubClient, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
			require_NoError(t, err)
			defer hubClient.Close()
			var denied atomic.Int32
			_, err = hubClient.Subscribe("destination.>", func(m *nats.Msg) {
				if m.Subject != "destination.device-123.value" {
					denied.Add(1)
				}
				m.Respond(m.Data)
			})
			require_NoError(t, err)
			require_NoError(t, hubClient.Flush())
			for _, subject := range []string{"out.device-.value", "out.other.value"} {
				m, err := hubClient.Request(subject, []byte("handler control"), time.Second)
				require_NoError(t, err)
				require_Equal(t, string(m.Data), "handler control")
			}
			require_Equal(t, denied.Load(), int32(2))
			leaf := grantTransportLeaf(t, grantTransportCredentials(t, f, false), hub)
			checkLeafNodeConnected(t, hub)
			checkLeafNodeConnected(t, leaf)
			nc, err := nats.Connect(leaf.ClientURL(), nats.NoReconnect())
			require_NoError(t, err)
			defer nc.Close()
			checkAccountLeafInterest(t, leaf, globalAccountName, "out.device-123.value")
			id := authGrantSingleLeafID(t, hub)
			initial, err := nc.Request("out.device-123.value", []byte("initial allowed barrier"), time.Second)
			require_NoError(t, err)
			require_Equal(t, string(initial.Data), "initial allowed barrier")
			for _, subject := range []string{"out.device-.value", "out.other.value"} {
				_, err := nc.Request(subject, []byte("denied publication"), 300*time.Millisecond)
				t.Logf("%s result: %v", subject, err)
				if err != nats.ErrNoResponders {
					t.Errorf("%s result = %v, want %v", subject, err, nats.ErrNoResponders)
				}
				barrier, err := nc.Request("out.device-123.value", []byte("future prefix barrier"), time.Second)
				if err != nil {
					t.Errorf("future-prefix barrier: %v", err)
				} else {
					require_Equal(t, string(barrier.Data), "future prefix barrier")
				}
				checkLeafNodeConnected(t, hub)
				after := authGrantSingleLeafID(t, hub)
				t.Logf("accepted leaf CID before=%d after=%d", id, after)
				if after != id {
					t.Errorf("accepted leaf CID changed from %d to %d", id, after)
				}
			}
			require_Equal(t, denied.Load(), int32(2))
		})
	}
}

func TestAuthGrantLeafResponseOutsidePubThroughSpoke(t *testing.T) {
	hook := authGrantInterestHook(authverify.Grant{
		Pub:  authverify.SubjectGrant{Allow: []string{"out.allowed"}},
		Sub:  authverify.SubjectGrant{Allow: []string{"service"}},
		Resp: &jwt.ResponsePermission{MaxMsgs: 1, Expires: time.Second},
	})
	f := newGrantFixture(t, hook)
	hub := grantTransportCloneHub(t, f, hook, true)
	hubClient, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
	require_NoError(t, err)
	defer hubClient.Close()
	const inbox = "_INBOX.f8.finite.reply"
	replies, err := hubClient.SubscribeSync(inbox)
	require_NoError(t, err)
	require_NoError(t, hubClient.Flush())
	leaf := grantTransportLeaf(t, grantTransportCredentials(t, f, false), hub)
	checkLeafNodeConnected(t, hub)
	checkLeafNodeConnected(t, leaf)
	nc, err := nats.Connect(leaf.ClientURL(), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	_, err = nc.Subscribe("service", func(m *nats.Msg) { m.Respond([]byte("finite response outside Pub")) })
	require_NoError(t, err)
	require_NoError(t, nc.Flush())
	checkAccountLeafInterest(t, hub, f.acc.Name, "service")
	id := authGrantSingleLeafID(t, hub)
	require_NoError(t, hubClient.PublishRequest("service", inbox, []byte("request")))
	require_NoError(t, hubClient.Flush())
	m, err := replies.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, string(m.Data), "finite response outside Pub")
	require_Equal(t, authGrantSingleLeafID(t, hub), id)
}

func authGrantInterestBarrier(t *testing.T, conn net.Conn, reader *bufio.Reader, nc *nats.Conn) []string {
	t.Helper()
	if nc != nil {
		require_NoError(t, nc.Flush())
	}
	_, err := fmt.Fprint(conn, "PING\r\n")
	require_NoError(t, err)
	return authGrantLeafUntilPong(t, reader)
}

func authGrantExactProtocolRows(lines []string, prefix string) []string {
	var rows []string
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 1 && (fields[0] == "LS+" || fields[0] == "LS-") && strings.HasPrefix(fields[1], prefix) {
			rows = append(rows, strings.Join(fields, " "))
		}
	}
	return rows
}

func authGrantRequireProtocolRows(t *testing.T, lines []string, want ...string) {
	t.Helper()
	got := authGrantExactProtocolRows(lines, "out.")
	if !slices.Equal(got, want) {
		t.Fatalf("interest updates = %q, want %q", got, want)
	}
}

func TestAuthGrantLeafInterestContributions(t *testing.T) {
	for _, name := range []string{"ordinary_overlap", "accepted_hub", "queue_weights", "mapping_subscription", "mapping_idempotent", "service_mapping_remove_service_first", "service_mapping_remove_mapping_first", "delayed_mapping_add", "delayed_mapping_remove", "reinstall"} {
		t.Run(name, func(t *testing.T) {
			hook := authGrantOrdinaryInterestHook()
			f := newGrantFixture(t, hook)
			hub := grantTransportCloneHub(t, f, hook, true)
			nc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
			require_NoError(t, err)
			defer nc.Close()
			acc, err := hub.LookupAccount(f.acc.Name)
			require_NoError(t, err)
			var exporter *Account
			if strings.HasPrefix(name, "service_") {
				exporter, err = hub.RegisterAccount("F8_EXPORTER")
				require_NoError(t, err)
				require_NoError(t, exporter.AddServiceExport("remote", nil))
				require_NoError(t, acc.AddServiceImport(exporter, "out.allowed", "remote"))
				require_NoError(t, acc.AddMapping("out.allowed", "destination.allowed"))
			}
			conn, reader := authGrantRawLeaf(t, hub, f.creds(t, f.signer, true, "", 0), name == "accepted_hub")
			initial := authGrantLeafUntilPong(t, reader)
			c := hub.grantClient(authGrantSingleLeafID(t, hub))
			require_True(t, c != nil)
			switch name {
			case "ordinary_overlap", "accepted_hub":
				broad, err := nc.SubscribeSync("out.>")
				require_NoError(t, err)
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc), "LS+ out.allowed")
				exact, err := nc.SubscribeSync("out.allowed")
				require_NoError(t, err)
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc))
				require_NoError(t, broad.Unsubscribe())
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc))
				require_NoError(t, exact.Unsubscribe())
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc), "LS- out.allowed")
			case "queue_weights":
				one, err := nc.QueueSubscribeSync("out.>", "workers")
				require_NoError(t, err)
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc), "LS+ out.allowed workers 1")
				two, err := nc.QueueSubscribeSync("out.allowed", "workers")
				require_NoError(t, err)
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc), "LS+ out.allowed workers 2")
				require_NoError(t, one.Unsubscribe())
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc), "LS+ out.allowed workers 1")
				require_NoError(t, two.Unsubscribe())
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc), "LS- out.allowed workers")
			case "mapping_subscription", "mapping_idempotent":
				require_NoError(t, acc.AddMapping("out.allowed", "destination.allowed"))
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc), "LS+ out.allowed")
				var sub *nats.Subscription
				if name == "mapping_subscription" {
					sub, err = nc.SubscribeSync("out.allowed")
					require_NoError(t, err)
				} else {
					require_NoError(t, acc.AddMapping("out.allowed", "destination.allowed"))
				}
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc))
				require_True(t, acc.RemoveMapping("out.allowed"))
				if sub == nil {
					authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc), "LS- out.allowed")
				} else {
					authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc))
					require_NoError(t, sub.Unsubscribe())
					authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc), "LS- out.allowed")
				}
			case "service_mapping_remove_service_first", "service_mapping_remove_mapping_first":
				authGrantRequireProtocolRows(t, initial, "LS+ out.allowed")
				if strings.HasSuffix(name, "service_first") {
					acc.removeServiceImport(exporter.Name, "out.allowed")
				} else {
					require_True(t, acc.RemoveMapping("out.allowed"))
				}
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc))
				if strings.HasSuffix(name, "service_first") {
					require_True(t, acc.RemoveMapping("out.allowed"))
				} else {
					acc.removeServiceImport(exporter.Name, "out.allowed")
				}
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc), "LS- out.allowed")
			case "delayed_mapping_add":
				require_NoError(t, acc.AddMapping("out.allowed", "destination.allowed"))
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc), "LS+ out.allowed")
				require_True(t, acc.RemoveMapping("out.allowed"))
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc), "LS- out.allowed")
				c.forceAddToSmap("out.allowed")
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc))
			case "delayed_mapping_remove":
				require_NoError(t, acc.AddMapping("out.allowed", "destination.allowed"))
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc), "LS+ out.allowed")
				c.forceRemoveFromSmap("out.allowed")
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc))
			case "reinstall":
				subscription, err := nc.SubscribeSync("out.>")
				require_NoError(t, err)
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc), "LS+ out.allowed")
				p, pub, sub, err := compileAuthGrant(authverify.Grant{Pub: authverify.SubjectGrant{Allow: []string{"out.narrow"}}, Sub: authverify.SubjectGrant{Allow: []string{">"}}})
				require_NoError(t, err)
				c.mu.Lock()
				c.installAuthGrant(p, pub, sub)
				c.mu.Unlock()
				rows := authGrantExactProtocolRows(authGrantInterestBarrier(t, conn, reader, nc), "out.")
				slices.Sort(rows)
				require_Equal(t, strings.Join(rows, ";"), "LS+ out.narrow;LS- out.allowed")
				require_NoError(t, subscription.Unsubscribe())
				authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc), "LS- out.narrow")
			}
		})
	}
}

func TestAuthGrantLeafInterestInitUpdateRace(t *testing.T) {
	hook := authGrantOrdinaryInterestHook()
	f := newGrantFixture(t, hook)
	hub := grantTransportCloneHub(t, f, hook, true)
	nc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	acc, err := hub.LookupAccount(f.acc.Name)
	require_NoError(t, err)
	for iteration := 0; iteration < 50; iteration++ {
		t.Run(fmt.Sprintf("iteration=%02d", iteration), func(t *testing.T) {
			start := make(chan struct{})
			errors := make(chan error, 2)
			go func() {
				<-start
				for i := 0; i < 8; i++ {
					sub, err := nc.SubscribeSync("out.>")
					if err != nil {
						errors <- err
						return
					}
					if err := sub.Unsubscribe(); err != nil {
						errors <- err
						return
					}
				}
				errors <- nc.Flush()
			}()
			go func() {
				<-start
				for i := 0; i < 8; i++ {
					if err := acc.AddMapping("out.allowed", "destination.allowed"); err != nil {
						errors <- err
						return
					}
					acc.RemoveMapping("out.allowed")
				}
				errors <- nil
			}()
			close(start)
			conn, reader := authGrantRawLeaf(t, hub, f.creds(t, f.signer, true, "", 0))
			lines := authGrantLeafUntilPong(t, reader)
			require_NoError(t, <-errors)
			require_NoError(t, <-errors)
			sub, err := nc.SubscribeSync("out.allowed")
			require_NoError(t, err)
			lines = append(lines, authGrantInterestBarrier(t, conn, reader, nc)...)
			state := make(map[string]bool)
			for _, line := range authGrantExactProtocolRows(lines, "out.") {
				fields := strings.Fields(line)
				if fields[0] == "LS+" {
					state[fields[1]] = true
				} else {
					if !state[fields[1]] {
						t.Errorf("removal without positive contribution: %s", line)
					}
					delete(state, fields[1])
				}
			}
			if len(state) != 1 || !state["out.allowed"] {
				t.Errorf("final net rows = %v, want out.allowed only", state)
			}
			require_NoError(t, sub.Unsubscribe())
			authGrantRequireProtocolRows(t, authGrantInterestBarrier(t, conn, reader, nc), "LS- out.allowed")
			require_NoError(t, conn.Close())
			checkFor(t, time.Second, time.Millisecond, func() error {
				z, err := hub.Leafz(nil)
				if err == nil && z.NumLeafs != 0 {
					return fmt.Errorf("prior raw leaf remains")
				}
				return err
			})
		})
	}
}

func TestAuthGrantLeafExportGrantCompatibility(t *testing.T) {
	for _, test := range []struct {
		name, field string
		invalid     bool
	}{
		{"missing_allow", `{}`, false},
		{"null_allow", `{"allow":null}`, false},
		{"empty_allow", `{"allow":[]}`, false},
		{"null_field", `null`, true},
		{"array_field", `[]`, true},
		{"string_field", `"invalid"`, true},
		{"string_allow", `{"allow":">"}`, true},
		{"string_deny", `{"allow":[],"deny":"out.blocked"}`, true},
		{"string_prefix", `{"allow":[],"allow_prefix":"out.device-*"}`, true},
		{"invalid_allow", `{"allow":["out..invalid"]}`, true},
		{"invalid_deny", `{"allow":[">"],"deny":["out..invalid"]}`, true},
		{"invalid_prefix", `{"allow":[],"allow_prefix":["out.*middle"]}`, true},
		{"legacy_no_field", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			hook := authGrantInterestHook(grantAll())
			f := newGrantFixture(t, hook)
			hub := grantTransportCloneHub(t, f, hook, true)
			hc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
			require_NoError(t, err)
			defer hc.Close()
			_, err = hc.Subscribe("out.>", func(m *nats.Msg) { m.Respond([]byte("legacy response")) })
			require_NoError(t, err)
			require_NoError(t, hc.Flush())
			leaf := grantTransportLeaf(t, grantTransportCredentials(t, f, true), hub)
			checkLeafNodeConnected(t, hub)
			checkLeafNodeConnected(t, leaf)
			id := authGrantSingleLeafID(t, hub)
			peer := hub.GetLeafNode(id)
			require_True(t, peer != nil)
			info := `{"import":{"allow":[">"]},"export":{"allow":[">"]}`
			if test.field != "" {
				info += `,"export_grant":` + test.field
			}
			info += `}`
			peer.mu.Lock()
			peer.enqueueProto([]byte("INFO " + info + "\r\nLS+ sync.f8.barrier\r\n"))
			peer.mu.Unlock()
			if test.invalid {
				checkFor(t, time.Second, time.Millisecond, func() error {
					if hub.GetLeafNode(id) != nil {
						return fmt.Errorf("invalid export_grant retained original accepted CID %d", id)
					}
					return nil
				})
				return
			}
			checkAccountLeafInterest(t, leaf, globalAccountName, "sync.f8.barrier")
			nc, err := nats.Connect(leaf.ClientURL(), nats.NoReconnect())
			require_NoError(t, err)
			defer nc.Close()
			m, err := nc.Request("out.probe", nil, 300*time.Millisecond)
			if test.field == "" {
				require_NoError(t, err)
				require_Equal(t, string(m.Data), "legacy response")
			} else if err != nats.ErrNoResponders {
				t.Errorf("empty exact authority request = %v, want %v", err, nats.ErrNoResponders)
			}
			require_Equal(t, authGrantSingleLeafID(t, hub), id)
		})
	}
}

func TestAuthGrantLeafImportPrefixSupersetRealSpoke(t *testing.T) {
	hook := authGrantInterestHook(authverify.Grant{
		Pub: authverify.SubjectGrant{Allow: []string{"out.barrier"}},
		Sub: authverify.SubjectGrant{AllowPrefix: []string{"in.device-*.>"}, Allow: []string{"_INBOX.>"}},
	})
	f := newGrantFixture(t, hook)
	hub := grantTransportCloneHub(t, f, hook, true)
	hc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
	require_NoError(t, err)
	defer hc.Close()
	_, err = hc.Subscribe("out.barrier", func(m *nats.Msg) { m.Respond(m.Data) })
	require_NoError(t, err)
	require_NoError(t, hc.Flush())
	leaf := grantTransportLeaf(t, grantTransportCredentials(t, f, false), hub)
	checkLeafNodeConnected(t, hub)
	checkLeafNodeConnected(t, leaf)
	nc, err := nats.Connect(leaf.ClientURL(), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	allowed, err := nc.SubscribeSync("in.device-123.value")
	require_NoError(t, err)
	require_NoError(t, nc.Flush())
	checkAccountLeafInterest(t, hub, f.acc.Name, "in.device-123.value")
	require_NoError(t, hc.Publish("in.device-123.value", []byte("allowed delivery")))
	require_NoError(t, hc.Flush())
	m, err := allowed.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, string(m.Data), "allowed delivery")
	checkAccountLeafInterest(t, leaf, globalAccountName, "out.barrier")
	id := authGrantSingleLeafID(t, hub)
	_, err = nc.SubscribeSync("in.other.value")
	require_NoError(t, err)
	require_NoError(t, nc.Flush())
	barrier, err := nc.Request("out.barrier", []byte("ordered subscription barrier"), time.Second)
	if err != nil {
		t.Errorf("post-subscription barrier failed: %v", err)
	} else {
		require_Equal(t, string(barrier.Data), "ordered subscription barrier")
	}
	checkLeafNodeConnected(t, hub)
	after := authGrantSingleLeafID(t, hub)
	t.Logf("real spoke local Import-superset subscription accepted CID before=%d after=%d", id, after)
	if after != id {
		t.Errorf("local subscription outside exact Sub prefix changed accepted CID %d -> %d", id, after)
	}
}

func TestAuthGrantLeafReconnectNarrowedInterest(t *testing.T) {
	var narrow atomic.Bool
	requests := make(chan *authverify.GrantRequest, 4)
	hook := &testGrantHook{verify: func(r *authverify.GrantRequest) *authverify.GrantVerdict {
		requests <- r
		subject := "out.allowed"
		if narrow.Load() {
			subject = "out.narrow"
		}
		return &authverify.GrantVerdict{Generation: 1, Grant: authverify.Grant{Pub: authverify.SubjectGrant{Allow: []string{subject}}, Sub: authverify.SubjectGrant{Allow: []string{">"}}}, Done: func(bool) {}}
	}}
	f := newGrantFixture(t, hook)
	hub := grantTransportCloneHub(t, f, hook, true)
	nc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	_, err = nc.SubscribeSync("out.>")
	require_NoError(t, err)
	require_NoError(t, nc.Flush())
	credentials := f.creds(t, f.signer, true, "", 0)
	conn, reader := authGrantRawLeaf(t, hub, credentials)
	first := grantRecv(t, requests)
	authGrantRequireInterestRows(t, authGrantLeafUntilPong(t, reader), "LS+", "out.", []string{"out.allowed"})
	narrow.Store(true)
	require_NoError(t, hub.UpdateClientGrant(authverify.GrantUpdate{ClientID: first.Client.ID, Account: first.Account, UserNkey: first.UserNkey, Generation: 2, Grant: authverify.Grant{Pub: authverify.SubjectGrant{Allow: []string{"out.narrow"}}, Sub: authverify.SubjectGrant{Allow: []string{">"}}}}))
	grantTransportClosedReason(t, hub, first.Client.ID, AuthorizationChanged)
	require_NoError(t, conn.Close())
	_, reader = authGrantRawLeaf(t, hub, credentials)
	second := grantRecv(t, requests)
	require_True(t, second.Client.ID != first.Client.ID)
	authGrantRequireInterestRows(t, authGrantLeafUntilPong(t, reader), "LS+", "out.", []string{"out.narrow"})
}

func TestAuthGrantLeafGatewayLiteralReplyDeny(t *testing.T) {
	for _, mode := range []string{"allow_control", "exact_deny", "remote_deny"} {
		t.Run(mode, func(t *testing.T) {
			hook := authGrantInterestHook(grantAll())
			f := newGrantFixture(t, hook)
			hub := grantTransportCloneHub(t, f, hook, true)
			remoteURL, err := url.Parse(fmt.Sprintf("nats://127.0.0.1:%d", hub.getOpts().LeafNode.Port))
			require_NoError(t, err)
			opts := DefaultOptions()
			opts.Host, opts.Port = "127.0.0.1", -1
			opts.LeafNode.Host, opts.LeafNode.Port = "127.0.0.1", -1
			remote := &RemoteLeafOpts{URLs: []*url.URL{remoteURL}, Credentials: grantTransportCredentials(t, f, true)}
			if mode == "remote_deny" {
				remote.DenyExports = []string{"out.blocked"}
			}
			opts.LeafNode.Remotes = []*RemoteLeafOpts{remote}
			leaf := RunServer(opts)
			t.Cleanup(leaf.Shutdown)
			checkLeafNodeConnected(t, hub)
			checkLeafNodeConnected(t, leaf)
			id := authGrantSingleLeafID(t, hub)
			peer := hub.GetLeafNode(id)
			require_True(t, peer != nil)
			raw := gwReplyPrefix + strings.Repeat("A", gwHashLen) + "." + strings.Repeat("B", gwHashLen) + ".out.blocked"
			exact := `{"allow":[]}`
			if mode == "exact_deny" {
				exact = `{"allow":[],"deny":["out.blocked"]}`
			}
			peer.mu.Lock()
			peer.enqueueProto([]byte(`INFO {"import":{"allow":[">"]},"export":{"allow":[">"]},"export_grant":` + exact + "}\r\nLS+ " + raw + "\r\nLS+ sync.f8.gateway\r\n"))
			peer.mu.Unlock()
			checkAccountLeafInterest(t, leaf, globalAccountName, "sync.f8.gateway")
			checkAccountLeafInterest(t, leaf, globalAccountName, raw)
			origin, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", leaf.getOpts().LeafNode.Port), time.Second)
			require_NoError(t, err)
			defer origin.Close()
			require_NoError(t, origin.SetDeadline(time.Now().Add(3*time.Second)))
			reader := bufio.NewReader(origin)
			_, err = reader.ReadString('\n')
			require_NoError(t, err)
			_, err = fmt.Fprint(origin, "CONNECT {\"name\":\"f8-origin\"}\r\nPING\r\n")
			require_NoError(t, err)
			authGrantLeafUntilPong(t, reader)
			outgoing := func() int64 {
				leaf.mu.RLock()
				var peers []*client
				for _, c := range leaf.leafs {
					peers = append(peers, c)
				}
				leaf.mu.RUnlock()
				for _, c := range peers {
					c.mu.Lock()
					if c.isSolicitedLeafNode() {
						value := c.outMsgs
						c.mu.Unlock()
						return value
					}
					c.mu.Unlock()
				}
				t.Fatal("solicited hub link absent")
				return 0
			}
			before := outgoing()
			_, err = fmt.Fprintf(origin, "LMSG %s 7\r\npayload\r\nPING\r\n", raw)
			require_NoError(t, err)
			authGrantLeafUntilPong(t, reader)
			after := outgoing()
			if mode == "allow_control" {
				require_Equal(t, after, before+1)
			} else {
				require_Equal(t, after, before)
			}
			require_Equal(t, authGrantSingleLeafID(t, hub), id)
		})
	}
}

func TestAuthGrantLeafLegacyInfoBytes(t *testing.T) {
	for _, mapping := range []bool{false, true} {
		t.Run(fmt.Sprintf("mapping=%t", mapping), func(t *testing.T) {
			grant := authverify.Grant{Pub: authverify.SubjectGrant{Allow: []string{"out.allowed"}}, Sub: authverify.SubjectGrant{Allow: []string{">"}}, Resp: &jwt.ResponsePermission{MaxMsgs: 1, Expires: time.Second}}
			wantImport := `{"allow":["\u003e"]}`
			wantExport := `{"allow":["\u003e"]}`
			if mapping {
				grant.Pub = authverify.SubjectGrant{Allow: []string{"map.allowed", "map.*.wild"}, Deny: []string{"map.secret.wild"}, AllowPrefix: []string{"map.device-*"}}
				grant.Sub = authverify.SubjectGrant{}
				wantImport = `{}`
				wantExport = `{"allow":["\u003e"],"deny":["map.secret.wild"]}`
			}
			hook := authGrantInterestHook(grant)
			f := newGrantFixture(t, hook)
			hub := grantTransportCloneHub(t, f, hook, true)
			_, reader := authGrantRawLeaf(t, hub, f.creds(t, f.signer, true, "", 0))
			fields := authGrantInfoFields(t, authGrantLeafUntilPong(t, reader))
			require_Equal(t, string(fields["import"]), wantImport)
			require_Equal(t, string(fields["export"]), wantExport)
			t.Logf("legacy INFO bytes Import=%s Export=%s", fields["import"], fields["export"])
		})
	}
}

func TestAuthGrantLeafPartialDenyInterest(t *testing.T) {
	hook := authGrantInterestHook(authverify.Grant{
		Pub:  authverify.SubjectGrant{Allow: []string{"out.>"}, Deny: []string{"out.*"}},
		Sub:  authverify.SubjectGrant{Allow: []string{">"}},
		Resp: &jwt.ResponsePermission{MaxMsgs: 1, Expires: time.Second},
	})
	f := newGrantFixture(t, hook)
	hub := grantTransportCloneHub(t, f, hook, true)
	hc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
	require_NoError(t, err)
	defer hc.Close()
	var denied atomic.Int32
	_, err = hc.Subscribe("out.>", func(m *nats.Msg) {
		if m.Subject == "out.value" {
			denied.Add(1)
		}
		m.Respond(m.Data)
	})
	require_NoError(t, err)
	require_NoError(t, hc.Flush())
	t.Run("raw", func(t *testing.T) {
		_, reader := authGrantRawLeaf(t, hub, f.creds(t, f.signer, true, "", 0))
		authGrantRequireInterestRows(t, authGrantLeafUntilPong(t, reader), "LS+", "out.", []string{"out.>"})
	})
	checkFor(t, time.Second, time.Millisecond, func() error {
		z, err := hub.Leafz(nil)
		if err == nil && z.NumLeafs != 0 {
			return fmt.Errorf("raw control remains")
		}
		return err
	})
	control, err := hc.Request("out.value", []byte("direct denied handler control"), time.Second)
	require_NoError(t, err)
	require_Equal(t, string(control.Data), "direct denied handler control")
	require_Equal(t, denied.Load(), int32(1))
	leaf := grantTransportLeaf(t, grantTransportCredentials(t, f, false), hub)
	checkLeafNodeConnected(t, hub)
	checkLeafNodeConnected(t, leaf)
	nc, err := nats.Connect(leaf.ClientURL(), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	checkAccountLeafInterest(t, leaf, globalAccountName, "out.deep.value")
	id := authGrantSingleLeafID(t, hub)
	initial, err := nc.Request("out.deep.value", []byte("initial deep allowed"), time.Second)
	require_NoError(t, err)
	require_Equal(t, string(initial.Data), "initial deep allowed")
	_, err = nc.Request("out.value", nil, 300*time.Millisecond)
	if err != nats.ErrNoResponders {
		t.Errorf("partial-deny request = %v, want %v", err, nats.ErrNoResponders)
	}
	barrier, err := nc.Request("out.deep.value", []byte("same callback ordered barrier"), time.Second)
	require_NoError(t, err)
	require_Equal(t, string(barrier.Data), "same callback ordered barrier")
	require_Equal(t, denied.Load(), int32(1))
	require_Equal(t, authGrantSingleLeafID(t, hub), id)
}

func TestAuthGrantLeafReinstallNilEmptyAllow(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty=%t", empty), func(t *testing.T) {
			hook := authGrantOrdinaryInterestHook()
			f := newGrantFixture(t, hook)
			hub := grantTransportCloneHub(t, f, hook, true)
			nc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
			require_NoError(t, err)
			defer nc.Close()
			_, err = nc.SubscribeSync("out.>")
			require_NoError(t, err)
			require_NoError(t, nc.Flush())
			conn, reader := authGrantRawLeaf(t, hub, f.creds(t, f.signer, true, "", 0))
			authGrantRequireInterestRows(t, authGrantLeafUntilPong(t, reader), "LS+", "out.", []string{"out.allowed"})
			id := authGrantSingleLeafID(t, hub)
			c := hub.grantClient(id)
			require_True(t, c != nil)
			p, pub, sub, err := compileAuthGrant(authverify.Grant{Sub: authverify.SubjectGrant{Allow: []string{"in.allowed"}}})
			require_NoError(t, err)
			if empty {
				p.Publish.Allow = []string{}
			} else {
				p.Publish.Allow = nil
			}
			c.mu.Lock()
			c.installAuthGrant(p, pub, sub)
			c.mu.Unlock()
			lines := authGrantInterestBarrier(t, conn, reader, nc)
			wantGrant := `{"allow":[">"]}`
			if empty {
				wantGrant = `{"allow":[]}`
			}
			authGrantRequireJSON(t, authGrantInfoFields(t, lines)["export_grant"], wantGrant)
			rows := authGrantExactProtocolRows(lines, "out.")
			slices.Sort(rows)
			want := []string{"LS+ out.>", "LS- out.allowed"}
			if empty {
				want = []string{"LS- out.allowed"}
			}
			if !slices.Equal(rows, want) {
				t.Errorf("reinstall rows = %q, want %q", rows, want)
			}
			require_Equal(t, authGrantSingleLeafID(t, hub), id)
		})
	}
}

func authGrantRawLeafWithDeny(t *testing.T, hub *Server, credentials nats.Option, deny []string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", hub.getOpts().LeafNode.Port), time.Second)
	require_NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require_NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	require_NoError(t, err)
	var info Info
	require_NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(line), "INFO ")), &info))
	opts := nats.GetDefaultOptions()
	require_NoError(t, credentials(&opts))
	token, err := opts.UserJWT()
	require_NoError(t, err)
	sig, err := opts.SignatureCB([]byte(info.Nonce))
	require_NoError(t, err)
	fields := map[string]any{"jwt": token, "sig": base64.RawURLEncoding.EncodeToString(sig), "name": "f8-transport-deny", "headers": true, "deny_pub": deny}
	data, err := json.Marshal(fields)
	require_NoError(t, err)
	_, err = fmt.Fprintf(conn, "CONNECT %s\r\nPING\r\n", data)
	require_NoError(t, err)
	return conn, reader
}

func authGrantLeafDeliveredPayloads(lines []string, prefix string) map[string]string {
	got := make(map[string]string)
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "LMSG" && strings.HasPrefix(fields[1], prefix) && i+1 < len(lines) {
			got[fields[1]] = lines[i+1]
		}
	}
	return got
}

func TestAuthGrantLeafReinstallRetainsTransportDeny(t *testing.T) {
	grant := authverify.Grant{Pub: authverify.SubjectGrant{Allow: []string{"out.>"}}, Sub: authverify.SubjectGrant{Allow: []string{"in.>"}, Deny: []string{"in.retired"}}}
	hook := authGrantInterestHook(grant)
	f := newGrantFixture(t, hook)
	hub := grantTransportCloneHub(t, f, hook, true)
	nc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
	require_NoError(t, err)
	defer nc.Close()
	conn, reader := authGrantRawLeafWithDeny(t, hub, f.creds(t, f.signer, true, "", 0), []string{"in.blocked"})
	authGrantLeafUntilPong(t, reader)
	id := authGrantSingleLeafID(t, hub)
	_, err = fmt.Fprint(conn, "LS+ in.>\r\nPING\r\n")
	require_NoError(t, err)
	authGrantLeafUntilPong(t, reader)
	for _, phase := range []string{"initial", "reinstalled", "grant_deny_removed"} {
		if phase != "initial" {
			next := grant
			if phase == "grant_deny_removed" {
				next.Sub.Deny = nil
			}
			p, pub, sub, err := compileAuthGrant(next)
			require_NoError(t, err)
			c := hub.grantClient(id)
			require_True(t, c != nil)
			c.mu.Lock()
			c.installAuthGrant(p, pub, sub)
			c.mu.Unlock()
			authGrantInterestBarrier(t, conn, reader, nc)
		}
		for _, subject := range []string{"in.blocked", "in.retired", "in.control"} {
			require_NoError(t, nc.Publish(subject, []byte(phase+" "+subject)))
		}
		got := authGrantLeafDeliveredPayloads(authGrantInterestBarrier(t, conn, reader, nc), "in.")
		t.Logf("%s delivery subjects: %v", phase, got)
		if got["in.control"] != phase+" in.control" {
			t.Errorf("%s allowed control missing: %v", phase, got)
		}
		if _, present := got["in.blocked"]; present {
			t.Errorf("%s leaked CONNECT transport-denied in.blocked", phase)
		}
		_, retired := got["in.retired"]
		if retired != (phase == "grant_deny_removed") {
			t.Errorf("%s retired grant deny delivery = %t", phase, retired)
		}
		require_Equal(t, authGrantSingleLeafID(t, hub), id)
	}
}

func TestAuthGrantLeafAsyncInfoRetainsJetStreamGuard(t *testing.T) {
	hook := authGrantInterestHook(grantAll())
	f := newGrantFixture(t, hook)
	hub := grantTransportCloneHub(t, f, hook, true)
	hc, err := nats.Connect(hub.ClientURL(), nats.UserCredentials(grantTransportCredentials(t, f, true)), nats.NoReconnect())
	require_NoError(t, err)
	defer hc.Close()
	control, err := hc.SubscribeSync("in.control")
	require_NoError(t, err)
	require_NoError(t, hc.Flush())
	remoteURL, err := url.Parse(fmt.Sprintf("nats://127.0.0.1:%d", hub.getOpts().LeafNode.Port))
	require_NoError(t, err)
	opts := DefaultOptions()
	opts.Host, opts.Port = "127.0.0.1", -1
	opts.ServerName = "F8SPOKE"
	opts.Cluster = ClusterOpts{}
	opts.JetStream, opts.JetStreamDomain, opts.StoreDir = true, "F8SPOKE", t.TempDir()
	opts.JetStreamMaxMemory, opts.JetStreamMaxStore = 64*1024*1024, 64*1024*1024
	opts.LeafNode.Host, opts.LeafNode.Port = "127.0.0.1", -1
	opts.LeafNode.Remotes = []*RemoteLeafOpts{{URLs: []*url.URL{remoteURL}, Credentials: grantTransportCredentials(t, f, false)}}
	leaf := RunServer(opts)
	t.Cleanup(leaf.Shutdown)
	checkLeafNodeConnected(t, hub)
	checkLeafNodeConnected(t, leaf)
	id := authGrantSingleLeafID(t, hub)
	peer := hub.GetLeafNode(id)
	require_True(t, peer != nil)
	raw := gwReplyPrefix + strings.Repeat("A", gwHashLen) + "." + strings.Repeat("B", gwHashLen) + ".$JS.F8SPOKE.API.F8"
	peer.mu.Lock()
	peer.enqueueProto([]byte("LS+ " + raw + "\r\nLS+ sync.f8.js.initial\r\n"))
	peer.mu.Unlock()
	checkAccountLeafInterest(t, leaf, globalAccountName, "sync.f8.js.initial")
	origin, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", leaf.getOpts().LeafNode.Port), time.Second)
	require_NoError(t, err)
	defer origin.Close()
	require_NoError(t, origin.SetDeadline(time.Now().Add(5*time.Second)))
	reader := bufio.NewReader(origin)
	_, err = reader.ReadString('\n')
	require_NoError(t, err)
	_, err = fmt.Fprint(origin, "CONNECT {\"name\":\"f8-js-origin\"}\r\nPING\r\n")
	require_NoError(t, err)
	authGrantLeafUntilPong(t, reader)
	outgoing := func() int64 {
		leaf.mu.RLock()
		var peers []*client
		for _, c := range leaf.leafs {
			peers = append(peers, c)
		}
		leaf.mu.RUnlock()
		for _, c := range peers {
			c.mu.Lock()
			if c.isSolicitedLeafNode() {
				n := c.outMsgs
				c.mu.Unlock()
				return n
			}
			c.mu.Unlock()
		}
		t.Fatal("solicited JetStream link absent")
		return 0
	}
	for _, phase := range []string{"initial", "updated"} {
		if phase == "updated" {
			peer.mu.Lock()
			peer.enqueueProto([]byte(`INFO {"import":{"allow":[">"]},"export":{"allow":[">"]},"export_grant":{"allow":[">"]}}` + "\r\nLS+ sync.f8.js.updated\r\n"))
			peer.mu.Unlock()
			checkAccountLeafInterest(t, leaf, globalAccountName, "sync.f8.js.updated")
		}
		before := outgoing()
		_, err = fmt.Fprintf(origin, "LMSG %s 7\r\nblocked\r\nLMSG in.control %d\r\n%s\r\nPING\r\n", raw, len(phase), phase)
		require_NoError(t, err)
		authGrantLeafUntilPong(t, reader)
		m, err := control.NextMsg(time.Second)
		require_NoError(t, err)
		require_Equal(t, string(m.Data), phase)
		after := outgoing()
		t.Logf("%s solicited outgoing message delta = %d, want one control", phase, after-before)
		if after != before+1 {
			t.Errorf("%s JetStream transport guard leaked blocked gateway-routed subject", phase)
		}
		require_Equal(t, authGrantSingleLeafID(t, hub), id)
	}
}
