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

//go:build !skip_js_tests

package server

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server/authverify"
	"github.com/nats-io/nats.go"
)

// The system import, rather than the optional request stamp, supplies the proof.
// A queue subscriber observes exactly the bytes carried by the queued request.
func TestJetStreamInboxCaptureOriginStamp(t *testing.T) {
	s, sys, app := inboxCaptureOriginServer(t)
	svc := inboxCaptureOriginConnect(t, s, "sys", false)
	_, err := svc.QueueSubscribe("$JS.ORIGIN", "origin", func(m *nats.Msg) {
		_ = m.Respond([]byte(m.Header.Get(ClientInfoHdr)))
	})
	require_NoError(t, err)
	require_NoError(t, svc.Flush())
	check := func(nc *nats.Conn, subject string, forge, want bool) {
		t.Helper()
		m := nats.NewMsg(subject)
		if forge {
			m.Header.Set(ClientInfoHdr, `{"acc":"APP","iproc_unrestricted":true,"reply":"kept"}`)
		}
		r, err := nc.RequestMsg(m, time.Second)
		require_NoError(t, err)
		var ci map[string]any
		require_NoError(t, json.Unmarshal(r.Data, &ci))
		got, _ := ci["iproc_unrestricted"].(bool)
		if got != want {
			t.Fatalf("origin proof = %v, want %v, header %s", got, want, r.Data)
		}
	}
	host := inboxCaptureOriginConnect(t, s, "host", true)
	for _, detailed := range []bool{false, true} {
		require_NoError(t, app.SetServiceImportSharing(sys, "$JS.ORIGIN", detailed))
		check(host, "$JS.ORIGIN", true, true)
		check(inboxCaptureOriginConnect(t, s, "bounded", true), "$JS.ORIGIN", true, false)
		check(inboxCaptureOriginConnect(t, s, "host", false), "$JS.ORIGIN", true, false)
		check(inboxCaptureOriginConnect(t, s, "sys", true), "$JS.ORIGIN", true, false)
		check(inboxCaptureOriginConnect(t, s, "chain", true), "$JS.ORIGIN", true, false)
	}
	id, err := host.GetClientID()
	require_NoError(t, err)
	s.mu.Lock()
	c := s.clients[id]
	s.mu.Unlock()
	if c == nil {
		t.Fatal("missing in-process client")
	}
	c.mu.Lock()
	c.setPermissions(&Permissions{Publish: &SubjectPermission{Allow: []string{">"}}})
	c.mu.Unlock()
	check(host, "$JS.ORIGIN", false, false)
	c.mu.Lock()
	c.perms = nil
	c.mu.Unlock()
	check(host, "$JS.ORIGIN", false, true)
}

func TestJetStreamInboxCaptureOriginIngress(t *testing.T) {
	s, _, _ := inboxCaptureOriginServer(t)
	svc := inboxCaptureOriginConnect(t, s, "host", false)
	_, err := svc.Subscribe("direct", func(m *nats.Msg) {
		_ = m.Respond([]byte(m.Header.Get(ClientInfoHdr)))
	})
	require_NoError(t, err)
	require_NoError(t, svc.Flush())
	for _, iproc := range []bool{false, true} {
		nc := inboxCaptureOriginConnect(t, s, "host", iproc)
		m := nats.NewMsg("direct")
		m.Header.Set(ClientInfoHdr, `{"acc":"APP","iproc_unrestricted":true,"reply":"kept","user":"still-present"}`)
		r, err := nc.RequestMsg(m, time.Second)
		require_NoError(t, err)
		var ci map[string]any
		require_NoError(t, json.Unmarshal(r.Data, &ci))
		if ci["iproc_unrestricted"] == true {
			t.Fatalf("forged proof survived ingress: %s", r.Data)
		}
		if ci["reply"] != "kept" || ci["user"] != "still-present" {
			t.Fatalf("unrelated header fields changed: %s", r.Data)
		}
	}
}

func TestJetStreamInboxCaptureOriginCopies(t *testing.T) {
	var ci ClientInfo
	require_NoError(t, json.Unmarshal([]byte(`{"acc":"APP","iproc_unrestricted":true}`), &ci))
	for _, copy := range []*ClientInfo{ci.forProposal(), ci.forAdvisory(), ci.forAssignmentSnap()} {
		b, err := json.Marshal(copy)
		require_NoError(t, err)
		var fields map[string]any
		require_NoError(t, json.Unmarshal(b, &fields))
		if fields["iproc_unrestricted"] == true {
			t.Fatalf("origin proof escaped in copy: %s", b)
		}
	}
}

func TestJetStreamInboxCaptureOriginAuthority(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kind  int
		iproc bool
		perms *permissions
		want  bool
	}{
		{"trusted", CLIENT, true, nil, true},
		{"unrestricted structure", CLIENT, true, &permissions{}, true},
		{"network", CLIENT, false, nil, false},
		{"leaf", LEAF, true, nil, false},
		{"route", ROUTER, true, nil, false},
		{"gateway", GATEWAY, true, nil, false},
		{"callback", JETSTREAM, true, nil, false},
		{"publish allow", CLIENT, true, &permissions{pub: perm{allow: NewSublistNoCache()}}, false},
		{"publish deny", CLIENT, true, &permissions{pub: perm{deny: NewSublistNoCache()}}, false},
		{"subscribe allow", CLIENT, true, &permissions{sub: perm{allow: NewSublistNoCache()}}, false},
		{"subscribe deny", CLIENT, true, &permissions{sub: perm{deny: NewSublistNoCache()}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &client{kind: tc.kind, iproc: tc.iproc, perms: tc.perms}
			if got := c.inProcessUnrestricted(); got != tc.want {
				t.Fatalf("unrestricted = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestJetStreamInboxCaptureOriginAPI(t *testing.T) {
	conf := createConfFile(t, []byte(fmt.Sprintf("listen: 127.0.0.1:-1\njetstream {store_dir: %q}\n", t.TempDir())+inboxCaptureOriginAccounts))
	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()
	inboxCaptureOriginAPIControls(t, s, 1)
}

func TestJetStreamInboxCaptureOriginLeaf(t *testing.T) {
	for _, bindSystem := range []bool{false, true} {
		t.Run(fmt.Sprintf("system=%t", bindSystem), func(t *testing.T) {
			hub, _, _ := inboxCaptureOriginServer(t, func(o *Options) {
				o.FeatureFlags = map[string]bool{"js_reject_inbox_capture": true}
				o.JetStream, o.JetStreamDomain, o.StoreDir = true, "HUB", t.TempDir()
				o.JetStreamMaxMemory, o.JetStreamMaxStore = 64<<20, 64<<20
				o.Accounts[1].jsLimits = defaultJSAccountTiers
				o.LeafNode.Host, o.LeafNode.Port = "127.0.0.1", -1
				account := o.Accounts[1]
				if bindSystem {
					account = o.Accounts[0]
				}
				o.LeafNode.Users = []*User{{Username: "leaf", Password: "pwd", Account: account}}
			})
			remote, _, _ := inboxCaptureOriginServer(t, func(o *Options) {
				require_NoError(t, o.Accounts[0].AddServiceExport("$JS.HUB.API.>", nil))
				require_NoError(t, o.Accounts[1].AddServiceImport(o.Accounts[0], "$JS.HUB.API.>", "$JS.HUB.API.>"))
				u, err := url.Parse(fmt.Sprintf("nats-leaf://leaf:pwd@%s:%d", hub.getOpts().LeafNode.Host, hub.getOpts().LeafNode.Port))
				require_NoError(t, err)
				o.LeafNode.Remotes = []*RemoteLeafOpts{{URLs: []*url.URL{u}, LocalAccount: "SYS"}}
			})
			checkLeafNodeConnected(t, hub)
			svc := inboxCaptureOriginConnect(t, hub, "sys", false)
			_, err := svc.Subscribe("$JS.ORIGIN", func(m *nats.Msg) { _ = m.Respond([]byte(m.Header.Get(ClientInfoHdr))) })
			require_NoError(t, err)
			require_NoError(t, svc.Flush())
			// The remote first system import supplies a real trusted proof.
			// Leaf ingress must clear it before the hub handles the request.
			spy := inboxCaptureOriginConnect(t, remote, "sys", false)
			sub, err := spy.SubscribeSync("$JS.ORIGIN")
			require_NoError(t, err)
			require_NoError(t, spy.Flush())
			host := inboxCaptureOriginConnect(t, remote, "host", true)
			checkFor(t, 5*time.Second, 20*time.Millisecond, func() error {
				response, err := host.Request("$JS.ORIGIN", nil, 250*time.Millisecond)
				if err != nil {
					return err
				}
				var ci ClientInfo
				if err := json.Unmarshal(response.Data, &ci); err != nil {
					return err
				}
				if ci.InProcessUnrestricted {
					return fmt.Errorf("leaf forwarded proof: %s", response.Data)
				}
				return nil
			})
			request, err := sub.NextMsg(time.Second)
			require_NoError(t, err)
			var ci ClientInfo
			require_NoError(t, json.Unmarshal([]byte(request.Header.Get(ClientInfoHdr)), &ci))
			require_True(t, ci.InProcessUnrestricted)
			// A response through the same leaf proves safe JS management and reads.
			remoteJS, err := host.JetStream(nats.Domain("HUB"))
			require_NoError(t, err)
			_, err = remoteJS.AddStream(&nats.StreamConfig{Name: "LEAF_SAFE", Subjects: []string{"leaf.safe"}, Storage: nats.MemoryStorage})
			require_NoError(t, err)
			hubHost := inboxCaptureOriginConnect(t, hub, "host", true)
			hubJS, err := hubHost.JetStream()
			require_NoError(t, err)
			_, err = hubJS.Publish("leaf.safe", []byte("safe"))
			require_NoError(t, err)
			stored, err := remoteJS.GetLastMsg("LEAF_SAFE", "leaf.safe")
			require_NoError(t, err)
			require_Equal(t, string(stored.Data), "safe")
			for _, operation := range []string{"create", "update", "restore"} {
				name, api := "LEAF_BAD", JSApiStreamCreateT
				if operation == "update" {
					name, api = "LEAF_SAFE", JSApiStreamUpdateT
				}
				if operation == "restore" {
					api = JSApiStreamRestoreT
				}
				cfg := StreamConfig{Name: name, Subjects: []string{"_INBOX.foreign.x"}, Storage: MemoryStorage}
				var value any = cfg
				if operation == "restore" {
					value = JSApiStreamRestoreRequest{Config: cfg}
				}
				payload, err := json.Marshal(value)
				require_NoError(t, err)
				subject := strings.Replace(fmt.Sprintf(api, name), "$JS.API", "$JS.HUB.API", 1)
				response, err := host.Request(subject, payload, 5*time.Second)
				require_NoError(t, err)
				var result ApiResponse
				require_NoError(t, json.Unmarshal(response.Data, &result))
				requireInboxCaptureError(t, result.Error)
			}
			info, err := hubJS.StreamInfo("LEAF_SAFE")
			require_NoError(t, err)
			require_Equal(t, info.Config.Subjects[0], "leaf.safe")
			_, err = hubJS.StreamInfo("LEAF_BAD")
			require_Error(t, err)
		})
	}
}

func TestJetStreamInboxCaptureOriginHeaderRewrite(t *testing.T) {
	for _, kind := range []int{CLIENT, LEAF, ROUTER, GATEWAY} {
		c := &client{kind: kind}
		msg := c.setHeader(ClientInfoHdr, `{"acc":"APP","iproc_unrestricted":true,"reply":"original"}`, []byte("payload\r\n"))
		msg = c.clearForwardedOriginMarker(msg)
		var ci ClientInfo
		require_NoError(t, json.Unmarshal(sliceHeader(ClientInfoHdr, msg[:c.pa.hdr]), &ci))
		require_Equal(t, ci.InProcessUnrestricted, kind == ROUTER || kind == GATEWAY)
		require_Equal(t, ci.Account, "APP")
		require_Equal(t, ci.Reply, "original")
		require_Equal(t, string(msg[c.pa.hdr:]), "payload\r\n")
		require_Equal(t, c.pa.size, len(msg)-LEN_CR_LF)
		require_Equal(t, string(c.pa.szb), fmt.Sprint(c.pa.size))
		require_Equal(t, string(c.pa.hdb), fmt.Sprint(c.pa.hdr))
		again := c.clearForwardedOriginMarker(msg)
		require_True(t, &again[0] == &msg[0])
	}
}

func TestJetStreamInboxCaptureOriginGrant(t *testing.T) {
	for _, grant := range []authverify.Grant{grantAll(), {}} {
		reqs := make(chan *authverify.GrantRequest, 1)
		f := newGrantFixture(t, &testGrantHook{verify: func(req *authverify.GrantRequest) *authverify.GrantVerdict {
			reqs <- req
			return &authverify.GrantVerdict{Generation: 1, Grant: grant, Done: func(bool) {}}
		}}, func(ac *jwt.AccountClaims, _ *jwt.UserScope) {
			ac.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: jwt.NoLimit, DiskStorage: jwt.NoLimit, Streams: jwt.NoLimit, Consumer: jwt.NoLimit}
		})
		_, systemKey := createKey(t)
		systemJWT, err := jwt.NewAccountClaims(systemKey).Encode(oKp)
		require_NoError(t, err)
		require_NoError(t, f.s.AccountResolver().Store(systemKey, systemJWT))
		require_NoError(t, f.s.SetSystemAccount(systemKey))
		opts := *f.s.getOpts()
		opts.FeatureFlags = map[string]bool{"js_reject_inbox_capture": true}
		f.s.setOpts(&opts)
		require_NoError(t, f.s.EnableJetStream(&JetStreamConfig{StoreDir: t.TempDir(), MaxMemory: 64 << 20, MaxStore: 64 << 20}))
		nc, err := nats.Connect(f.s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.InProcessServer(f.s))
		require_NoError(t, err)
		defer nc.Close()
		req := grantRecv(t, reqs)
		c := f.s.grantClient(req.Client.ID)
		require_True(t, c.iproc)
		require_False(t, c.inProcessUnrestricted())
		if len(grant.Pub.Allow) == 0 {
			continue
		}
		js, err := nc.JetStream()
		require_NoError(t, err)
		_, err = js.AddStream(&nats.StreamConfig{Name: "GRANT_SAFE", Subjects: []string{"grant.safe"}, Storage: nats.MemoryStorage})
		require_NoError(t, err)
		_, err = js.Publish("grant.safe", []byte("safe"))
		require_NoError(t, err)
		message, err := js.GetLastMsg("GRANT_SAFE", "grant.safe")
		require_NoError(t, err)
		require_Equal(t, string(message.Data), "safe")
		for _, operation := range []string{"create", "update", "restore"} {
			name, api := "GRANT_BAD", JSApiStreamCreateT
			if operation == "update" {
				name, api = "GRANT_SAFE", JSApiStreamUpdateT
			}
			if operation == "restore" {
				api = JSApiStreamRestoreT
			}
			cfg := StreamConfig{Name: name, Subjects: []string{"_INBOX.foreign.x"}, Storage: MemoryStorage}
			var value any = cfg
			if operation == "restore" {
				value = JSApiStreamRestoreRequest{Config: cfg}
			}
			payload, err := json.Marshal(value)
			require_NoError(t, err)
			response, err := nc.Request(fmt.Sprintf(api, name), payload, 5*time.Second)
			require_NoError(t, err)
			var result ApiResponse
			require_NoError(t, json.Unmarshal(response.Data, &result))
			requireInboxCaptureError(t, result.Error)
		}
		info, err := js.StreamInfo("GRANT_SAFE")
		require_NoError(t, err)
		require_Equal(t, info.Config.Subjects[0], "grant.safe")
		_, err = js.StreamInfo("GRANT_BAD")
		require_Error(t, err)
	}
}
