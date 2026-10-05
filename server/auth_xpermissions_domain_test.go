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
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

// The expected expansions are written out literally so that the tests do not
// depend on the production table. See the v2 design spec, sections 5 and 6.
//
// With a domain the JetStream API prefix carries that domain and the domain
// token of the v2 ack and flow control patterns is the domain name instead of
// a wildcard. The v1 patterns have no domain token and do not change.
func macroDomainReadPubSubjects(domain, stream string) []string {
	api := "$JS." + domain + ".API"
	return []string{
		api + ".STREAM.INFO." + stream,
		api + ".STREAM.MSG.GET." + stream,
		api + ".DIRECT.GET." + stream,
		api + ".DIRECT.GET." + stream + ".>",
		api + ".CONSUMER.CREATE." + stream,
		api + ".CONSUMER.CREATE." + stream + ".>",
		api + ".CONSUMER.DURABLE.CREATE." + stream + ".>",
		api + ".CONSUMER.INFO." + stream + ".>",
		api + ".CONSUMER.NAMES." + stream,
		api + ".CONSUMER.LIST." + stream,
		api + ".CONSUMER.DELETE." + stream + ".>",
		api + ".CONSUMER.MSG.NEXT." + stream + ".>",
		"$JS.ACK." + stream + ".*.*.*.*.*.*",
		"$JS.ACK." + domain + ".*." + stream + ".*.*.*.*.*.>",
		"$JS.FC." + stream + ".*.*",
		"$JS.FC." + domain + ".*." + stream + ".*.*",
	}
}

// data is the complete data publish subject, already prefixed when the remote
// domain prefixes it. It is empty for plain streams.
func macroDomainWritePubSubjects(domain, stream, data string) []string {
	out := append(macroDomainReadPubSubjects(domain, stream), "$JS."+domain+".API.STREAM.PURGE."+stream)
	if data != "" {
		out = append(out, data)
	}
	return out
}

func macroDomainAdminPubSubjects(domain, stream, data string) []string {
	api := "$JS." + domain + ".API"
	return append(macroDomainWritePubSubjects(domain, stream, data),
		api+".STREAM.CREATE."+stream,
		api+".STREAM.UPDATE."+stream,
		api+".STREAM.DELETE."+stream,
		api+".STREAM.MSG.DELETE."+stream,
		api+".STREAM.SNAPSHOT."+stream,
		api+".STREAM.RESTORE."+stream,
		api+".INFO",
	)
}

func macroDomainConsumerPubSubjects(domain, stream, consumer string) []string {
	api := "$JS." + domain + ".API"
	return []string{
		api + ".STREAM.INFO." + stream,
		api + ".CONSUMER.INFO." + stream + "." + consumer,
		api + ".CONSUMER.MSG.NEXT." + stream + "." + consumer,
		"$JS.ACK." + stream + "." + consumer + ".*.*.*.*.*",
		"$JS.ACK." + domain + ".*." + stream + "." + consumer + ".*.*.*.*.>",
		"$JS.FC." + stream + "." + consumer + ".*",
		"$JS.FC." + domain + ".*." + stream + "." + consumer + ".*",
	}
}

func macroDomainConsumerAdminPubSubjects(domain, stream, consumer string) []string {
	api := "$JS." + domain + ".API"
	return append(macroDomainConsumerPubSubjects(domain, stream, consumer),
		api+".CONSUMER.CREATE."+stream+"."+consumer,
		api+".CONSUMER.CREATE."+stream+"."+consumer+".>",
		api+".CONSUMER.DURABLE.CREATE."+stream+"."+consumer,
		api+".CONSUMER.DELETE."+stream+"."+consumer,
		api+".CONSUMER.PAUSE."+stream+"."+consumer,
		api+".CONSUMER.UNPIN."+stream+"."+consumer,
		api+".CONSUMER.RESET."+stream+"."+consumer,
	)
}

// requireSubjectsInOrder is requireSameSubjects plus the emission order, which
// the cartesian product tests need.
func requireSubjectsInOrder(t *testing.T, res jwt.StringList, expected []string) {
	t.Helper()
	if len(res) != len(expected) {
		t.Fatalf("expected %d subjects, got %d: %v", len(expected), len(res), res)
	}
	for i, subj := range expected {
		if res[i] != subj {
			t.Fatalf("subject %d: expected %q, got %q", i, subj, res[i])
		}
	}
}

// Every macro emits its usual set against the named domain.
func TestJWTXPermissionsDomainSubjectSets(t *testing.T) {
	const dom = "hub"
	for _, test := range []struct {
		raw      string
		expected []string
	}{
		{`{"kv":[{"op":"rw","bucket":"{{tag(kv)}}","domain":"hub"}]}`,
			macroDomainWritePubSubjects(dom, "KV_cfg", "$JS.hub.API.$KV.cfg.>")},
		{`{"kv":[{"op":"admin","bucket":"{{tag(kv)}}","domain":"hub"}]}`,
			macroDomainAdminPubSubjects(dom, "KV_cfg", "$JS.hub.API.$KV.cfg.>")},
		// The Object Store data subject is not prefixed: clients do not
		// prefix it and there is no $O domain mapping.
		{`{"obj":[{"op":"rw","bucket":"{{tag(obj)}}","domain":"hub"}]}`,
			macroDomainWritePubSubjects(dom, "OBJ_blobs", "$O.blobs.>")},
		{`{"stream":[{"op":"ro","stream":"{{tag(js)}}","domain":"hub"}]}`,
			macroDomainReadPubSubjects(dom, "orders")},
		{`{"stream":[{"op":"admin","stream":"{{tag(js)}}","domain":"hub"}]}`,
			macroDomainAdminPubSubjects(dom, "orders", "")},
		{`{"consumer":[{"op":"ro","stream":"{{tag(js)}}","consumer":"{{tag(c)}}","domain":"hub"}]}`,
			macroDomainConsumerPubSubjects(dom, "orders", "workers")},
		{`{"consumer":[{"op":"admin","stream":"{{tag(js)}}","consumer":"{{tag(c)}}","domain":"hub"}]}`,
			macroDomainConsumerAdminPubSubjects(dom, "orders", "workers")},
	} {
		t.Run(test.raw, func(t *testing.T) {
			uc, acc := macroTestUserClaims(t, "kv:cfg", "obj:blobs", "js:orders", "c:workers")
			res, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, mustXPermissions(t, test.raw), uc, acc)
			require_NoError(t, err)
			requireSubjectsInOrder(t, res.Pub.Allow, test.expected)
		})
	}
}

// The domain is the innermost loop of the cartesian product, so a resource
// list stays together and each resource is expanded once per domain.
func TestJWTXPermissionsDomainCartesianProduct(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "js:alpha", "js:beta", "dom:one", "dom:two")

	xp := mustXPermissions(t, `{"stream":[{"op":"ro","stream":"{{tag(js)}}","domain":"{{tag(dom)}}"}]}`)
	res, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_NoError(t, err)
	var expected []string
	for _, s := range []string{"alpha", "beta"} {
		expected = append(expected, macroDomainReadPubSubjects("one", s)...)
		second := macroDomainReadPubSubjects("two", s)
		expected = append(expected, second[:12]...)
		expected = append(expected, second[13])
		expected = append(expected, second[15])
	}
	requireSubjectsInOrder(t, res.Pub.Allow, expected)

	// One literal resource in two domains gives two sets, in tag order.
	xp = mustXPermissions(t, `{"kv":[{"op":"rw","bucket":"cfg","domain":"{{tag(dom)}}"}]}`)
	res, err = processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_NoError(t, err)
	expected = macroDomainWritePubSubjects("one", "KV_cfg", "$JS.one.API.$KV.cfg.>")
	second := macroDomainWritePubSubjects("two", "KV_cfg", "$JS.two.API.$KV.cfg.>")
	expected = append(expected, second[:12]...)
	expected = append(expected, second[13])
	expected = append(expected, second[15:]...)
	requireSubjectsInOrder(t, res.Pub.Allow, expected)
}

// A subscribe list names the bucket's own data subject, which is account
// local, so a domain does not change what a subscribe list expands to.
func TestJWTXPermissionsDomainSubscribeListUnchanged(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "kv:cfg", "obj:blobs")
	lim := jwt.UserPermissionLimits{}
	lim.Sub.Deny.Add("$KV.cfg.>")
	xp := mustXPermissions(t, `{"kv":[{"op":"rw","bucket":"{{tag(kv)}}","domain":"hub"}],"obj":[{"op":"rw","bucket":"{{tag(obj)}}","domain":"hub"}]}`)
	res, err := processUserPermissionsTemplate(lim, xp, uc, acc)
	require_NoError(t, err)
	requireSubjectsInOrder(t, res.Sub.Allow, []string{"$KV.cfg.>", "$O.blobs.>"})
	requireSubjectsInOrder(t, res.Sub.Deny, []string{"$KV.cfg.>"})
	// Only the publish list carries the prefixed data subject.
	require_True(t, res.Pub.Allow.Contains("$JS.hub.API.$KV.cfg.>"))
	require_False(t, res.Pub.Allow.Contains("$KV.cfg.>"))
}

// A domain that resolves to no value emits nothing in an allow list, so the
// user fails closed, and is an error in a deny list.
func TestJWTXPermissionsDomainMissingValueFailsClosed(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "kv:cfg") // no "dom:" tag at all
	xp := mustXPermissions(t, `{"kv":[{"op":"rw","bucket":"{{tag(kv)}}","domain":"{{tag(dom)}}"}]}`)
	_, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_Error(t, err)
	require_Contains(t, err.Error(), "not defined")
}

// A domain value is held to the resource name rule, so it cannot carry a
// separator, a wildcard or a template token.
func TestJWTXPermissionsDomainInvalidValue(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "kv:cfg",
		"dom:good", "dom:a.b", "dom:*", "dom:{{name()}}", "dom:")
	xp := mustXPermissions(t, `{"kv":[{"op":"rw","bucket":"{{tag(kv)}}","domain":"{{tag(dom)}}"}]}`)
	_, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_Error(t, err)
	require_Contains(t, err.Error(), "generated invalid subject")

	// An invalid literal domain emits nothing and fails closed.
	for _, bad := range []string{"a.b", "*", ">"} {
		f := newXPermissionsRawFixture(t, `{"kv":[{"op":"rw","bucket":"cfg","domain":"`+bad+`"}]}`)
		_, _, _, err := f.server.verifyAccountClaimsWithXPermissions(f.token)
		require_Error(t, err)
	}
}

// Whitespace around the named argument, its key and its value is trimmed.
func TestJWTXPermissionsDomainArgumentWhitespace(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "kv:cfg")
	xp := mustXPermissions(t, `{"kv":[{"op":"rw","bucket":"{{ tag(kv) }}","domain":"hub"}]}`)
	res, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_NoError(t, err)
	requireSubjectsInOrder(t, res.Pub.Allow,
		macroDomainWritePubSubjects("hub", "KV_cfg", "$JS.hub.API.$KV.cfg.>"))

}

// A zero-argument macro takes the domain and nothing else.
func TestJWTXPermissionsDomainOnlyArgument(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "dom:hub")
	lim := jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("$JS.{{tag(dom)}}.API.INFO", "$JS.{{tag(dom)}}.API.STREAM.NAMES", "$JS.{{tag(dom)}}.API.STREAM.LIST")
	res, err := processUserPermissionsTemplate(lim, nil, uc, acc)
	require_NoError(t, err)
	requireSubjectsInOrder(t, res.Pub.Allow,
		[]string{"$JS.hub.API.INFO", "$JS.hub.API.STREAM.NAMES", "$JS.hub.API.STREAM.LIST"})

}

// End-to-end coverage of the domain argument. See the v2 design spec,
// section 10 item 4.
//
// A hub server and a spoke server run different JetStream domains and are
// connected by a leaf node, both in operator mode with the same operator,
// system account and application account. A scoped user of that account
// connects to the SPOKE and works on hub resources through
// nats.Domain("hub"). The hub pins the v2 ack and flow control format, so the
// acks that come back carry the "hub" domain token and the pinned pattern of
// the macro is the one that has to match.
func TestJWTXPermissionsDomainEndToEnd(t *testing.T) {
	_, sysPub := createKey(t)
	sysJwt := encodeClaim(t, jwt.NewAccountClaims(sysPub), sysPub)

	accKp, accPub := createKey(t)
	accClaim := jwt.NewAccountClaims(accPub)
	accClaim.Name = "acc"
	accClaim.Limits.JetStreamTieredLimits["R1"] = jwt.JetStreamLimits{
		DiskStorage: jwt.NoLimit, MemoryStorage: jwt.NoLimit,
		Consumer: jwt.NoLimit, Streams: jwt.NoLimit,
	}
	// The scoped signer of the user that reaches the hub domain. The
	// subscribe entry has no domain: a bucket's data subject is account
	// local, so it never carries one.
	hubKp, hubPub := createKey(t)
	hubScope := jwt.NewUserScope()
	hubScope.Key = hubPub
	hubScope.Template.Sub.Allow.Add("_INBOX.>")
	accClaim.SigningKeys.AddScopedSigner(hubScope)
	// The same template without a domain, for the negative case.
	locKp, locPub := createKey(t)
	locScope := jwt.NewUserScope()
	locScope.Key = locPub
	locScope.Template.Sub.Allow.Add("_INBOX.>")
	accClaim.SigningKeys.AddScopedSigner(locScope)
	accJwt := encodeAccountClaimWithXPermissions(t, accClaim, map[string]string{
		hubPub: `{"kv":[{"op":"rw","bucket":"{{tag(kv)}}","domain":"hub"}],"consumer":[{"op":"ro","stream":"orders","consumer":"shared","domain":"hub"}]}`,
		locPub: `{"kv":[{"op":"rw","bucket":"{{tag(kv)}}"}]}`,
	})

	adminCreds := newUser(t, accKp)
	// The leaf node link must not be narrower than the users that use it.
	leafCreds := newUser(t, accKp)
	scopedCreds := func(kp nkeys.KeyPair, tags ...string) string {
		t.Helper()
		ukp, _ := nkeys.CreateUser()
		seed, _ := ukp.Seed()
		upub, _ := ukp.PublicKey()
		uclaim := newJWTTestUserClaims()
		uclaim.Subject = upub
		uclaim.SetScoped(true)
		uclaim.IssuerAccount = accPub
		uclaim.Tags.Add(tags...)
		ujwt, err := uclaim.Encode(kp)
		require_NoError(t, err)
		return genCredsFile(t, ujwt, seed)
	}
	hubUserCreds := scopedCreds(hubKp, "kv:cfg")
	locUserCreds := scopedCreds(locKp, "kv:cfg")

	operatorMode := fmt.Sprintf(`
		operator: %s
		system_account: %s
		resolver: MEM
		resolver_preload: {
			%s: %s
			%s: %s
		}
	`, ojwt, sysPub, sysPub, sysJwt, accPub, accJwt)

	hubConf := createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:-1
		server_name: HUB
		%s
		jetstream: { domain: hub, store_dir: '%s', max_mem: 64Mb, max_file: 256Mb }
		leafnodes: { listen: 127.0.0.1:-1 }
		feature_flags { js_ack_fc_v2: true }
	`, operatorMode, t.TempDir())))
	sHub, _ := RunServerWithConfig(hubConf)
	defer sHub.Shutdown()

	// The administrator is an unscoped user of the same account, connected to
	// the hub. It owns the bucket, the stream and the durable consumer.
	anc := natsConnect(t, sHub.ClientURL(), nats.UserCredentials(adminCreds))
	defer anc.Close()
	ajs, err := anc.JetStream()
	require_NoError(t, err)
	_, err = ajs.CreateKeyValue(&nats.KeyValueConfig{Bucket: "cfg", History: 5})
	require_NoError(t, err)
	_, err = ajs.AddStream(&nats.StreamConfig{Name: "orders", Subjects: []string{"orders.>"}})
	require_NoError(t, err)
	for i := 0; i < 5; i++ {
		_, err = ajs.Publish(fmt.Sprintf("orders.%d", i), []byte("m"))
		require_NoError(t, err)
	}
	_, err = ajs.AddConsumer("orders", &nats.ConsumerConfig{
		Durable: "shared", FilterSubject: "orders.>", AckPolicy: nats.AckExplicitPolicy})
	require_NoError(t, err)

	// In operator mode every leaf remote names its account explicitly.
	spokeConf := createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:-1
		server_name: SPOKE
		%s
		jetstream: { domain: spoke, store_dir: '%s', max_mem: 64Mb, max_file: 256Mb }
		leafnodes: {
			remotes: [ { url: nats://127.0.0.1:%d, account: %s, credentials: '%s' } ]
		}
	`, operatorMode, t.TempDir(), sHub.opts.LeafNode.Port, accPub, leafCreds)))
	sSpoke, _ := RunServerWithConfig(spokeConf)
	defer sSpoke.Shutdown()

	checkLeafNodeConnectedCount(t, sHub, 1)
	checkLeafNodeConnectedCount(t, sSpoke, 1)
	// The hub advertises its domain mappings over the leaf node. Wait for
	// that interest, otherwise the first request gets "no responders".
	checkSubInterest(t, sSpoke, accPub, "$JS.hub.API.STREAM.INFO.KV_cfg", 5*time.Second)
	checkSubInterest(t, sSpoke, accPub, "$JS.hub.API.CONSUMER.INFO.orders.shared", 5*time.Second)

	// Denied publishes show up as asynchronous permission violations. The
	// text of each one names the subject the client used.
	var violations atomic.Int32
	var vmu sync.Mutex
	var vmsgs []string
	t.Cleanup(func() {
		vmu.Lock()
		defer vmu.Unlock()
		for _, m := range vmsgs {
			t.Logf("permission violation seen: %s", m)
		}
	})
	violationSeen := func(fragment string) bool {
		vmu.Lock()
		defer vmu.Unlock()
		for _, m := range vmsgs {
			if strings.Contains(m, fragment) {
				return true
			}
		}
		return false
	}
	connect := func(creds string) *nats.Conn {
		t.Helper()
		return natsConnect(t, sSpoke.ClientURL(), nats.UserCredentials(creds),
			nats.PermissionErrOnSubscribe(true),
			nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
				if errors.Is(err, nats.ErrPermissionViolation) {
					violations.Add(1)
					vmu.Lock()
					vmsgs = append(vmsgs, err.Error())
					vmu.Unlock()
				}
			}))
	}

	nc := connect(hubUserCreds)
	defer nc.Close()
	js, err := nc.JetStream(nats.Domain("hub"), nats.MaxWait(5*time.Second))
	require_NoError(t, err)
	njs, err := jetstream.NewWithDomain(nc, "hub", jetstream.WithDefaultTimeout(5*time.Second))
	require_NoError(t, err)
	ctx := context.Background()

	t.Run("kv through the legacy api", func(t *testing.T) {
		kv, err := js.KeyValue("cfg")
		require_NoError(t, err)
		_, err = kv.Put("legacy", []byte("v1"))
		require_NoError(t, err)
		e, err := kv.Get("legacy")
		require_NoError(t, err)
		require_Equal(t, string(e.Value()), "v1")

		w, err := kv.Watch("legacy")
		require_NoError(t, err)
		defer w.Stop()
		select {
		case upd := <-w.Updates():
			require_NotNil(t, upd)
			require_Equal(t, string(upd.Value()), "v1")
		case <-time.After(5 * time.Second):
			t.Fatal("no watch update")
		}

		require_NoError(t, kv.Delete("legacy"))
		_, err = kv.Get("legacy")
		require_True(t, err == nats.ErrKeyNotFound)
	})

	t.Run("kv through the jetstream api", func(t *testing.T) {
		kv, err := njs.KeyValue(ctx, "cfg")
		require_NoError(t, err)
		_, err = kv.Put(ctx, "new", []byte("v2"))
		require_NoError(t, err)
		e, err := kv.Get(ctx, "new")
		require_NoError(t, err)
		require_Equal(t, string(e.Value()), "v2")

		w, err := kv.Watch(ctx, "new")
		require_NoError(t, err)
		defer w.Stop()
		select {
		case upd := <-w.Updates():
			require_NotNil(t, upd)
			require_Equal(t, string(upd.Value()), "v2")
		case <-time.After(5 * time.Second):
			t.Fatal("no watch update")
		}

		require_NoError(t, kv.Delete(ctx, "new"))
		_, err = kv.Get(ctx, "new")
		require_True(t, errors.Is(err, jetstream.ErrKeyNotFound))
	})

	t.Run("consumer with a v2 ack from the hub", func(t *testing.T) {
		sub, err := js.PullSubscribe("orders.>", "shared", nats.Bind("orders", "shared"))
		require_NoError(t, err)
		defer sub.Unsubscribe()
		before := violations.Load()
		msgs, err := sub.Fetch(1, nats.MaxWait(5*time.Second))
		require_NoError(t, err)
		require_Len(t, len(msgs), 1)
		// $JS.ACK.<domain>.<account hash>.<stream>.<consumer>.<delivered>.
		// <sseq>.<cseq>.<ts>.<pending>, so the domain is the third token.
		t.Logf("ack reply subject: %s", msgs[0].Reply)
		tokens := strings.Split(msgs[0].Reply, ".")
		require_Len(t, len(tokens), 11)
		require_Equal(t, tokens[2], "hub")
		require_NoError(t, msgs[0].Ack())
		// An ack is fire and forget, so a denied ack only shows up as a
		// pending ack that never clears.
		checkFor(t, 5*time.Second, 25*time.Millisecond, func() error {
			ci, err := js.ConsumerInfo("orders", "shared")
			if err != nil {
				return err
			}
			if ci.NumAckPending != 0 {
				return fmt.Errorf("still %d acks pending", ci.NumAckPending)
			}
			return nil
		})
		require_Equal(t, violations.Load(), before)
	})

	t.Run("the same template without a domain cannot reach the hub", func(t *testing.T) {
		lnc := connect(locUserCreds)
		defer lnc.Close()
		ljs, err := lnc.JetStream(nats.Domain("hub"), nats.MaxWait(time.Second))
		require_NoError(t, err)

		// The bind is a $JS.hub.API.STREAM.INFO.KV_cfg request, which this
		// template does not grant.
		_, err = ljs.KeyValue("cfg")
		require_Error(t, err)
		// A data publish to the hub bucket is denied as well.
		require_NoError(t, lnc.Publish("$JS.hub.API.$KV.cfg.legacy", []byte("nope")))
		require_NoError(t, lnc.Flush())

		checkFor(t, 5*time.Second, 25*time.Millisecond, func() error {
			if !violationSeen("$JS.hub.API.STREAM.INFO.KV_cfg") {
				return fmt.Errorf("no violation for the hub stream info subject")
			}
			if !violationSeen("$JS.hub.API.$KV.cfg.legacy") {
				return fmt.Errorf("no violation for the hub data subject")
			}
			return nil
		})
		// The same template does grant the local JetStream API, so the
		// domain prefix is the only reason the requests above failed. The
		// spoke has its own domain and no such bucket, so the request is
		// answered with an API error and not with a violation.
		before := violations.Load()
		localJS, err := lnc.JetStream(nats.MaxWait(5 * time.Second))
		require_NoError(t, err)
		_, err = localJS.StreamInfo("KV_cfg")
		require_Error(t, err)
		require_True(t, errors.Is(err, nats.ErrStreamNotFound))
		require_Equal(t, violations.Load(), before)
	})

	// Both negative cases must have produced a permission violation.
	require_True(t, violations.Load() >= 2)
}
