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
// depend on the production table. See the v2 design spec, sections 5.5 and 5.6.
func macroConsumerPubSubjects(stream, consumer string) []string {
	return []string{
		"$JS.API.STREAM.INFO." + stream,
		"$JS.API.CONSUMER.INFO." + stream + "." + consumer,
		"$JS.API.CONSUMER.MSG.NEXT." + stream + "." + consumer,
		"$JS.ACK." + stream + "." + consumer + ".*.*.*.*.*",
		"$JS.ACK.*.*." + stream + "." + consumer + ".*.*.*.*.>",
		"$JS.FC." + stream + "." + consumer + ".*",
		"$JS.FC.*.*." + stream + "." + consumer + ".*",
	}
}

func macroConsumerAdminPubSubjects(stream, consumer string) []string {
	return append(macroConsumerPubSubjects(stream, consumer),
		"$JS.API.CONSUMER.CREATE."+stream+"."+consumer,
		"$JS.API.CONSUMER.CREATE."+stream+"."+consumer+".>",
		"$JS.API.CONSUMER.DURABLE.CREATE."+stream+"."+consumer,
		"$JS.API.CONSUMER.DELETE."+stream+"."+consumer,
		"$JS.API.CONSUMER.PAUSE."+stream+"."+consumer,
		"$JS.API.CONSUMER.UNPIN."+stream+"."+consumer,
		"$JS.API.CONSUMER.RESET."+stream+"."+consumer,
	)
}

func TestJWTXPermissionsConsumerSubjectSets(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "s:orders", "c:workers")
	xp := mustXPermissions(t, `{"consumer":[{"op":"ro","stream":"{{tag(s)}}","consumer":"{{tag(c)}}"},{"op":"admin","stream":"ORDERS","consumer":"own"}]}`)
	res, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_NoError(t, err)
	expected := append(macroConsumerPubSubjects("orders", "workers"),
		macroConsumerAdminPubSubjects("ORDERS", "own")...)
	requireSameSubjects(t, res.Pub.Allow, expected)

	// A consumer macro is bound to its stream and its consumer only. It
	// grants no stream management and no data subject.
	for _, subj := range res.Pub.Allow {
		require_True(t, strings.HasPrefix(subj, "$JS."))
		require_False(t, strings.Contains(subj, "STREAM.PURGE"))
		require_False(t, strings.Contains(subj, "STREAM.DELETE"))
		require_False(t, strings.Contains(subj, "STREAM.CREATE"))
	}
	// jsconsumer emits 7 subjects, jsconsumeradmin 14.
	require_Len(t, len(res.Pub.Allow), 21)
}

// The cartesian product expands in argument order, with the first argument as
// the outer loop.
func TestJWTXPermissionsConsumerCartesianProduct(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "s:alpha", "s:beta", "c:one", "c:two")
	xp := mustXPermissions(t, `{"consumer":[{"op":"ro","stream":"{{tag(s)}}","consumer":"{{tag(c)}}"}]}`)
	res, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_NoError(t, err)
	var expected []string
	for _, s := range []string{"alpha", "beta"} {
		expected = append(expected, macroConsumerPubSubjects(s, "one")...)
		second := macroConsumerPubSubjects(s, "two")
		expected = append(expected, second[1:]...)
	}
	require_Len(t, len(res.Pub.Allow), len(expected))
	for i, subj := range expected {
		require_Equal(t, res.Pub.Allow[i], subj)
	}

	// A literal mixed with a tag gives one set per tag value.
	xp = mustXPermissions(t, `{"consumer":[{"op":"admin","stream":"orders","consumer":"{{tag(c)}}"}]}`)
	res, err = processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_NoError(t, err)
	second := macroConsumerAdminPubSubjects("orders", "two")
	expected = append(macroConsumerAdminPubSubjects("orders", "one"), second[1:]...)
	require_Len(t, len(res.Pub.Allow), len(expected))
	for i, subj := range expected {
		require_Equal(t, res.Pub.Allow[i], subj)
	}
}

// A consumer has no derivable data subject, so the consumer macros are
// rejected in subscribe lists, as the stream macros are.
func TestJWTXPermissionsConsumerNotInSubscribeList(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "s:orders", "c:workers")
	xp := mustXPermissions(t, `{"consumer":[{"op":"admin","stream":"{{tag(s)}}","consumer":"{{tag(c)}}"}]}`)
	res, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_NoError(t, err)
	require_Len(t, len(res.Sub.Allow), 0)
	require_Len(t, len(res.Sub.Deny), 0)
}

// Whitespace around every part of the argument list is trimmed.
func TestJWTXPermissionsConsumerArgumentWhitespace(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "js:orders")
	xp := mustXPermissions(t, `{"consumer":[{"op":"ro","stream":"{{ tag(js) }}","consumer":"workers"}]}`)
	res, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_NoError(t, err)
	requireSameSubjects(t, res.Pub.Allow, macroConsumerPubSubjects("orders", "workers"))
}

// A wrong number of positional arguments, or an unknown, empty, repeated or
// misplaced named argument, is the upstream "is not defined" error. The only
// named argument the grammar defines is the trailing "domain", which
// TestJWTXPermissionsDomain* covers.
func TestJWTXPermissionsArgumentListErrors(t *testing.T) {
	for _, raw := range []string{
		`{"consumer":[{"op":"ro","stream":"orders"}]}`,
		`{"consumer":[{"op":"ro","stream":"orders","consumer":"workers","extra":true}]}`,
		`{"consumer":[{"op":"rw","stream":"orders","consumer":"workers"}]}`,
		`{"stream":[{"op":"ro","stream":"orders","consumer":"workers"}]}`,
		`{"jsinfo":{"domain":"hub"}}`,
	} {
		t.Run(raw, func(t *testing.T) {
			f := newXPermissionsRawFixture(t, raw)
			_, _, _, err := f.server.verifyAccountClaimsWithXPermissions(f.token)
			require_Error(t, err)
		})
	}
}

// A tag with no value emits nothing in an allow list and is an error in a
// deny list, for every positional argument.
func TestJWTXPermissionsConsumerMissingValueFailsClosed(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "s:orders") // no "c:" tag at all
	xp := mustXPermissions(t, `{"consumer":[{"op":"ro","stream":"{{tag(s)}}","consumer":"{{tag(c)}}"}]}`)
	_, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_Error(t, err)
	require_Contains(t, err.Error(), "not defined")
}

// A consumer name that carries a separator, a wildcard or a template token is
// skipped in an allow list and is an error in a deny list.
func TestJWTXPermissionsConsumerInvalidName(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "s:orders",
		"c:good", "c:bad.name", "c:wild*", "c:{{tag(s)}}", "c:")
	xp := mustXPermissions(t, `{"consumer":[{"op":"ro","stream":"{{tag(s)}}","consumer":"{{tag(c)}}"}]}`)
	_, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_Error(t, err)
	require_Contains(t, err.Error(), "generated invalid subject")
}

// End-to-end coverage of the consumer level macros with real nats.go clients
// on both APIs. See the v2 design spec, section 10 item 3.
//
// The run is repeated with the v1 and the v2 ack and flow control formats,
// because the consumer set carries one ack pattern per format and only a real
// ack proves the pattern matches.
func TestJWTXPermissionsConsumerEndToEnd(t *testing.T) {
	for _, test := range []struct {
		name string
		// Number of tokens in the ack reply subject of that format. v1 is
		// $JS.ACK.<stream>.<consumer>.<dc>.<sseq>.<dseq>.<ts>.<pending>, v2
		// inserts the domain and the account hash.
		ackTokens int
		extra     string
	}{
		{"ack_v1", 9, _EMPTY_},
		{"ack_v2", 11, "feature_flags { js_ack_fc_v2: true }"},
	} {
		t.Run(test.name, func(t *testing.T) {
			testJWTTemplateMacroConsumer(t, test.ackTokens, test.extra)
		})
	}
}

func testJWTTemplateMacroConsumer(t *testing.T, ackTokens int, extraConf string) {
	sysKp, syspub := createKey(t)
	sysJwt := encodeClaim(t, jwt.NewAccountClaims(syspub), syspub)
	sysCreds := newUser(t, sysKp)

	accKp, accPub := createKey(t)
	accClaim := jwt.NewAccountClaims(accPub)
	accClaim.Name = "acc"
	accClaim.Limits.JetStreamTieredLimits["R1"] = jwt.JetStreamLimits{
		DiskStorage: jwt.NoLimit, MemoryStorage: jwt.NoLimit,
		Consumer: jwt.NoLimit, Streams: jwt.NoLimit,
	}
	scopedKp, scopedPub := createKey(t)
	scope := jwt.NewUserScope()
	scope.Key = scopedPub
	scope.Template.Sub.Allow.Add("_INBOX.>")
	accClaim.SigningKeys.AddScopedSigner(scope)
	accJwt := encodeAccountClaimWithXPermissions(t, accClaim, map[string]string{scopedPub: `{
		"consumer":[{"op":"ro","stream":"orders","consumer":"shared"},{"op":"admin","stream":"orders","consumer":"{{tag(own)}}"}]
	}`})
	adminCreds := newUser(t, accKp)

	ukp, _ := nkeys.CreateUser()
	seed, _ := ukp.Seed()
	upub, _ := ukp.PublicKey()
	uclaim := newJWTTestUserClaims()
	uclaim.Subject = upub
	uclaim.SetScoped(true)
	uclaim.IssuerAccount = accPub
	uclaim.Tags.Add("own:mine")
	ujwt, err := uclaim.Encode(scopedKp)
	require_NoError(t, err)
	userCreds := genCredsFile(t, ujwt, seed)

	cf := createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:-1
		server_name: s1
		jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}
		operator: %s
		system_account: %s
		resolver: {
			type: full
			dir: '%s'
		}
		%s
	`, t.TempDir(), ojwt, syspub, t.TempDir(), extraConf)))
	s, _ := RunServerWithConfig(cf)
	defer s.Shutdown()
	updateJwt(t, s.ClientURL(), sysCreds, sysJwt, 1)
	updateJwt(t, s.ClientURL(), sysCreds, accJwt, 1)

	// The administrator is an unscoped user of the same account. It owns the
	// stream, the filtered durable the scoped user may use, and a third
	// durable the scoped user may not touch.
	anc := natsConnect(t, s.ClientURL(), nats.UserCredentials(adminCreds))
	defer anc.Close()
	ajs, err := anc.JetStream()
	require_NoError(t, err)
	_, err = ajs.AddStream(&nats.StreamConfig{Name: "orders", Subjects: []string{"orders.>"}})
	require_NoError(t, err)
	for i := 0; i < 5; i++ {
		_, err = ajs.Publish(fmt.Sprintf("orders.eu.%d", i), []byte("m"))
		require_NoError(t, err)
		_, err = ajs.Publish(fmt.Sprintf("orders.us.%d", i), []byte("m"))
		require_NoError(t, err)
	}
	_, err = ajs.AddConsumer("orders", &nats.ConsumerConfig{
		Durable: "shared", FilterSubject: "orders.eu.>", AckPolicy: nats.AckExplicitPolicy})
	require_NoError(t, err)
	_, err = ajs.AddConsumer("orders", &nats.ConsumerConfig{
		Durable: "third", FilterSubject: "orders.us.>", AckPolicy: nats.AckExplicitPolicy})
	require_NoError(t, err)

	// The scoped user has only the macro permissions. Denied publishes show
	// up as async permission violations; count them so the negative cases
	// below are known to fail for that reason and not for an unrelated
	// timeout. The text of each violation names the subject the client used.
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
	nc := natsConnect(t, s.ClientURL(), nats.UserCredentials(userCreds),
		nats.PermissionErrOnSubscribe(true),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			if errors.Is(err, nats.ErrPermissionViolation) {
				violations.Add(1)
				vmu.Lock()
				vmsgs = append(vmsgs, err.Error())
				vmu.Unlock()
			}
		}))
	defer nc.Close()
	js, err := nc.JetStream(nats.MaxWait(time.Second))
	require_NoError(t, err)
	njs, err := jetstream.New(nc, jetstream.WithDefaultTimeout(time.Second))
	require_NoError(t, err)
	ctx := context.Background()

	// An ack is fire and forget, so a denied ack only shows up as a pending
	// ack that never clears. Both are checked.
	requireAckLands := func(t *testing.T, before int32, info func() (uint64, error)) {
		t.Helper()
		checkFor(t, 2*time.Second, 25*time.Millisecond, func() error {
			pending, err := info()
			if err != nil {
				return err
			}
			if pending != 0 {
				return fmt.Errorf("still %d acks pending", pending)
			}
			return nil
		})
		require_Equal(t, violations.Load(), before)
	}
	// A denied publish is also fire and forget when the client does not wait
	// for a reply, so wait for the violation instead.
	requireViolation := func(t *testing.T, fn func()) {
		t.Helper()
		before := violations.Load()
		fn()
		checkFor(t, 2*time.Second, 25*time.Millisecond, func() error {
			if violations.Load() <= before {
				return fmt.Errorf("no permission violation seen")
			}
			return nil
		})
	}
	sharedPending := func() (uint64, error) {
		ci, err := js.ConsumerInfo("orders", "shared")
		if err != nil {
			return 0, err
		}
		return uint64(ci.NumAckPending), nil
	}

	t.Run("bind with BindStream", func(t *testing.T) {
		// The filter subject must match the consumer's, so the user consumes
		// exactly what the administrator allowed.
		sub, err := js.PullSubscribe("orders.eu.>", "shared", nats.BindStream("orders"))
		require_NoError(t, err)
		defer sub.Unsubscribe()
		before := violations.Load()
		msgs, err := sub.Fetch(1, nats.MaxWait(time.Second))
		require_NoError(t, err)
		require_Len(t, len(msgs), 1)
		require_True(t, strings.HasPrefix(msgs[0].Subject, "orders.eu."))
		// The server must use the ack format this run configured, otherwise
		// the two runs would exercise the same pattern.
		require_Len(t, len(strings.Split(msgs[0].Reply, ".")), ackTokens)
		require_NoError(t, msgs[0].Ack())
		requireAckLands(t, before, sharedPending)
	})

	t.Run("bind with Bind", func(t *testing.T) {
		sub, err := js.PullSubscribe("orders.eu.>", "shared", nats.Bind("orders", "shared"))
		require_NoError(t, err)
		defer sub.Unsubscribe()
		before := violations.Load()
		msgs, err := sub.Fetch(1, nats.MaxWait(time.Second))
		require_NoError(t, err)
		require_Len(t, len(msgs), 1)
		require_NoError(t, msgs[0].Ack())
		requireAckLands(t, before, sharedPending)
	})

	t.Run("bind with the new api", func(t *testing.T) {
		cons, err := njs.Consumer(ctx, "orders", "shared")
		require_NoError(t, err)
		before := violations.Load()
		batch, err := cons.Fetch(1, jetstream.FetchMaxWait(time.Second))
		require_NoError(t, err)
		var got int
		for msg := range batch.Messages() {
			require_NoError(t, msg.Ack())
			got++
		}
		require_NoError(t, batch.Error())
		require_Len(t, got, 1)
		requireAckLands(t, before, func() (uint64, error) {
			ci, err := cons.Info(ctx)
			if err != nil {
				return 0, err
			}
			return uint64(ci.NumAckPending), nil
		})
	})

	t.Run("cannot manage the shared consumer", func(t *testing.T) {
		requireViolation(t, func() {
			require_Error(t, js.DeleteConsumer("orders", "shared"))
		})
		requireViolation(t, func() {
			_, err := njs.CreateOrUpdateConsumer(ctx, "orders", jetstream.ConsumerConfig{
				Durable: "shared", FilterSubject: "orders.eu.>", AckPolicy: jetstream.AckExplicitPolicy})
			require_Error(t, err)
		})
		// The consumer is still there and still usable.
		_, err := js.ConsumerInfo("orders", "shared")
		require_NoError(t, err)
	})

	t.Run("cannot touch a third consumer", func(t *testing.T) {
		// Consumer info is denied, so the client cannot even bind. The pull
		// request is sent raw to show that MSG.NEXT itself is denied.
		requireViolation(t, func() {
			sub, err := nc.SubscribeSync(nats.NewInbox())
			require_NoError(t, err)
			defer sub.Unsubscribe()
			require_NoError(t, nc.PublishRequest("$JS.API.CONSUMER.MSG.NEXT.orders.third",
				sub.Subject, []byte(`{"batch":1,"no_wait":true}`)))
			require_NoError(t, nc.Flush())
			_, err = sub.NextMsg(500 * time.Millisecond)
			require_Error(t, err)
		})
		requireViolation(t, func() {
			_, err := js.ConsumerInfo("orders", "third")
			require_Error(t, err)
		})
	})

	t.Run("owns its own consumer", func(t *testing.T) {
		cons, err := njs.CreateOrUpdateConsumer(ctx, "orders", jetstream.ConsumerConfig{
			Durable: "mine", FilterSubject: "orders.us.>", AckPolicy: jetstream.AckExplicitPolicy})
		require_NoError(t, err)
		before := violations.Load()
		batch, err := cons.Fetch(1, jetstream.FetchMaxWait(time.Second))
		require_NoError(t, err)
		var got int
		for msg := range batch.Messages() {
			require_True(t, strings.HasPrefix(msg.Subject(), "orders.us."))
			require_NoError(t, msg.Ack())
			got++
		}
		require_NoError(t, batch.Error())
		require_Len(t, got, 1)
		requireAckLands(t, before, func() (uint64, error) {
			ci, err := cons.Info(ctx)
			if err != nil {
				return 0, err
			}
			return uint64(ci.NumAckPending), nil
		})
		require_NoError(t, njs.DeleteConsumer(ctx, "orders", "mine"))

		// Only the consumer the tag names.
		requireViolation(t, func() {
			_, err := njs.CreateOrUpdateConsumer(ctx, "orders", jetstream.ConsumerConfig{
				Durable: "other", FilterSubject: "orders.us.>", AckPolicy: jetstream.AckExplicitPolicy})
			require_Error(t, err)
		})
	})

	// Every negative case must have produced a permission violation: delete
	// and recreate of the shared consumer, pull and info on the third
	// consumer, and the create of a consumer the tag does not name.
	require_True(t, violations.Load() >= 5)
}
