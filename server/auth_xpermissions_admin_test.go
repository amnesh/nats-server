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

// End-to-end coverage of the admin level macros and of jsinfo, with real
// nats.go clients on both APIs. See the v2 design spec, section 10 item 2.
//
// The run is repeated with the v1 and the v2 ack and flow control formats,
// because the read set carries one pattern per format and only a real ack
// proves the pattern matches.
func TestJWTXPermissionsAdminStreamInfoEndToEnd(t *testing.T) {
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
			testJWTXPermissionsAdminStreamInfo(t, test.ackTokens, test.extra)
		})
	}
}

func testJWTXPermissionsAdminStreamInfo(t *testing.T, ackTokens int, extraConf string) {
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
	scope.Template.Pub.Allow.Add("orders.>", "events.>")
	scope.Template.Sub.Allow.Add("_INBOX.>")
	accClaim.SigningKeys.AddScopedSigner(scope)
	accJwt := encodeAccountClaimWithXPermissions(t, accClaim, map[string]string{scopedPub: `{
		"kv":[{"op":"admin","bucket":"{{tag(kva)}}"}],
		"obj":[{"op":"admin","bucket":"{{tag(obja)}}"}],
		"stream":[{"op":"ro","stream":"{{tag(js)}}"},{"op":"admin","stream":"{{tag(jsa)}}"}],
		"jsinfo":true
	}`})
	adminCreds := newUser(t, accKp)

	ukp, _ := nkeys.CreateUser()
	seed, _ := ukp.Seed()
	upub, _ := ukp.PublicKey()
	uclaim := newJWTTestUserClaims()
	uclaim.Subject = upub
	uclaim.SetScoped(true)
	uclaim.IssuerAccount = accPub
	// The jwt library lowercases tag values, so the names are lowercase.
	uclaim.Tags.Add("kva:cfg", "obja:blobs", "js:orders", "jsa:events")
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

	// The admin is an unscoped user of the same account. It creates the
	// streams the scoped user works on, plus one stream it may not touch.
	anc := natsConnect(t, s.ClientURL(), nats.UserCredentials(adminCreds))
	defer anc.Close()
	ajs, err := anc.JetStream()
	require_NoError(t, err)
	for _, name := range []string{"orders", "events", "other"} {
		_, err = ajs.AddStream(&nats.StreamConfig{Name: name, Subjects: []string{name + ".>"}})
		require_NoError(t, err)
		for i := 0; i < 3; i++ {
			_, err = ajs.Publish(fmt.Sprintf("%s.%d", name, i), []byte("m"))
			require_NoError(t, err)
		}
	}

	// The scoped user has only the macro permissions. Denied publishes show
	// up as async permission violations; count them so the negative cases
	// below are known to fail for that reason and not for an unrelated
	// timeout. The text of each violation names the subject the client used.
	var violations atomic.Int32
	var vmu sync.Mutex
	var vmsgs []string
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
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

	t.Run("kvadmin", func(t *testing.T) {
		kv, err := js.CreateKeyValue(&nats.KeyValueConfig{Bucket: "cfg", History: 3})
		require_NoError(t, err)
		_, err = kv.Put("k", []byte("v"))
		require_NoError(t, err)
		e, err := kv.Get("k")
		require_NoError(t, err)
		require_Equal(t, string(e.Value()), "v")
		require_NoError(t, js.DeleteKeyValue("cfg"))

		nkv, err := njs.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "cfg", History: 3})
		require_NoError(t, err)
		_, err = nkv.Put(ctx, "k", []byte("v"))
		require_NoError(t, err)
		ne, err := nkv.Get(ctx, "k")
		require_NoError(t, err)
		require_Equal(t, string(ne.Value()), "v")
		require_NoError(t, njs.DeleteKeyValue(ctx, "cfg"))

		// A bucket the macro does not name.
		_, err = js.CreateKeyValue(&nats.KeyValueConfig{Bucket: "nope"})
		require_Error(t, err)
	})

	t.Run("objadmin", func(t *testing.T) {
		obs, err := js.CreateObjectStore(&nats.ObjectStoreConfig{Bucket: "blobs"})
		require_NoError(t, err)
		_, err = obs.PutBytes("f", []byte("hello"))
		require_NoError(t, err)
		b, err := obs.GetBytes("f")
		require_NoError(t, err)
		require_Equal(t, string(b), "hello")
		require_NoError(t, obs.Seal())
		require_NoError(t, js.DeleteObjectStore("blobs"))

		nobs, err := njs.CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: "blobs"})
		require_NoError(t, err)
		_, err = nobs.PutBytes(ctx, "g", []byte("hello"))
		require_NoError(t, err)
		nb, err := nobs.GetBytes(ctx, "g")
		require_NoError(t, err)
		require_Equal(t, string(nb), "hello")
		require_NoError(t, nobs.Seal(ctx))
		require_NoError(t, njs.DeleteObjectStore(ctx, "blobs"))

		_, err = js.CreateObjectStore(&nats.ObjectStoreConfig{Bucket: "nope2"})
		require_Error(t, err)
	})

	t.Run("jsread", func(t *testing.T) {
		// Durable pull consumer, fetch and ack. The stream is found through
		// $JS.API.STREAM.NAMES, which jsinfo grants.
		sub, err := js.PullSubscribe("orders.>", "workers")
		require_NoError(t, err)
		before := violations.Load()
		msgs, err := sub.Fetch(1, nats.MaxWait(time.Second))
		require_NoError(t, err)
		require_Len(t, len(msgs), 1)
		// The server must use the ack format this run configured, otherwise
		// the two runs would exercise the same pattern.
		require_Len(t, len(strings.Split(msgs[0].Reply, ".")), ackTokens)
		require_NoError(t, msgs[0].Ack())
		requireAckLands(t, before, func() (uint64, error) {
			ci, err := js.ConsumerInfo("orders", "workers")
			if err != nil {
				return 0, err
			}
			return uint64(ci.NumAckPending), nil
		})

		// Ephemeral push consumer delivering to an inbox.
		psub, err := js.SubscribeSync("orders.>", nats.BindStream("orders"))
		require_NoError(t, err)
		m, err := psub.NextMsg(2 * time.Second)
		require_NoError(t, err)
		require_NoError(t, m.Ack())
		require_NoError(t, psub.Unsubscribe())

		raw, err := js.GetMsg("orders", 1)
		require_NoError(t, err)
		require_NotNil(t, raw)

		var found bool
		for name := range js.ConsumerNames("orders") {
			if name == "workers" {
				found = true
			}
		}
		require_True(t, found)
		// The subscription is left alive on purpose: nats.go deletes the
		// consumer it created on Unsubscribe.
		require_NoError(t, js.DeleteConsumer("orders", "workers"))

		stream, err := njs.Stream(ctx, "orders")
		require_NoError(t, err)
		cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
			Durable: "w2", FilterSubject: "orders.>", AckPolicy: jetstream.AckExplicitPolicy})
		require_NoError(t, err)
		before = violations.Load()
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
		require_NoError(t, stream.DeleteConsumer(ctx, "w2"))

		// Read does not grant purge or stream management.
		require_Error(t, js.PurgeStream("orders"))
		require_Error(t, js.DeleteStream("orders"))
	})

	t.Run("jsadmin", func(t *testing.T) {
		require_NoError(t, js.PurgeStream("events"))

		si, err := js.StreamInfo("events")
		require_NoError(t, err)
		cfg := si.Config
		cfg.Description = "updated by the scoped user"
		si, err = js.UpdateStream(&cfg)
		require_NoError(t, err)
		require_Equal(t, si.Config.Description, "updated by the scoped user")

		pa, err := js.Publish("events.a", []byte("m"))
		require_NoError(t, err)
		require_NoError(t, js.DeleteMsg("events", pa.Sequence))

		// Admin is cumulative, so the read set works on this stream too.
		_, err = js.Publish("events.b", []byte("m"))
		require_NoError(t, err)
		sub, err := js.PullSubscribe("events.>", "ev", nats.BindStream("events"))
		require_NoError(t, err)
		before := violations.Load()
		msgs, err := sub.Fetch(1, nats.MaxWait(time.Second))
		require_NoError(t, err)
		require_Len(t, len(msgs), 1)
		require_NoError(t, msgs[0].Ack())
		requireAckLands(t, before, func() (uint64, error) {
			ci, err := js.ConsumerInfo("events", "ev")
			if err != nil {
				return 0, err
			}
			return uint64(ci.NumAckPending), nil
		})

		require_NoError(t, js.DeleteStream("events"))
		_, err = js.AddStream(&nats.StreamConfig{Name: "events", Subjects: []string{"events.>"}})
		require_NoError(t, err)

		// Admin is bound to the named stream only.
		_, err = js.AddStream(&nats.StreamConfig{Name: "brandnew", Subjects: []string{"brandnew.>"}})
		require_Error(t, err)
		require_Error(t, js.PurgeStream("other"))
		_, err = js.StreamInfo("other")
		require_Error(t, err)
	})

	t.Run("jsinfo", func(t *testing.T) {
		ai, err := js.AccountInfo()
		require_NoError(t, err)
		require_NotNil(t, ai)

		seen := map[string]bool{}
		for name := range js.StreamNames() {
			seen[name] = true
		}
		require_True(t, seen["orders"])
		require_True(t, seen["events"])
		require_True(t, seen["other"])

		nai, err := njs.AccountInfo(ctx)
		require_NoError(t, err)
		require_NotNil(t, nai)
	})

	// Every negative case must have produced a permission violation: the two
	// bucket creates, purge and delete of the jsread stream, and the create,
	// purge and info of the streams jsadmin does not name.
	require_True(t, violations.Load() >= 7)
}
