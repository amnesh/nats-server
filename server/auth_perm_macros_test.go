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
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

// The expected expansions are written out literally so that the tests do not
// depend on the production table.
func macroReadPubSubjects(stream string) []string {
	return []string{
		"$JS.API.STREAM.INFO." + stream,
		"$JS.API.STREAM.MSG.GET." + stream,
		"$JS.API.DIRECT.GET." + stream,
		"$JS.API.DIRECT.GET." + stream + ".>",
		"$JS.API.CONSUMER.CREATE." + stream,
		"$JS.API.CONSUMER.CREATE." + stream + ".>",
		"$JS.API.CONSUMER.INFO." + stream + ".>",
		"$JS.API.CONSUMER.DELETE." + stream + ".>",
		"$JS.API.CONSUMER.MSG.NEXT." + stream + ".>",
		"$JS.FC." + stream + ".>",
		"$JS.FC.*.*." + stream + ".>",
	}
}

func macroWritePubSubjects(stream, data string) []string {
	return append(macroReadPubSubjects(stream), data+".>", "$JS.API.STREAM.PURGE."+stream)
}

func macroTestUserClaims(t *testing.T, tags ...string) (*jwt.UserClaims, *Account) {
	t.Helper()
	kp, _ := nkeys.CreateAccount()
	aPub, _ := kp.PublicKey()
	ukp, _ := nkeys.CreateUser()
	upub, _ := ukp.PublicKey()
	uc := newJWTTestUserClaims()
	uc.Name = "myname"
	uc.Subject = upub
	uc.SetScoped(true)
	uc.IssuerAccount = aPub
	for _, tag := range tags {
		uc.Tags.Add(tag)
	}
	acc := &Account{nameTag: "accname", tags: []string{"kv:acckv"}}
	return uc, acc
}

func requireSameSubjects(t *testing.T, res jwt.StringList, expected []string) {
	t.Helper()
	if len(res) != len(expected) {
		t.Fatalf("expected %d subjects, got %d: %v", len(expected), len(res), res)
	}
	for _, s := range expected {
		if !res.Contains(s) {
			t.Fatalf("expected %q in %v", s, res)
		}
	}
}

func TestJWTTemplateMacroKVReadWrite(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "kv:foo")
	lim := jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("{{kvrw(tag(kv))}}")
	lim.Sub.Allow.Add("{{kvrw(tag(kv))}}")

	res, err := processUserPermissionsTemplate(lim, uc, acc)
	require_NoError(t, err)
	requireSameSubjects(t, res.Pub.Allow, macroWritePubSubjects("KV_foo", "$KV.foo"))
	requireSameSubjects(t, res.Sub.Allow, []string{"$KV.foo.>"})
	require_Len(t, len(res.Pub.Deny), 0)
	require_Len(t, len(res.Sub.Deny), 0)
}

func TestJWTTemplateMacroKVReadOnly(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "kv:foo")
	lim := jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("{{kvro(tag(kv))}}")
	lim.Sub.Allow.Add("{{kvro(tag(kv))}}")

	res, err := processUserPermissionsTemplate(lim, uc, acc)
	require_NoError(t, err)
	requireSameSubjects(t, res.Pub.Allow, macroReadPubSubjects("KV_foo"))
	require_False(t, res.Pub.Allow.Contains("$KV.foo.>"))
	require_False(t, res.Pub.Allow.Contains("$JS.API.STREAM.PURGE.KV_foo"))
	requireSameSubjects(t, res.Sub.Allow, []string{"$KV.foo.>"})
}

func TestJWTTemplateMacroObjectStore(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "obj:img")
	lim := jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("{{objrw(tag(obj))}}")
	lim.Pub.Deny.Add("{{objro(tag(obj))}}")
	lim.Sub.Allow.Add("{{objro(tag(obj))}}")
	lim.Sub.Deny.Add("{{objrw(tag(obj))}}")

	res, err := processUserPermissionsTemplate(lim, uc, acc)
	require_NoError(t, err)
	requireSameSubjects(t, res.Pub.Allow, macroWritePubSubjects("OBJ_img", "$O.img"))
	requireSameSubjects(t, res.Pub.Deny, macroReadPubSubjects("OBJ_img"))
	requireSameSubjects(t, res.Sub.Allow, []string{"$O.img.>"})
	requireSameSubjects(t, res.Sub.Deny, []string{"$O.img.>"})
}

func TestJWTTemplateMacroMultipleValuesAndPassthrough(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "kv:a", "kv:b")
	lim := jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("{{kvro(tag(kv))}}", "plain.subject", "tpl.{{tag(kv)}}")
	lim.Sub.Allow.Add("_INBOX.>", "{{kvro(tag(kv))}}")

	res, err := processUserPermissionsTemplate(lim, uc, acc)
	require_NoError(t, err)
	expected := append(macroReadPubSubjects("KV_a"), macroReadPubSubjects("KV_b")...)
	expected = append(expected, "plain.subject", "tpl.a", "tpl.b")
	requireSameSubjects(t, res.Pub.Allow, expected)
	requireSameSubjects(t, res.Sub.Allow, []string{"_INBOX.>", "$KV.a.>", "$KV.b.>"})
}

func TestJWTTemplateMacroArgumentForms(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "kv:foo")
	for _, test := range []struct{ arg, bucket string }{
		{"config", "config"}, // literal bucket name
		{"tag(KV)", "foo"},   // tag keys are case insensitive
		{"account-tag(kv)", "acckv"},
		{"name()", "myname"},
		{"subject()", uc.Subject},
		{"account-name()", "accname"},
		{"account-subject()", uc.IssuerAccount},
	} {
		t.Run(test.arg, func(t *testing.T) {
			lim := jwt.UserPermissionLimits{}
			lim.Pub.Allow.Add(fmt.Sprintf("{{KVRO(%s)}}", test.arg))
			res, err := processUserPermissionsTemplate(lim, uc, acc)
			require_NoError(t, err)
			requireSameSubjects(t, res.Pub.Allow, macroReadPubSubjects("KV_"+test.bucket))
		})
	}
}

func TestJWTTemplateMacroMissingValueFailsClosed(t *testing.T) {
	uc, acc := macroTestUserClaims(t) // no tags at all
	lim := jwt.UserPermissionLimits{}
	lim.Sub.Allow.Add("{{kvro(tag(kv))}}")
	lim.Pub.Allow.Add("{{kvrw(tag(kv))}}")

	res, err := processUserPermissionsTemplate(lim, uc, acc)
	require_NoError(t, err)
	require_Len(t, len(res.Sub.Allow), 0)
	require_True(t, res.Sub.Deny.Contains(">"))
	require_Len(t, len(res.Pub.Allow), 0)
	require_True(t, res.Pub.Deny.Contains(">"))

	// In deny lists a missing value is an error, as for plain tags.
	for _, mk := range []func(*jwt.UserPermissionLimits){
		func(l *jwt.UserPermissionLimits) { l.Pub.Deny.Add("{{kvrw(tag(kv))}}") },
		func(l *jwt.UserPermissionLimits) { l.Sub.Deny.Add("{{kvrw(tag(kv))}}") },
	} {
		lim := jwt.UserPermissionLimits{}
		mk(&lim)
		_, err := processUserPermissionsTemplate(lim, uc, acc)
		require_Error(t, err)
		require_Contains(t, err.Error(), "generated invalid subject")
	}
}

func TestJWTTemplateMacroInvalidBucketName(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "kv:good", "kv:bad.name", "kv:wild*", "kv:full>", "kv:")
	lim := jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("{{kvro(tag(kv))}}")

	// Allow lists skip invalid values.
	res, err := processUserPermissionsTemplate(lim, uc, acc)
	require_NoError(t, err)
	requireSameSubjects(t, res.Pub.Allow, macroReadPubSubjects("KV_good"))

	// Deny lists fail on invalid values.
	lim = jwt.UserPermissionLimits{}
	lim.Pub.Deny.Add("{{kvro(tag(kv))}}")
	_, err = processUserPermissionsTemplate(lim, uc, acc)
	require_Error(t, err)
	require_Contains(t, err.Error(), "generated invalid subject")

	// An invalid literal in an allow list emits nothing and fails closed.
	lim = jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("{{kvro(bad.literal)}}")
	res, err = processUserPermissionsTemplate(lim, uc, acc)
	require_NoError(t, err)
	require_Len(t, len(res.Pub.Allow), 0)
	require_True(t, res.Pub.Deny.Contains(">"))
}

func TestJWTTemplateMacroMustBeWholeEntry(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "kv:foo")
	for _, entry := range []string{
		"foo.{{kvrw(tag(kv))}}",
		"{{kvrw(tag(kv))}}.bar",
		"{{kvrw(tag(kv))}}{{kvro(tag(kv))}}",
		"{{kvrw(tag(kv))}}.{{tag(kv)}}",
	} {
		t.Run(entry, func(t *testing.T) {
			lim := jwt.UserPermissionLimits{}
			lim.Pub.Allow.Add(entry)
			_, err := processUserPermissionsTemplate(lim, uc, acc)
			require_Error(t, err)
			require_Contains(t, err.Error(), "macro")
		})
	}
}

func TestJWTTemplateMacroUnknownOperationStillErrors(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "kv:foo")
	for _, entry := range []string{
		"{{kvxx(tag(kv))}}",
		"{{kvro(tag(kv)}}",
		"{{kvro(nope(kv))}}",
		"{{kvro()}}",
		"{{kvro(tag())}}",
	} {
		t.Run(entry, func(t *testing.T) {
			lim := jwt.UserPermissionLimits{}
			lim.Pub.Allow.Add(entry)
			_, err := processUserPermissionsTemplate(lim, uc, acc)
			require_Error(t, err)
			require_Contains(t, err.Error(), "not defined")
		})
	}
}

func TestJWTTemplateMacroExpansionLimit(t *testing.T) {
	mkTags := func(n int) []string {
		tags := make([]string, 0, n)
		for i := 0; i < n; i++ {
			tags = append(tags, fmt.Sprintf("kv:b%d", i))
		}
		return tags
	}
	// 300 buckets x 11 subjects fits under the cap.
	uc, acc := macroTestUserClaims(t, mkTags(300)...)
	lim := jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("{{kvro(tag(kv))}}")
	res, err := processUserPermissionsTemplate(lim, uc, acc)
	require_NoError(t, err)
	require_Len(t, len(res.Pub.Allow), 300*11)

	// 400 buckets x 11 subjects exceeds the cap.
	uc, acc = macroTestUserClaims(t, mkTags(400)...)
	_, err = processUserPermissionsTemplate(lim, uc, acc)
	require_Error(t, err, errPermTemplateExpansionLimit)
}

// The end-to-end test checks that the subject sets are sufficient for the
// nats.go legacy and new JetStream APIs, and that nothing outside the tagged
// buckets is granted.
func TestJWTTemplateMacroKVObjectStoreEndToEnd(t *testing.T) {
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
	scope.Template.Pub.Allow.Add(
		"{{kvrw(tag(kv))}}", "{{kvro(tag(kvr))}}",
		"{{objrw(tag(obj))}}", "{{objro(tag(objr))}}")
	scope.Template.Sub.Allow.Add("_INBOX.>", "{{kvrw(tag(kv))}}")
	accClaim.SigningKeys.AddScopedSigner(scope)
	accJwt := encodeClaim(t, accClaim, accPub)
	adminCreds := newUser(t, accKp)

	ukp, _ := nkeys.CreateUser()
	seed, _ := ukp.Seed()
	upub, _ := ukp.PublicKey()
	uclaim := newJWTTestUserClaims()
	uclaim.Subject = upub
	uclaim.SetScoped(true)
	uclaim.IssuerAccount = accPub
	uclaim.Tags.Add("kv:rw", "kvr:ro", "kvr:nd", "obj:orw", "objr:oro")
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
	`, t.TempDir(), ojwt, syspub, t.TempDir())))
	s, _ := RunServerWithConfig(cf)
	defer s.Shutdown()
	updateJwt(t, s.ClientURL(), sysCreds, sysJwt, 1)
	updateJwt(t, s.ClientURL(), sysCreds, accJwt, 1)

	// The admin creates the buckets and seeds the read-only ones.
	anc := natsConnect(t, s.ClientURL(), nats.UserCredentials(adminCreds))
	defer anc.Close()
	ajs, err := anc.JetStream()
	require_NoError(t, err)
	for _, b := range []string{"rw", "ro", "none"} {
		_, err = ajs.CreateKeyValue(&nats.KeyValueConfig{Bucket: b, History: 5})
		require_NoError(t, err)
	}
	// A bucket without direct get exercises the STREAM.MSG.GET path.
	_, err = ajs.AddStream(&nats.StreamConfig{
		Name: "KV_nd", Subjects: []string{"$KV.nd.>"}, MaxMsgsPerSubject: 1, AllowDirect: false})
	require_NoError(t, err)
	for _, b := range []string{"ro", "nd"} {
		kv, err := ajs.KeyValue(b)
		require_NoError(t, err)
		_, err = kv.Put("seed", []byte("v"))
		require_NoError(t, err)
	}
	for _, b := range []string{"orw", "oro", "onone"} {
		_, err = ajs.CreateObjectStore(&nats.ObjectStoreConfig{Bucket: b})
		require_NoError(t, err)
	}
	seedObs, err := ajs.ObjectStore("oro")
	require_NoError(t, err)
	_, err = seedObs.PutBytes("seed", []byte("data"))
	require_NoError(t, err)

	// The scoped user has only the macro permissions. Denied publishes show
	// up as async permission violations; count them so the negative cases
	// below are known to fail for that reason and not for an unrelated timeout.
	var violations atomic.Int32
	nc := natsConnect(t, s.ClientURL(), nats.UserCredentials(userCreds),
		nats.PermissionErrOnSubscribe(true),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			if errors.Is(err, nats.ErrPermissionViolation) {
				violations.Add(1)
			}
		}))
	defer nc.Close()
	js, err := nc.JetStream(nats.MaxWait(time.Second))
	require_NoError(t, err)
	njs, err := jetstream.New(nc, jetstream.WithDefaultTimeout(time.Second))
	require_NoError(t, err)
	ctx := context.Background()

	t.Run("kv read write legacy api", func(t *testing.T) {
		kv, err := js.KeyValue("rw")
		require_NoError(t, err)
		rev, err := kv.Put("k1", []byte("v1"))
		require_NoError(t, err)
		e, err := kv.Get("k1")
		require_NoError(t, err)
		require_Equal(t, string(e.Value()), "v1")
		_, err = kv.Update("k1", []byte("v2"), rev)
		require_NoError(t, err)
		_, err = kv.Create("k2", []byte("v"))
		require_NoError(t, err)
		h, err := kv.History("k1")
		require_NoError(t, err)
		require_Len(t, len(h), 2)
		keys, err := kv.Keys()
		require_NoError(t, err)
		require_Len(t, len(keys), 2)
		w, err := kv.Watch("k1")
		require_NoError(t, err)
		require_True(t, <-w.Updates() != nil)
		require_NoError(t, w.Stop())
		require_NoError(t, kv.Delete("k2"))
		require_NoError(t, kv.Purge("k2"))
		require_NoError(t, kv.PurgeDeletes(nats.DeleteMarkersOlderThan(-1)))
		_, err = kv.Status()
		require_NoError(t, err)
	})

	t.Run("kv read write new api", func(t *testing.T) {
		kv, err := njs.KeyValue(ctx, "rw")
		require_NoError(t, err)
		_, err = kv.Put(ctx, "n1", []byte("v1"))
		require_NoError(t, err)
		e, err := kv.Get(ctx, "n1")
		require_NoError(t, err)
		require_Equal(t, string(e.Value()), "v1")
		h, err := kv.History(ctx, "n1")
		require_NoError(t, err)
		require_Len(t, len(h), 1)
		w, err := kv.Watch(ctx, "n1")
		require_NoError(t, err)
		require_True(t, <-w.Updates() != nil)
		require_NoError(t, w.Stop())
		lister, err := kv.ListKeys(ctx)
		require_NoError(t, err)
		seen := map[string]bool{}
		for k := range lister.Keys() {
			seen[k] = true
		}
		require_True(t, seen["n1"])
		require_NoError(t, kv.Delete(ctx, "n1"))
		require_NoError(t, kv.PurgeDeletes(ctx, jetstream.DeleteMarkersOlderThan(-1)))
		_, err = kv.Status(ctx)
		require_NoError(t, err)
	})

	t.Run("kv read only", func(t *testing.T) {
		for _, b := range []string{"ro", "nd"} {
			kv, err := js.KeyValue(b)
			require_NoError(t, err)
			e, err := kv.Get("seed")
			require_NoError(t, err)
			require_Equal(t, string(e.Value()), "v")
			keys, err := kv.Keys()
			require_NoError(t, err)
			require_Len(t, len(keys), 1)
			_, err = kv.Put("seed", []byte("x"))
			require_Error(t, err)

			kv2, err := njs.KeyValue(ctx, b)
			require_NoError(t, err)
			e2, err := kv2.Get(ctx, "seed")
			require_NoError(t, err)
			require_Equal(t, string(e2.Value()), "v")
			_, err = kv2.Put(ctx, "seed", []byte("x"))
			require_Error(t, err)
		}
	})

	t.Run("kv not granted", func(t *testing.T) {
		_, err := js.KeyValue("none")
		require_Error(t, err)
		_, err = njs.KeyValue(ctx, "none")
		require_Error(t, err)
	})

	t.Run("raw subscribe", func(t *testing.T) {
		sub, err := nc.SubscribeSync("$KV.rw.>")
		require_NoError(t, err)
		require_NoError(t, nc.Flush())
		kv, err := js.KeyValue("rw")
		require_NoError(t, err)
		_, err = kv.Put("raw", []byte("x"))
		require_NoError(t, err)
		_, err = sub.NextMsg(time.Second)
		require_NoError(t, err)

		denied, err := nc.SubscribeSync("$KV.ro.>")
		require_NoError(t, err)
		_, err = denied.NextMsg(time.Second)
		require_Error(t, err)
		require_True(t, errors.Is(err, nats.ErrPermissionViolation))
	})

	t.Run("object store read write", func(t *testing.T) {
		obs, err := js.ObjectStore("orw")
		require_NoError(t, err)
		_, err = obs.PutBytes("f", []byte("hello"))
		require_NoError(t, err)
		b, err := obs.GetBytes("f")
		require_NoError(t, err)
		require_Equal(t, string(b), "hello")
		infos, err := obs.List()
		require_NoError(t, err)
		require_Len(t, len(infos), 1)
		require_NoError(t, obs.Delete("f"))

		obs2, err := njs.ObjectStore(ctx, "orw")
		require_NoError(t, err)
		_, err = obs2.PutBytes(ctx, "g", []byte("hello"))
		require_NoError(t, err)
		b, err = obs2.GetBytes(ctx, "g")
		require_NoError(t, err)
		require_Equal(t, string(b), "hello")
		infos2, err := obs2.List(ctx)
		require_NoError(t, err)
		require_Len(t, len(infos2), 1)
		require_NoError(t, obs2.Delete(ctx, "g"))
	})

	t.Run("object store read only", func(t *testing.T) {
		obs, err := js.ObjectStore("oro")
		require_NoError(t, err)
		b, err := obs.GetBytes("seed")
		require_NoError(t, err)
		require_Equal(t, string(b), "data")
		require_Error(t, obs.Delete("seed"))

		obs2, err := njs.ObjectStore(ctx, "oro")
		require_NoError(t, err)
		b, err = obs2.GetBytes(ctx, "seed")
		require_NoError(t, err)
		require_Equal(t, string(b), "data")
		wctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		_, err = obs2.PutBytes(wctx, "x", []byte("y"))
		require_Error(t, err)

		_, err = js.ObjectStore("onone")
		require_Error(t, err)
	})

	// Every negative case above must have produced a permission violation.
	// 2 KV put (x2 buckets, x2 APIs) + 2 bucket binds + 1 delete + 1 put + 1 bind.
	require_True(t, violations.Load() >= 8)
}

// A tag value that contains a template token must not be expanded a second
// time by the upstream template pass. Only the plain bucket name is granted.
func TestJWTTemplateMacroRejectsTemplateInjection(t *testing.T) {
	uc, acc := macroTestUserClaims(t,
		"kv:{{tag(y)}}", "y:*", "kv:{{name()}}", "kv:{{account-tag(kv)}}", "kv:a$b", "kv:good")
	uc.Name = "*"
	acc.tags = []string{"kv:*"}
	lim := jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("{{kvrw(tag(kv))}}")
	lim.Sub.Allow.Add("{{kvrw(tag(kv))}}")

	res, err := processUserPermissionsTemplate(lim, uc, acc)
	require_NoError(t, err)
	requireSameSubjects(t, res.Pub.Allow, macroWritePubSubjects("KV_good", "$KV.good"))
	requireSameSubjects(t, res.Sub.Allow, []string{"$KV.good.>"})
	for _, s := range append(res.Pub.Allow, res.Sub.Allow...) {
		if strings.ContainsAny(s, "{}$*") && !strings.HasPrefix(s, "$JS.") && !strings.HasPrefix(s, "$KV.good.") {
			t.Fatalf("unexpected subject %q", s)
		}
		if strings.Contains(s, "KV_*") || strings.Contains(s, "$KV.*") || strings.Contains(s, "{{") {
			t.Fatalf("template injection widened subject %q", s)
		}
	}

	// In a deny list such a value is an error.
	lim = jwt.UserPermissionLimits{}
	lim.Pub.Deny.Add("{{kvrw(tag(kv))}}")
	_, err = processUserPermissionsTemplate(lim, uc, acc)
	require_Error(t, err)
	require_Contains(t, err.Error(), "generated invalid subject")
}
