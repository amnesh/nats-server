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
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"
)

// The literal * names every resource of a kind. NATS wildcards match whole
// tokens, so the stream token becomes * (never KV_*), and the data subject
// becomes $KV.*.> or $O.*.>. Expected lists are written literally.

func TestJWTXPermissionsWildcardStream(t *testing.T) {
	uc, acc := macroTestUserClaims(t)
	xp := mustXPermissions(t, `{"stream":[{"op":"ro","stream":"*"}]}`)
	res, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_NoError(t, err)
	requireSameSubjects(t, res.Pub.Allow, []string{
		"$JS.API.STREAM.INFO.*",
		"$JS.API.STREAM.MSG.GET.*",
		"$JS.API.DIRECT.GET.*",
		"$JS.API.DIRECT.GET.*.>",
		"$JS.API.CONSUMER.CREATE.*",
		"$JS.API.CONSUMER.CREATE.*.>",
		"$JS.API.CONSUMER.DURABLE.CREATE.*.>",
		"$JS.API.CONSUMER.INFO.*.>",
		"$JS.API.CONSUMER.NAMES.*",
		"$JS.API.CONSUMER.LIST.*",
		"$JS.API.CONSUMER.DELETE.*.>",
		"$JS.API.CONSUMER.MSG.NEXT.*.>",
		"$JS.ACK.*.*.*.*.*.*.*",
		"$JS.ACK.*.*.*.*.*.*.*.*.>",
		"$JS.FC.*.*.*",
		"$JS.FC.*.*.*.*.*",
	})

	xp = mustXPermissions(t, `{"stream":[{"op":"admin","stream":"*"}]}`)
	res, err = processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_NoError(t, err)
	requireSameSubjects(t, res.Pub.Allow, macroAdminPubSubjects("*", ""))
}

func TestJWTXPermissionsWildcardBucket(t *testing.T) {
	uc, acc := macroTestUserClaims(t)
	xp := mustXPermissions(t, `{"kv":[{"op":"rw","bucket":"*"}],"obj":[{"op":"ro","bucket":"*"}]}`)
	res, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_NoError(t, err)
	// The stream token is *, not KV_*: KV_* would be a literal token and
	// would match nothing.
	requireSameSubjects(t, res.Pub.Allow, macroWritePubSubjects("*", "$KV.*"))
	for _, subj := range res.Pub.Allow {
		require_False(t, strings.Contains(subj, "KV_"))
	}
	// The documented widening: a bucket wildcard reaches the API of every
	// stream in the account, including purge.
	require_True(t, res.Pub.Allow.Contains("$JS.API.STREAM.INFO.*"))
	require_True(t, res.Pub.Allow.Contains("$JS.API.STREAM.PURGE.*"))
	requireSameSubjects(t, res.Sub.Allow, []string{"$KV.*.>", "$O.*.>"})
}

func TestJWTXPermissionsWildcardConsumer(t *testing.T) {
	uc, acc := macroTestUserClaims(t)
	xp := mustXPermissions(t, `{"consumer":[{"op":"ro","stream":"orders","consumer":"*"}]}`)
	res, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_NoError(t, err)
	requireSameSubjects(t, res.Pub.Allow, []string{
		"$JS.API.STREAM.INFO.orders",
		"$JS.API.CONSUMER.INFO.orders.*",
		"$JS.API.CONSUMER.MSG.NEXT.orders.*",
		"$JS.ACK.orders.*.*.*.*.*.*",
		"$JS.ACK.*.*.orders.*.*.*.*.*.>",
		"$JS.FC.orders.*.*",
		"$JS.FC.*.*.orders.*.*",
	})

	xp = mustXPermissions(t, `{"consumer":[{"op":"admin","stream":"*","consumer":"*"}]}`)
	res, err = processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_NoError(t, err)
	require_Len(t, len(res.Pub.Allow), 14)
	require_True(t, res.Pub.Allow.Contains("$JS.API.CONSUMER.DELETE.*.*"))
}

func TestJWTXPermissionsWildcardWithDomain(t *testing.T) {
	uc, acc := macroTestUserClaims(t)
	xp := mustXPermissions(t, `{"kv":[{"op":"rw","bucket":"*","domain":"hub"}]}`)
	res, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_NoError(t, err)
	require_Len(t, len(res.Pub.Allow), 18)
	require_True(t, res.Pub.Allow.Contains("$JS.hub.API.STREAM.INFO.*"))
	require_True(t, res.Pub.Allow.Contains("$JS.hub.API.$KV.*.>"))
	require_True(t, res.Pub.Allow.Contains("$JS.ACK.hub.*.*.*.*.*.*.*.>"))
}

func TestJWTXPermissionsWildcardOnlyAsLiteral(t *testing.T) {
	// A wildcard that comes from a tag, or a wildcard domain, is an invalid
	// value: skipped in allow lists (fail closed), an error in deny lists.
	uc, acc := macroTestUserClaims(t, "kv:*", "dom:*")
	for _, raw := range []string{
		`{"kv":[{"op":"rw","bucket":"{{tag(kv)}}"}]}`,
		`{"kv":[{"op":"rw","bucket":"cfg","domain":"*"}]}`,
		`{"kv":[{"op":"rw","bucket":"cfg","domain":"{{tag(dom)}}"}]}`,
		`{"stream":[{"op":"ro","stream":"team-*"}]}`,
		`{"stream":[{"op":"ro","stream":">"}]}`,
	} {
		t.Run(raw, func(t *testing.T) {
			f := newXPermissionsRawFixture(t, raw)
			_, extensions, _, err := f.server.verifyAccountClaimsWithXPermissions(f.token)
			if err == nil {
				_, err = processUserPermissionsTemplate(jwt.UserPermissionLimits{}, extensions[f.signer], uc, acc)
			}
			require_Error(t, err)
		})
	}
}
