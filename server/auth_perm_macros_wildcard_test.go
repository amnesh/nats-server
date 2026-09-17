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

func TestJWTTemplateMacroWildcardStream(t *testing.T) {
	uc, acc := macroTestUserClaims(t)
	lim := jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("{{jsread(*)}}")

	res, err := processUserPermissionsTemplate(lim, uc, acc)
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

	lim = jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("{{jsadmin(*)}}")
	res, err = processUserPermissionsTemplate(lim, uc, acc)
	require_NoError(t, err)
	requireSameSubjects(t, res.Pub.Allow, macroAdminPubSubjects("*", ""))
}

func TestJWTTemplateMacroWildcardBucket(t *testing.T) {
	uc, acc := macroTestUserClaims(t)
	lim := jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("{{kvrw(*)}}")
	lim.Sub.Allow.Add("{{kvrw(*)}}", "{{objro(*)}}")

	res, err := processUserPermissionsTemplate(lim, uc, acc)
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

func TestJWTTemplateMacroWildcardConsumer(t *testing.T) {
	uc, acc := macroTestUserClaims(t)
	lim := jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("{{jsconsumer(orders, *)}}")

	res, err := processUserPermissionsTemplate(lim, uc, acc)
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

	lim = jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("{{jsconsumeradmin(*, *)}}")
	res, err = processUserPermissionsTemplate(lim, uc, acc)
	require_NoError(t, err)
	require_Len(t, len(res.Pub.Allow), 14)
	require_True(t, res.Pub.Allow.Contains("$JS.API.CONSUMER.DELETE.*.*"))
}

func TestJWTTemplateMacroWildcardWithDomain(t *testing.T) {
	uc, acc := macroTestUserClaims(t)
	lim := jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("{{kvrw(*, domain=hub)}}")

	res, err := processUserPermissionsTemplate(lim, uc, acc)
	require_NoError(t, err)
	require_Len(t, len(res.Pub.Allow), 18)
	require_True(t, res.Pub.Allow.Contains("$JS.hub.API.STREAM.INFO.*"))
	require_True(t, res.Pub.Allow.Contains("$JS.hub.API.$KV.*.>"))
	require_True(t, res.Pub.Allow.Contains("$JS.ACK.hub.*.*.*.*.*.*.*.>"))
}

func TestJWTTemplateMacroWildcardOnlyAsLiteral(t *testing.T) {
	// A wildcard that comes from a tag, or a wildcard domain, is an invalid
	// value: skipped in allow lists (fail closed), an error in deny lists.
	uc, acc := macroTestUserClaims(t, "kv:*", "dom:*")
	for _, entry := range []string{
		"{{kvrw(tag(kv))}}",
		"{{kvrw(cfg, domain=*)}}",
		"{{kvrw(cfg, domain=tag(dom))}}",
		"{{jsread(team-*)}}",
		"{{jsread(>)}}",
	} {
		t.Run(entry, func(t *testing.T) {
			lim := jwt.UserPermissionLimits{}
			lim.Pub.Allow.Add(entry)
			res, err := processUserPermissionsTemplate(lim, uc, acc)
			require_NoError(t, err)
			require_Len(t, len(res.Pub.Allow), 0)
			require_True(t, res.Pub.Deny.Contains(">"))

			lim = jwt.UserPermissionLimits{}
			lim.Pub.Deny.Add(entry)
			_, err = processUserPermissionsTemplate(lim, uc, acc)
			require_Error(t, err)
			require_Contains(t, err.Error(), "generated invalid subject")
		})
	}
}
