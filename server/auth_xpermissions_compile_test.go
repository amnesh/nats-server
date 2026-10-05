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
	"reflect"
	"sync"
	"testing"

	"github.com/nats-io/jwt/v2"
)

func mustXPermissions(t *testing.T, raw string) *xPermissions {
	t.Helper()
	f := newXPermissionsRawFixture(t, raw)
	_, extensions, _, err := f.server.verifyAccountClaimsWithXPermissions(f.token)
	require_NoError(t, err)
	return extensions[f.signer]
}

func TestJWTXPermissionsCompileGroups(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "kv:cfg", "obj:blobs", "stream:orders", "consumer:worker")
	xp := mustXPermissions(t, `{
		"kv":[{"op":"rw","bucket":"{{tag(kv)}}"}],
		"obj":[{"op":"ro","bucket":"{{tag(obj)}}"}],
		"stream":[{"op":"admin","stream":"{{tag(stream)}}"}],
		"consumer":[{"op":"ro","stream":"orders","consumer":"{{tag(consumer)}}"}],
		"jsinfo":true
	}`)
	res, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_NoError(t, err)
	require_True(t, res.Pub.Allow.Contains("$JS.API.STREAM.PURGE.KV_cfg"))
	require_True(t, res.Pub.Allow.Contains("$KV.cfg.>"))
	require_True(t, res.Pub.Allow.Contains("$JS.API.STREAM.INFO.OBJ_blobs"))
	require_True(t, res.Pub.Allow.Contains("$JS.API.STREAM.DELETE.orders"))
	require_True(t, res.Pub.Allow.Contains("$JS.API.CONSUMER.MSG.NEXT.orders.worker"))
	require_True(t, res.Pub.Allow.Contains("$JS.API.STREAM.NAMES"))
	requireSameSubjects(t, res.Sub.Allow, []string{"$KV.cfg.>", "$O.blobs.>"})
}

func TestJWTXPermissionsCompileJSInfoFalseAndUntouchedDirection(t *testing.T) {
	uc, acc := macroTestUserClaims(t)
	for _, raw := range []string{
		`{"jsinfo":false}`,
		`{"stream":[{"op":"ro","stream":"orders"}],"jsinfo":false}`,
		`{"consumer":[{"op":"ro","stream":"orders","consumer":"worker"}]}`,
	} {
		xp := mustXPermissions(t, raw)
		res, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
		require_NoError(t, err)
		require_Len(t, len(res.Sub.Allow), 0)
		require_Len(t, len(res.Sub.Deny), 0)
	}

	lim := jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("$JS.API.INFO")
	res, err := processUserPermissionsTemplate(lim, mustXPermissions(t, `{"jsinfo":false}`), uc, acc)
	require_NoError(t, err)
	requireSameSubjects(t, res.Pub.Allow, []string{"$JS.API.INFO"})
}

func TestJWTXPermissionsCompilePreservesStandardPolicyAndLimits(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "kv:cfg")
	lim := jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("audit.{{tag(kv)}}")
	lim.Pub.Deny.Add("$JS.API.STREAM.PURGE.>")
	lim.Sub.Allow.Add("_INBOX.>")
	lim.Sub.Deny.Add("$KV.secret.>")
	lim.Resp = &jwt.ResponsePermission{MaxMsgs: 3, Expires: 42}
	lim.Limits.Payload = 1024
	lim.Limits.Subs = 7
	before := lim
	before.Permissions.Pub.Allow = append(jwt.StringList(nil), lim.Permissions.Pub.Allow...)
	before.Permissions.Pub.Deny = append(jwt.StringList(nil), lim.Permissions.Pub.Deny...)
	before.Permissions.Sub.Allow = append(jwt.StringList(nil), lim.Permissions.Sub.Allow...)
	before.Permissions.Sub.Deny = append(jwt.StringList(nil), lim.Permissions.Sub.Deny...)

	xp := mustXPermissions(t, `{"kv":[{"op":"rw","bucket":"{{tag(kv)}}"}]}`)
	res, err := processUserPermissionsTemplate(lim, xp, uc, acc)
	require_NoError(t, err)
	require_True(t, res.Pub.Allow.Contains("audit.cfg"))
	require_True(t, res.Pub.Allow.Contains("$KV.cfg.>"))
	require_True(t, res.Pub.Deny.Contains("$JS.API.STREAM.PURGE.>"))
	require_True(t, res.Sub.Allow.Contains("_INBOX.>"))
	require_True(t, res.Sub.Allow.Contains("$KV.cfg.>"))
	require_True(t, res.Sub.Deny.Contains("$KV.secret.>"))
	require_True(t, reflect.DeepEqual(res.Resp, lim.Resp))
	require_True(t, reflect.DeepEqual(res.Limits, lim.Limits))
	require_True(t, reflect.DeepEqual(lim, before))
}

func TestJWTXPermissionsCompileSelectorsOrderDedupAndFailure(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "team:red", "team:blue", "bucket:a", "bucket:a")
	xp := mustXPermissions(t, `{"kv":[
		{"op":"ro","bucket":"{{tag(team)}}_{{tag(bucket)}}"},
		{"op":"ro","bucket":"red_a"}
	]}`)
	res, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_NoError(t, err)
	require_True(t, reflect.DeepEqual(res.Sub.Allow, jwt.StringList{"$KV.red_a.>", "$KV.blue_a.>"}))

	xp = mustXPermissions(t, `{"stream":[{"op":"ro","stream":"{{tag(missing)}}"}]}`)
	_, err = processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_Error(t, err)
	require_Contains(t, err.Error(), "not defined")
	for _, context := range []string{"group stream", "entry 0", `op "ro"`, "field stream"} {
		require_Contains(t, err.Error(), context)
	}

	uc.Tags = jwt.TagList{"domain:"}
	xp = mustXPermissions(t, `{"stream":[{"op":"ro","stream":"orders","domain":"{{tag(domain)}}"}]}`)
	_, err = processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_Error(t, err)
	require_Contains(t, err.Error(), "field domain")
}

func TestJWTXPermissionsCompileCandidateBudgetBeforeDedup(t *testing.T) {
	uc, acc := macroTestUserClaims(t)
	xp := &xPermissions{KV: make([]xBucketPermission, maxPermTemplateSubjectExpansions+1)}
	for i := range xp.KV {
		xp.KV[i] = xBucketPermission{Op: "ro", Bucket: "same"}
	}
	_, err := processUserPermissionsTemplate(jwt.UserPermissionLimits{}, xp, uc, acc)
	require_Error(t, err)
	require_Contains(t, err.Error(), errPermTemplateExpansionLimit.Error())
}

func TestJWTXPermissionsCompileSharesBudgetWithStandardTemplates(t *testing.T) {
	uc, acc := macroTestUserClaims(t)
	uc.Tags = make(jwt.TagList, maxPermTemplateSubjectExpansions-1)
	for i := range uc.Tags {
		uc.Tags[i] = "v:same"
	}
	lim := jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("events.{{tag(v)}}")
	_, err := processUserPermissionsTemplate(lim, mustXPermissions(t, `{"jsinfo":true}`), uc, acc)
	require_Error(t, err)
	require_Contains(t, err.Error(), errPermTemplateExpansionLimit.Error())
	require_Contains(t, err.Error(), "field jsinfo")
}

func TestJWTXPermissionsCompileEmptyOrdinaryAllowGuard(t *testing.T) {
	uc, acc := macroTestUserClaims(t)
	for _, test := range []struct {
		name         string
		xp           *xPermissions
		explicitDeny bool
		wantGuard    bool
	}{
		{name: "empty ordinary allow", wantGuard: true},
		{name: "grouped grant prevents synthetic guard", xp: mustXPermissions(t, `{"kv":[{"op":"rw","bucket":"cfg"}]}`)},
		{name: "explicit deny survives grouped grant", xp: mustXPermissions(t, `{"kv":[{"op":"rw","bucket":"cfg"}]}`), explicitDeny: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			lim := jwt.UserPermissionLimits{}
			lim.Pub.Allow.Add("pub.{{tag(missing)}}")
			lim.Sub.Allow.Add("sub.{{tag(missing)}}")
			if test.explicitDeny {
				lim.Pub.Deny.Add(">")
				lim.Sub.Deny.Add(">")
			}

			res, err := processUserPermissionsTemplate(lim, test.xp, uc, acc)
			require_NoError(t, err)
			require_Equal(t, res.Pub.Deny.Contains(">"), test.wantGuard || test.explicitDeny)
			require_Equal(t, res.Sub.Deny.Contains(">"), test.wantGuard || test.explicitDeny)
			if test.xp != nil {
				require_True(t, res.Pub.Allow.Contains("$KV.cfg.>"))
				require_True(t, res.Sub.Allow.Contains("$KV.cfg.>"))
			}
		})
	}
}

func TestJWTXPermissionsCompileSharedTemplateInParallel(t *testing.T) {
	uc, acc := macroTestUserClaims(t, "kv:a", "kv:b")
	lim := jwt.UserPermissionLimits{}
	lim.Pub.Allow.Add("events.{{tag(kv)}}")
	lim.Sub.Allow.Add("inbox.{{tag(kv)}}")
	xp := mustXPermissions(t, `{"kv":[{"op":"rw","bucket":"{{tag(kv)}}"}]}`)
	want := lim
	want.Permissions.Pub.Allow = append(jwt.StringList(nil), lim.Permissions.Pub.Allow...)
	want.Permissions.Sub.Allow = append(jwt.StringList(nil), lim.Permissions.Sub.Allow...)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := processUserPermissionsTemplate(lim, xp, uc, acc)
			if err != nil || !res.Pub.Allow.Contains("$KV.a.>") || !res.Pub.Allow.Contains("$KV.b.>") {
				t.Errorf("unexpected compile result: %v %v", res.Pub.Allow, err)
			}
		}()
	}
	wg.Wait()
	require_True(t, reflect.DeepEqual(lim, want))
}
