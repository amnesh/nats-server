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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

type xPermissionsRawFixture struct {
	server   *Server
	claim    *jwt.AccountClaims
	token    string
	signer   string
	scopeRaw json.RawMessage
}

func resignXPermissionsJWT(t *testing.T, header string, payload []byte) string {
	t.Helper()
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	input := header + "." + encoded
	sig, err := oKp.Sign([]byte(input))
	require_NoError(t, err)
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func newXPermissionsRawFixture(t *testing.T, extension string) xPermissionsRawFixture {
	t.Helper()
	akp, err := nkeys.CreateAccount()
	require_NoError(t, err)
	apub, err := akp.PublicKey()
	require_NoError(t, err)
	skp, err := nkeys.CreateAccount()
	require_NoError(t, err)
	spub, err := skp.PublicKey()
	require_NoError(t, err)

	claim := jwt.NewAccountClaims(apub)
	scope := jwt.NewUserScope()
	scope.Key = spub
	scope.Role = "worker"
	scope.Template.Pub.Allow.Add("events.{{tag(team)}}.>")
	claim.SigningKeys.AddScopedSigner(scope)
	token := encodeAccountClaimWithXPermissions(t, claim, map[string]string{spub: extension})
	parts := strings.Split(token, ".")
	require_Len(t, len(parts), 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require_NoError(t, err)
	var root map[string]json.RawMessage
	require_NoError(t, json.Unmarshal(payload, &root))
	var nats map[string]json.RawMessage
	require_NoError(t, json.Unmarshal(root["nats"], &nats))
	var signing []json.RawMessage
	require_NoError(t, json.Unmarshal(nats["signing_keys"], &signing))
	require_Len(t, len(signing), 1)
	var scopeObject map[string]json.RawMessage
	require_NoError(t, json.Unmarshal(signing[0], &scopeObject))
	opub, err := oKp.PublicKey()
	require_NoError(t, err)
	return xPermissionsRawFixture{
		server:   &Server{trustedKeys: []string{opub}},
		claim:    claim,
		token:    token,
		signer:   spub,
		scopeRaw: signing[0],
	}
}

func encodeAccountClaimWithXPermissions(t *testing.T, claim *jwt.AccountClaims, extensions map[string]string) string {
	t.Helper()
	token, err := claim.Encode(oKp)
	require_NoError(t, err)
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require_NoError(t, err)
	var root map[string]json.RawMessage
	require_NoError(t, json.Unmarshal(payload, &root))
	var nats map[string]json.RawMessage
	require_NoError(t, json.Unmarshal(root["nats"], &nats))
	var signing []json.RawMessage
	require_NoError(t, json.Unmarshal(nats["signing_keys"], &signing))
	for i, rawSigner := range signing {
		var scopeObject map[string]json.RawMessage
		if err := json.Unmarshal(rawSigner, &scopeObject); err != nil {
			continue
		}
		var signer string
		if err := json.Unmarshal(scopeObject["key"], &signer); err != nil {
			continue
		}
		extension, ok := extensions[signer]
		if !ok || extension == "" {
			continue
		}
		var template map[string]json.RawMessage
		require_NoError(t, json.Unmarshal(scopeObject["template"], &template))
		template["xpermissions"] = json.RawMessage(extension)
		scopeObject["template"] = mustMarshalJSON(t, template)
		signing[i] = mustMarshalJSON(t, scopeObject)
	}
	nats["signing_keys"] = mustMarshalJSON(t, signing)
	root["nats"] = mustMarshalJSON(t, nats)
	return resignXPermissionsJWT(t, parts[0], mustMarshalJSON(t, root))
}

func mustMarshalJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(value)
	require_NoError(t, err)
	return b
}

func replaceXPermissionsSigningKeys(t *testing.T, f xPermissionsRawFixture, signingKeys json.RawMessage) string {
	t.Helper()
	parts := strings.Split(f.token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require_NoError(t, err)
	var root map[string]json.RawMessage
	require_NoError(t, json.Unmarshal(payload, &root))
	var nats map[string]json.RawMessage
	require_NoError(t, json.Unmarshal(root["nats"], &nats))
	nats["signing_keys"] = signingKeys
	root["nats"] = mustMarshalJSON(t, nats)
	return resignXPermissionsJWT(t, parts[0], mustMarshalJSON(t, root))
}

func TestJWTXPermissionsRawSchema(t *testing.T) {
	valid := []struct {
		name string
		raw  string
	}{
		{"kv ro", `{"kv":[{"op":"ro","bucket":"cfg"}]}`},
		{"kv rw", `{"kv":[{"op":"rw","bucket":"{{tag(kv)}}","domain":"hub"}]}`},
		{"kv admin", `{"kv":[{"op":"admin","bucket":"cfg"}]}`},
		{"obj ro", `{"obj":[{"op":"ro","bucket":"blobs"}]}`},
		{"obj rw", `{"obj":[{"op":"rw","bucket":"blobs"}]}`},
		{"obj admin", `{"obj":[{"op":"admin","bucket":"blobs"}]}`},
		{"stream ro", `{"stream":[{"op":"ro","stream":"orders"}]}`},
		{"stream admin", `{"stream":[{"op":"admin","stream":"orders","domain":"hub"}]}`},
		{"consumer ro", `{"consumer":[{"op":"ro","stream":"orders","consumer":"worker"}]}`},
		{"consumer admin", `{"consumer":[{"op":"admin","stream":"orders","consumer":"{{name()}}"}]}`},
		{"all groups", `{"kv":[{"op":"ro","bucket":"cfg"}],"obj":[{"op":"rw","bucket":"blobs"}],"stream":[{"op":"admin","stream":"orders"}],"consumer":[{"op":"ro","stream":"orders","consumer":"worker"}],"jsinfo":true}`},
		{"jsinfo true", `{"jsinfo":true}`},
		{"jsinfo false", `{"jsinfo":false}`},
		{"jsinfo false with group", `{"stream":[{"op":"ro","stream":"orders"}],"jsinfo":false}`},
	}
	for _, test := range valid {
		t.Run("valid "+test.name, func(t *testing.T) {
			f := newXPermissionsRawFixture(t, test.raw)
			ac, xp, _, err := f.server.verifyAccountClaimsWithXPermissions(f.token)
			require_NoError(t, err)
			require_True(t, ac != nil)
			require_True(t, xp[f.signer] != nil)
		})
	}
	t.Run("valid absent", func(t *testing.T) {
		f := newXPermissionsRawFixture(t, "")
		_, xp, _, err := f.server.verifyAccountClaimsWithXPermissions(f.token)
		require_NoError(t, err)
		require_Len(t, len(xp), 0)
	})

	invalid := []struct {
		name string
		raw  string
	}{
		{"null", `null`},
		{"empty object", `{}`},
		{"grants alias", `{"grants":[]}`},
		{"unknown top level", `{"future":true}`},
		{"empty kv", `{"kv":[]}`},
		{"non array", `{"kv":{}}`},
		{"case variant op", `{"kv":[{"op":"RW","bucket":"cfg"}]}`},
		{"unknown op", `{"stream":[{"op":"rw","stream":"orders"}]}`},
		{"missing field", `{"consumer":[{"op":"ro","stream":"orders"}]}`},
		{"extra field", `{"kv":[{"op":"ro","bucket":"cfg","stream":"orders"}]}`},
		{"non string selector", `{"stream":[{"op":"ro","stream":7}]}`},
		{"non string domain", `{"stream":[{"op":"ro","stream":"orders","domain":7}]}`},
		{"null kv domain", `{"kv":[{"op":"ro","bucket":"cfg","domain":null}]}`},
		{"empty kv domain", `{"kv":[{"op":"ro","bucket":"cfg","domain":""}]}`},
		{"null obj domain", `{"obj":[{"op":"ro","bucket":"blobs","domain":null}]}`},
		{"empty obj domain", `{"obj":[{"op":"ro","bucket":"blobs","domain":""}]}`},
		{"null stream domain", `{"stream":[{"op":"ro","stream":"orders","domain":null}]}`},
		{"empty stream domain", `{"stream":[{"op":"ro","stream":"orders","domain":""}]}`},
		{"null consumer domain", `{"consumer":[{"op":"ro","stream":"orders","consumer":"worker","domain":null}]}`},
		{"empty consumer domain", `{"consumer":[{"op":"ro","stream":"orders","consumer":"worker","domain":""}]}`},
		{"non bool jsinfo", `{"jsinfo":"true"}`},
		{"null jsinfo with valid group", `{"kv":[{"op":"ro","bucket":"cfg"}],"jsinfo":null}`},
		{"null group with jsinfo", `{"kv":null,"jsinfo":true}`},
		{"empty group with jsinfo", `{"kv":[],"jsinfo":true}`},
		{"wrong group type with jsinfo", `{"kv":"cfg","jsinfo":true}`},
		{"unknown entry field with valid fields", `{"kv":[{"op":"ro","bucket":"cfg","future":true}],"jsinfo":true}`},
		{"wrong entry field type with valid fields", `{"kv":[{"op":"ro","bucket":7}],"jsinfo":true}`},
		{"wildcard domain", `{"stream":[{"op":"ro","stream":"orders","domain":"*"}]}`},
		{"prefix wildcard", `{"stream":[{"op":"ro","stream":"orders-*"}]}`},
		{"unknown selector operation", `{"stream":[{"op":"ro","stream":"{{future()}}"}]}`},
		{"resource operation selector", `{"stream":[{"op":"ro","stream":"{{jsread(orders)}}"}]}`},
		{"duplicate extension field", `{"jsinfo":true,"jsinfo":false}`},
		{"duplicate entry field", `{"kv":[{"op":"ro","op":"rw","bucket":"cfg"}]}`},
	}
	for _, test := range invalid {
		t.Run("invalid "+test.name, func(t *testing.T) {
			f := newXPermissionsRawFixture(t, test.raw)
			_, _, _, err := f.server.verifyAccountClaimsWithXPermissions(f.token)
			require_Error(t, err)
		})
	}

	t.Run("invalid duplicate signing key entry", func(t *testing.T) {
		f := newXPermissionsRawFixture(t, `{"jsinfo":true}`)
		raw := json.RawMessage(fmt.Sprintf(`[%s,%s]`, f.scopeRaw, f.scopeRaw))
		_, _, _, err := f.server.verifyAccountClaimsWithXPermissions(replaceXPermissionsSigningKeys(t, f, raw))
		require_Error(t, err)
	})
	t.Run("invalid duplicate raw signing key member", func(t *testing.T) {
		f := newXPermissionsRawFixture(t, `{"jsinfo":true}`)
		raw := json.RawMessage("[" + strings.TrimSuffix(string(f.scopeRaw), "}") + `,"key":"` + f.signer + `"}]`)
		_, _, _, err := f.server.verifyAccountClaimsWithXPermissions(replaceXPermissionsSigningKeys(t, f, raw))
		require_Error(t, err)
	})
	t.Run("invalid raw typed key mismatch", func(t *testing.T) {
		f := newXPermissionsRawFixture(t, `{"jsinfo":true}`)
		other, err := nkeys.CreateAccount()
		require_NoError(t, err)
		otherPub, err := other.PublicKey()
		require_NoError(t, err)
		raw := json.RawMessage("[" + strings.Replace(string(f.scopeRaw), f.signer, otherPub, 1) + "]")
		token := replaceXPermissionsSigningKeys(t, f, raw)
		_, err = decodeAccountXPermissions(token, f.claim)
		require_Error(t, err)
	})
	t.Run("diagnostic context", func(t *testing.T) {
		f := newXPermissionsRawFixture(t, `{"consumer":[{"op":"ro","stream":"orders","consumer":"bad.name"}]}`)
		_, _, _, err := f.server.verifyAccountClaimsWithXPermissions(f.token)
		require_Error(t, err)
		for _, context := range []string{f.signer, "consumer", "entry 0", `op "ro"`, "field consumer"} {
			require_Contains(t, err.Error(), context)
		}
	})
	t.Run("diagnostic context for malformed optional field", func(t *testing.T) {
		f := newXPermissionsRawFixture(t, `{"stream":[{"op":"ro","stream":"orders","domain":null}]}`)
		_, _, _, err := f.server.verifyAccountClaimsWithXPermissions(f.token)
		require_Error(t, err)
		for _, context := range []string{f.signer, "stream", "entry 0", `op "ro"`, "field domain"} {
			require_Contains(t, err.Error(), context)
		}
	})
}

func TestJWTXPermissionsRejectLegacyMacros(t *testing.T) {
	for _, direction := range []string{"pub allow", "pub deny", "sub allow", "sub deny"} {
		t.Run(direction, func(t *testing.T) {
			f := newXPermissionsRawFixture(t, "")
			scope := f.claim.SigningKeys[f.signer].(*jwt.UserScope)
			switch direction {
			case "pub allow":
				scope.Template.Pub.Allow = jwt.StringList{"{{kvrw(tag(kv))}}"}
			case "pub deny":
				scope.Template.Pub.Deny = jwt.StringList{"{{jsadmin(orders)}}"}
			case "sub allow":
				scope.Template.Sub.Allow = jwt.StringList{"{{objro(blobs)}}"}
			case "sub deny":
				scope.Template.Sub.Deny = jwt.StringList{"{{jsinfo()}}"}
			}
			token, err := f.claim.Encode(oKp)
			require_NoError(t, err)
			_, _, _, err = f.server.verifyAccountClaimsWithXPermissions(token)
			require_Error(t, err)
		})
	}
	t.Run("ordinary value operation", func(t *testing.T) {
		f := newXPermissionsRawFixture(t, "")
		_, _, _, err := f.server.verifyAccountClaimsWithXPermissions(f.token)
		require_NoError(t, err)
	})
}
