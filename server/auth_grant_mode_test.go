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
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func injectJWTAuthMode(t *testing.T, token string, signer nkeys.KeyPair, extension string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	payload, err := jwtPayload(token)
	require_NoError(t, err)
	var root map[string]json.RawMessage
	require_NoError(t, json.Unmarshal(payload, &root))
	var block map[string]json.RawMessage
	require_NoError(t, json.Unmarshal(root["nats"], &block))
	if extension == "" {
		delete(block, "authverify")
	} else {
		block["authverify"] = json.RawMessage(extension)
	}
	root["nats"] = mustMarshalJSON(t, block)
	input := parts[0] + "." + base64.RawURLEncoding.EncodeToString(mustMarshalJSON(t, root))
	sig, err := signer.Sign([]byte(input))
	require_NoError(t, err)
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestAuthGrantAccountModeJWT(t *testing.T) {
	f := newXPermissionsRawFixture(t, `{"kv":[{"op":"ro","bucket":"cfg"}]}`)
	for _, test := range []struct {
		name  string
		raw   string
		mode  authMode
		valid bool
	}{
		{"absent", "", authModeStatic, true},
		{"static", `{"mode":"static"}`, authModeStatic, true},
		{"grant", `{"mode":"grant"}`, authModeGrant, true},
		{"unknown mode", `{"mode":"dynamic"}`, authModeStatic, false},
		{"unknown field", `{"mode":"grant","future":true}`, authModeStatic, false},
		{"wrong block type", `"grant"`, authModeStatic, false},
		{"null", `null`, authModeStatic, false},
		{"array", `[]`, authModeStatic, false},
		{"empty object", `{}`, authModeStatic, false},
		{"number mode", `{"mode":1}`, authModeStatic, false},
		{"null mode", `{"mode":null}`, authModeStatic, false},
		{"case mode", `{"mode":"Grant"}`, authModeStatic, false},
		{"case field", `{"Mode":"grant"}`, authModeStatic, false},
		{"duplicate mode", `{"mode":"static","mode":"grant"}`, authModeStatic, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			token := injectJWTAuthMode(t, f.token, oKp, test.raw)
			_, extensions, verified, err := f.server.verifyAccountClaimsWithXPermissions(token)
			if !test.valid {
				require_Error(t, err)
				return
			}
			require_NoError(t, err)
			require_Equal(t, verified, token)
			require_Equal(t, extensions.authMode, test.mode)
			require_NotNil(t, extensions.xpermissions[f.signer])
		})
	}
}

func TestAuthGrantAccountModeRejectsExternalAuthorization(t *testing.T) {
	f := newXPermissionsRawFixture(t, "")
	user, err := nkeys.CreateUser()
	require_NoError(t, err)
	pub, err := user.PublicKey()
	require_NoError(t, err)
	f.claim.Authorization.AuthUsers.Add(pub)
	token, err := f.claim.Encode(oKp)
	require_NoError(t, err)
	_, _, _, err = f.server.verifyAccountClaimsWithXPermissions(injectJWTAuthMode(t, token, oKp, `{"mode":"grant"}`))
	require_Error(t, err)
	_, _, _, err = f.server.verifyAccountClaimsWithXPermissions(injectJWTAuthMode(t, token, oKp, `{"mode":"static"}`))
	require_NoError(t, err)
}

func TestAuthGrantUserModeJWT(t *testing.T) {
	account, err := nkeys.CreateAccount()
	require_NoError(t, err)
	user, err := nkeys.CreateUser()
	require_NoError(t, err)
	pub, err := user.PublicKey()
	require_NoError(t, err)
	claim := jwt.NewUserClaims(pub)
	token, err := claim.Encode(account)
	require_NoError(t, err)
	for _, test := range []struct {
		name  string
		raw   string
		valid bool
	}{
		{"absent", "", true},
		{"static", `{"mode":"static"}`, true},
		{"grant", `{"mode":"grant"}`, false},
		{"unknown mode", `{"mode":"dynamic"}`, false},
		{"unknown field", `{"mode":"static","extra":true}`, false},
		{"null", `null`, false},
		{"array", `[]`, false},
		{"wrong block type", `"static"`, false},
		{"missing mode", `{}`, false},
		{"wrong mode type", `{"mode":false}`, false},
		{"null mode", `{"mode":null}`, false},
		{"duplicate mode", `{"mode":"static","mode":"static"}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := injectJWTAuthMode(t, token, account, test.raw)
			_, err := jwt.DecodeUserClaims(raw)
			require_NoError(t, err)
			mode, present, err := decodeAuthModeJWT(raw, true)
			if !test.valid {
				require_Error(t, err)
				return
			}
			require_NoError(t, err)
			require_Equal(t, mode, authModeStatic)
			require_Equal(t, present, test.raw != "")
		})
	}
}

func TestAuthGrantModeChangeClosesAccountConnections(t *testing.T) {
	account, pub := createKey(t)
	claim := jwt.NewAccountClaims(pub)
	token, err := claim.Encode(oKp)
	require_NoError(t, err)
	conf := createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:-1
		operator: %s
		resolver: MEM
		resolver_preload: { %s: %s }
	`, ojwt, pub, token)))
	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()
	user, err := nkeys.CreateUser()
	require_NoError(t, err)
	userPub, err := user.PublicKey()
	require_NoError(t, err)
	userSeed, err := user.Seed()
	require_NoError(t, err)
	userClaim := jwt.NewUserClaims(userPub)
	userJWT, err := userClaim.Encode(account)
	require_NoError(t, err)
	creds := genCredsFile(t, userJWT, userSeed)
	closed := make(chan struct{}, 2)
	for range 2 {
		nc := natsConnect(t, s.ClientURL(), nats.UserCredentials(creds), nats.NoReconnect(), nats.ClosedHandler(func(*nats.Conn) {
			closed <- struct{}{}
		}))
		defer nc.Close()
	}
	acc, err := s.LookupAccount(pub)
	require_NoError(t, err)
	require_Len(t, len(acc.getClients()), 2)

	static := injectJWTAuthMode(t, token, oKp, `{"mode":"static"}`)
	require_NoError(t, s.updateAccountWithClaimJWT(acc, static))
	require_Len(t, len(acc.getClients()), 2)
	before := len(s.closed.closedClients())
	grant := injectJWTAuthMode(t, token, oKp, `{"mode":"grant"}`)
	require_NoError(t, s.updateAccountWithClaimJWT(acc, grant))
	for range 2 {
		select {
		case <-closed:
		case <-time.After(2 * time.Second):
			t.Fatal("mode change did not close every account connection")
		}
	}
	checkClosedConns(t, s, before+2, 2*time.Second)
	for _, info := range s.closed.closedClients()[before:] {
		checkReason(t, info.Reason, AuthModeChanged)
	}
	acc.mu.RLock()
	mode := acc.authMode
	acc.mu.RUnlock()
	require_Equal(t, mode, authModeGrant)
	invalid := injectJWTAuthMode(t, token, oKp, `{"mode":"invalid"}`)
	require_Error(t, s.updateAccountWithClaimJWT(acc, invalid))
	acc.mu.RLock()
	mode = acc.authMode
	acc.mu.RUnlock()
	require_Equal(t, mode, authModeGrant)
	require_NoError(t, s.updateAccountWithClaimJWT(acc, token))
	acc.mu.RLock()
	mode = acc.authMode
	acc.mu.RUnlock()
	require_Equal(t, mode, authModeStatic)
}

func TestAuthGrantClosedStateStrings(t *testing.T) {
	require_Equal(t, AuthorizationChanged, ProxyRequired+1)
	for reason, expected := range map[ClosedState]string{
		AuthorizationChanged: "Authorization Changed",
		GrantRejected:        "Grant Rejected",
		AuthModeChanged:      "Authorization Mode Changed",
		ResourceLimit:        "Resource Limit",
	} {
		require_Equal(t, reason.String(), expected)
	}
}
