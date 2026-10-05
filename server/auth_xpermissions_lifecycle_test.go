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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func injectJWTXPermissions(t *testing.T, token string, signer nkeys.KeyPair, raw string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	require_Len(t, len(parts), 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require_NoError(t, err)
	var root map[string]json.RawMessage
	require_NoError(t, json.Unmarshal(payload, &root))
	var nats map[string]json.RawMessage
	require_NoError(t, json.Unmarshal(root["nats"], &nats))
	nats["xpermissions"] = json.RawMessage(raw)
	root["nats"] = mustMarshalJSON(t, nats)
	encoded := base64.RawURLEncoding.EncodeToString(mustMarshalJSON(t, root))
	input := parts[0] + "." + encoded
	sig, err := signer.Sign([]byte(input))
	require_NoError(t, err)
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func xPermissionsScopedCredentials(t *testing.T, account string, signer nkeys.KeyPair, injected string) string {
	t.Helper()
	ukp, err := nkeys.CreateUser()
	require_NoError(t, err)
	seed, err := ukp.Seed()
	require_NoError(t, err)
	upub, err := ukp.PublicKey()
	require_NoError(t, err)
	claim := newJWTTestUserClaims()
	claim.Subject = upub
	claim.SetScoped(true)
	claim.IssuerAccount = account
	token, err := claim.Encode(signer)
	require_NoError(t, err)
	if injected != _EMPTY_ {
		token = injectJWTXPermissions(t, token, signer, injected)
	}
	return genCredsFile(t, token, seed)
}

func xPermissionsUserInfo(t *testing.T, nc *nats.Conn) *UserInfo {
	t.Helper()
	msg, err := nc.Request(userDirectInfoSubj, nil, time.Second)
	require_NoError(t, err)
	response := ServerAPIResponse{Data: &UserInfo{}}
	require_NoError(t, json.Unmarshal(msg.Data, &response))
	return response.Data.(*UserInfo)
}

func xPermissionsRoundTrip(t *testing.T, nc *nats.Conn, subject string) {
	t.Helper()
	sub, err := nc.SubscribeSync(subject)
	require_NoError(t, err)
	require_NoError(t, nc.Flush())
	require_NoError(t, nc.Publish(subject, []byte("ok")))
	msg, err := sub.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, string(msg.Data), "ok")
}

func TestJWTXPermissionsAccountLifecycleRealClient(t *testing.T) {
	_, sysPub := createKey(t)
	sysClaim := jwt.NewAccountClaims(sysPub)
	sysSigner, sysSignerPub := createKey(t)
	sysScope := jwt.NewUserScope()
	sysScope.Key = sysSignerPub
	sysScope.Template.Pub.Allow.Add(userDirectInfoSubj)
	sysScope.Template.Sub.Allow.Add("_INBOX.>")
	sysClaim.SigningKeys.AddScopedSigner(sysScope)
	sysJWT := encodeAccountClaimWithXPermissions(t, sysClaim, map[string]string{
		sysSignerPub: `{"stream":[{"op":"ro","stream":"system_events"}]}`,
	})

	_, accountPub := createKey(t)
	accountClaim := jwt.NewAccountClaims(accountPub)
	accountClaim.Name = "APP"
	signer, signerPub := createKey(t)
	scope := jwt.NewUserScope()
	scope.Key = signerPub
	scope.Role = "worker"
	scope.Template.Pub.Allow.Add(userDirectInfoSubj)
	scope.Template.Sub.Allow.Add("_INBOX.>")
	accountClaim.SigningKeys.AddScopedSigner(scope)
	initialJWT := encodeAccountClaimWithXPermissions(t, accountClaim, map[string]string{
		signerPub: `{"kv":[{"op":"rw","bucket":"before"}]}`,
	})

	conf := createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:-1
		operator: %s
		system_account: %s
		resolver: MEM
		resolver_preload: {
			%s: %s
			%s: %s
		}
	`, ojwt, sysPub, sysPub, sysJWT, accountPub, initialJWT)))
	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	// SetSystemAccount must preserve the signed extension generation too.
	sysCreds := xPermissionsScopedCredentials(t, sysPub, sysSigner, _EMPTY_)
	sysNC := natsConnect(t, s.ClientURL(), nats.UserCredentials(sysCreds))
	sysInfo := xPermissionsUserInfo(t, sysNC)
	require_True(t, slices.Contains(sysInfo.Permissions.Publish.Allow, "$JS.API.STREAM.INFO.system_events"))
	sysNC.Close()

	// A user JWT cannot inject or replace account-authorized xpermissions.
	creds := xPermissionsScopedCredentials(t, accountPub, signer, `{"stream":[{"op":"ro","stream":"injected"}]}`)
	closed := make(chan error, 1)
	nc := natsConnect(t, s.ClientURL(), nats.UserCredentials(creds), nats.NoReconnect(), nats.ClosedHandler(func(conn *nats.Conn) {
		closed <- conn.LastError()
	}))
	info := xPermissionsUserInfo(t, nc)
	require_True(t, slices.Contains(info.Permissions.Publish.Allow, "$KV.before.>"))
	require_False(t, slices.Contains(info.Permissions.Publish.Allow, "$JS.API.STREAM.INFO.injected"))
	xPermissionsRoundTrip(t, nc, "$KV.before.key")
	acc, err := s.LookupAccount(accountPub)
	require_NoError(t, err)
	clients := acc.getClients()
	require_Len(t, len(clients), 1)
	clients[0].mu.Lock()
	require_NotNil(t, clients[0].user)
	require_Equal(t, clients[0].user.SigningKey, signerPub)
	clients[0].mu.Unlock()

	updatedJWT := encodeAccountClaimWithXPermissions(t, accountClaim, map[string]string{
		signerPub: `{"kv":[{"op":"rw","bucket":"after"}]}`,
	})
	closedBefore := len(s.closed.closedClients())
	require_NoError(t, s.updateAccountWithClaimJWT(acc, updatedJWT))
	select {
	case <-closed:
		checkClosedConns(t, s, closedBefore+1, 2*time.Second)
		closedClients := s.closed.closedClients()
		checkReason(t, closedClients[len(closedClients)-1].Reason, AuthenticationViolation)
	case <-time.After(2 * time.Second):
		t.Fatal("scoped client was not evicted after extension-only update")
	}

	closed = make(chan error, 1)
	nc = natsConnect(t, s.ClientURL(), nats.UserCredentials(creds), nats.NoReconnect(), nats.ClosedHandler(func(conn *nats.Conn) {
		closed <- conn.LastError()
	}))
	defer nc.Close()
	info = xPermissionsUserInfo(t, nc)
	require_True(t, slices.Contains(info.Permissions.Publish.Allow, "$KV.after.>"))
	require_False(t, slices.Contains(info.Permissions.Publish.Allow, "$KV.before.>"))
	xPermissionsRoundTrip(t, nc, "$KV.after.key")

	invalidJWT := encodeAccountClaimWithXPermissions(t, accountClaim, map[string]string{
		signerPub: `{"stream":[{"op":"ro","stream":"bad","domain":null}]}`,
	})
	require_Error(t, s.updateAccountWithClaimJWT(acc, invalidJWT))
	info = xPermissionsUserInfo(t, nc)
	require_True(t, slices.Contains(info.Permissions.Publish.Allow, "$KV.after.>"))
	xPermissionsRoundTrip(t, nc, "$KV.after.key")

	legacyClaim := jwt.NewAccountClaims(accountPub)
	legacyScope := jwt.NewUserScope()
	legacyScope.Key = signerPub
	legacyScope.Role = "worker"
	legacyScope.Template.Pub.Allow.Add(userDirectInfoSubj, "{{jsread(legacy)}}")
	legacyScope.Template.Sub.Allow.Add("_INBOX.>")
	legacyClaim.SigningKeys.AddScopedSigner(legacyScope)
	legacyJWT, err := legacyClaim.Encode(oKp)
	require_NoError(t, err)
	require_NoError(t, s.AccountResolver().Store(accountPub, legacyJWT))
	acc.mu.Lock()
	acc.updated = time.Time{}
	acc.mu.Unlock()
	require_Error(t, s.updateAccount(acc))
	info = xPermissionsUserInfo(t, nc)
	require_True(t, slices.Contains(info.Permissions.Publish.Allow, "$KV.after.>"))
	xPermissionsRoundTrip(t, nc, "$KV.after.key")
	select {
	case err := <-closed:
		t.Fatalf("rejected update disconnected active client: %v", err)
	default:
	}

	// Signed removal clears stale extension authority and evicts the signer.
	withoutExtension, err := accountClaim.Encode(oKp)
	require_NoError(t, err)
	closedBefore = len(s.closed.closedClients())
	require_NoError(t, s.updateAccountWithClaimJWT(acc, withoutExtension))
	select {
	case <-closed:
		checkClosedConns(t, s, closedBefore+1, 2*time.Second)
		closedClients := s.closed.closedClients()
		checkReason(t, closedClients[len(closedClients)-1].Reason, AuthenticationViolation)
	case <-time.After(2 * time.Second):
		t.Fatal("scoped client was not evicted after extension removal")
	}
	plainNC := natsConnect(t, s.ClientURL(), nats.UserCredentials(creds))
	defer plainNC.Close()
	info = xPermissionsUserInfo(t, plainNC)
	require_False(t, slices.Contains(info.Permissions.Publish.Allow, "$KV.after.>"))
}

func TestJWTXPermissionsConcurrentAccountGeneration(t *testing.T) {
	f := newXPermissionsRawFixture(t, `{"stream":[{"op":"ro","stream":"one"}]}`)
	s := opTrustBasicSetup()
	defer s.Shutdown()
	claimOne, xpOne, _, err := s.verifyAccountClaimsWithXPermissions(f.token)
	require_NoError(t, err)
	claimOne.SigningKeys[f.signer].(*jwt.UserScope).Role = "one"
	acc := s.buildInternalAccount(claimOne, xpOne)

	claimTwo := jwt.NewAccountClaims(claimOne.Subject)
	claimTwo.Name = claimOne.Name
	scopeTwo := jwt.NewUserScope()
	scopeTwo.Key = f.signer
	scopeTwo.Role = "two"
	claimTwo.SigningKeys.AddScopedSigner(scopeTwo)
	xpTwo := accountXPermissions{f.signer: {Stream: []xStreamPermission{{Op: "ro", Stream: "two"}}}}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 500 {
			s.updateAccountClaimsWithRefresh(acc, claimOne, xpOne, false)
			s.updateAccountClaimsWithRefresh(acc, claimTwo, xpTwo, false)
		}
	}()
	go func() {
		defer wg.Done()
		for range 2000 {
			scope, xp, ok := acc.issuerScopeAndXPermissions(f.signer)
			if !ok || xp == nil {
				t.Errorf("missing atomic signer generation")
				return
			}
			role := scope.(*jwt.UserScope).Role
			if len(xp.Stream) != 1 || xp.Stream[0].Stream != role {
				t.Errorf("mixed signer generation: role=%q extension=%v", role, xp.Stream)
				return
			}
		}
	}()
	wg.Wait()
}

func TestJWTXPermissionsIncompleteAccountRefresh(t *testing.T) {
	_, sysPub := createKey(t)
	sysClaim := jwt.NewAccountClaims(sysPub)
	sysJWT, err := sysClaim.Encode(oKp)
	require_NoError(t, err)

	_, exporterPub := createKey(t)
	exporterClaim := jwt.NewAccountClaims(exporterPub)
	exporterClaim.Exports.Add(&jwt.Export{Subject: jwt.Subject("events"), Type: jwt.Stream})
	exporterJWT, err := exporterClaim.Encode(oKp)
	require_NoError(t, err)

	_, importerPub := createKey(t)
	importerClaim := jwt.NewAccountClaims(importerPub)
	importerClaim.Imports.Add(&jwt.Import{Account: exporterPub, Subject: jwt.Subject("events"), Type: jwt.Stream})
	importerSigner, importerSignerPub := createKey(t)
	importerScope := jwt.NewUserScope()
	importerScope.Key = importerSignerPub
	importerScope.Template.Pub.Allow.Add(userDirectInfoSubj)
	importerScope.Template.Sub.Allow.Add("_INBOX.>")
	importerClaim.SigningKeys.AddScopedSigner(importerScope)
	importerJWT := encodeAccountClaimWithXPermissions(t, importerClaim, map[string]string{
		importerSignerPub: `{"stream":[{"op":"ro","stream":"restored"}]}`,
	})

	conf := createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:-1
		operator: %s
		system_account: %s
		resolver: MEM
		resolver_preload: {
			%s: %s
			%s: %s
		}
	`, ojwt, sysPub, sysPub, sysJWT, importerPub, importerJWT)))
	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	importer, err := s.LookupAccount(importerPub)
	require_NoError(t, err)
	importer.mu.RLock()
	require_True(t, importer.incomplete)
	require_Equal(t, importer.claimJWT, importerJWT)
	importer.mu.RUnlock()

	// A typed update has no signed extension payload, but must retain the stored
	// JWT so resolving the missing exporter can rebuild the complete generation.
	s.UpdateAccountClaims(importer, importerClaim)
	_, xp, ok := importer.issuerScopeAndXPermissions(importerSignerPub)
	require_True(t, ok)
	require_True(t, xp == nil)

	require_NoError(t, s.AccountResolver().Store(exporterPub, exporterJWT))
	_, err = s.LookupAccount(exporterPub)
	require_NoError(t, err)

	creds := xPermissionsScopedCredentials(t, importerPub, importerSigner, _EMPTY_)
	nc := natsConnect(t, s.ClientURL(), nats.UserCredentials(creds))
	defer nc.Close()
	info := xPermissionsUserInfo(t, nc)
	require_True(t, slices.Contains(info.Permissions.Publish.Allow, "$JS.API.STREAM.INFO.restored"))
	importer.mu.RLock()
	require_False(t, importer.incomplete)
	importer.mu.RUnlock()
}
