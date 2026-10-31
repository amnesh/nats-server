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
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server/authverify"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func TestAuthGrantModeChangeKeepsJetStreamClients(t *testing.T) {
	account, pub := createKey(t)
	claim := jwt.NewAccountClaims(pub)
	claim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: jwt.NoLimit, DiskStorage: jwt.NoLimit}
	token, err := claim.Encode(oKp)
	require_NoError(t, err)
	_, sysPub, sysClaim := NewJwtAccountClaim("SYS")
	sysJWT, err := sysClaim.Encode(oKp)
	require_NoError(t, err)
	conf := createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:-1
		jetstream: { store_dir: '%s' }
		operator: %s
		system_account: %s
		resolver: MEM
		resolver_preload: { %s: %s, %s: %s }
	`, t.TempDir(), ojwt, sysPub, pub, token, sysPub, sysJWT)))
	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()
	user, err := nkeys.CreateUser()
	require_NoError(t, err)
	userPub, err := user.PublicKey()
	require_NoError(t, err)
	userClaim := jwt.NewUserClaims(userPub)
	userJWT, err := userClaim.Encode(account)
	require_NoError(t, err)
	userJWT = injectJWTAuthMode(t, userJWT, account, `{"mode":"static"}`)
	connect := func() *nats.Conn {
		return natsConnect(t, s.ClientURL(), nats.UserJWT(func() (string, error) { return userJWT, nil }, user.Sign), nats.NoReconnect())
	}
	nc := connect()
	defer nc.Close()
	js, err := nc.JetStream(nats.MaxWait(time.Second))
	require_NoError(t, err)
	_, err = js.AddStream(&nats.StreamConfig{Name: "EVENTS", Subjects: []string{"events"}, Storage: nats.MemoryStorage})
	require_NoError(t, err)
	_, err = js.Publish("events", []byte("before"))
	require_NoError(t, err)
	acc, err := s.LookupAccount(pub)
	require_NoError(t, err)
	grant := injectJWTAuthMode(t, token, oKp, `{"mode":"grant"}`)
	require_NoError(t, s.updateAccountWithClaimJWT(acc, grant))
	nc = connect()
	defer nc.Close()
	js, err = nc.JetStream(nats.MaxWait(time.Second))
	require_NoError(t, err)
	_, err = js.Publish("events", []byte("after"))
	if err != nil {
		t.Fatalf("stream stopped storing messages after account mode change: %v", err)
	}
	info, err := js.StreamInfo("EVENTS")
	require_NoError(t, err)
	require_Equal(t, info.State.Msgs, uint64(2))
}

func TestAuthGrantUpdateAccountClaimsKeepsExtensions(t *testing.T) {
	f := newGrantFixture(t, &testGrantHook{verify: func(*authverify.GrantRequest) *authverify.GrantVerdict {
		return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
	}})
	raw := encodeAccountClaimWithXPermissions(t, f.claims, map[string]string{f.scope.Key: `{"kv":[{"op":"ro","bucket":"cfg"}]}`})
	raw = injectJWTAuthMode(t, raw, oKp, `{"mode":"grant"}`)
	require_NoError(t, f.s.updateAccountWithClaimJWT(f.acc, raw))
	nc := natsConnect(t, f.s.ClientURL(), f.creds(t, f.signer, true, "", 0), nats.NoReconnect())
	defer nc.Close()
	f.acc.mu.RLock()
	xpermissions := f.acc.xpermissions
	f.acc.mu.RUnlock()
	f.s.UpdateAccountClaims(f.acc, f.claims)
	f.acc.mu.RLock()
	mode := f.acc.authMode
	keptXPermissions := reflect.DeepEqual(f.acc.xpermissions, xpermissions)
	f.acc.mu.RUnlock()
	if mode != authModeGrant {
		t.Errorf("typed account update changed grant mode to %v", mode)
	}
	if !keptXPermissions {
		t.Error("typed account update dropped xpermissions")
	}
	if err := nc.Flush(); err != nil {
		t.Errorf("typed account update closed grant connection: %v", err)
	}
}
