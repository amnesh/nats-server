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
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server/authverify"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func TestClientInfoForRequestVerifiedJWTIdentity(t *testing.T) {
	for _, grant := range []bool{false, true} {
		mode := "static"
		if grant {
			mode = "grant"
		}
		t.Run(mode, func(t *testing.T) {
			account, accountKey, accountJWT := newRequestInfoJWTAccount(t)
			t.Cleanup(account.Wipe)
			signer := account
			if grant {
				var err error
				signer, err = nkeys.CreateAccount()
				require_NoError(t, err)
				t.Cleanup(signer.Wipe)
				signingKey, err := signer.PublicKey()
				require_NoError(t, err)
				claims := jwt.NewAccountClaims(accountKey)
				scope := jwt.NewUserScope()
				scope.Key, scope.Role = signingKey, "identity-probe"
				scope.Template.Pub.Deny.Add(">")
				scope.Template.Sub.Deny.Add(">")
				claims.SigningKeys.AddScopedSigner(scope)
				accountJWT, err = claims.Encode(oKp)
				require_NoError(t, err)
				accountJWT = authGrantJWTBlock(t, accountJWT, oKp, `{"mode":"grant"}`)
			}
			user, err := nkeys.CreateUser()
			require_NoError(t, err)
			t.Cleanup(user.Wipe)
			userKey, err := user.PublicKey()
			require_NoError(t, err)
			claims := jwt.NewUserClaims(userKey)
			if grant {
				claims.SetScoped(true)
				claims.IssuerAccount = accountKey
			}
			userJWT, err := claims.Encode(signer)
			require_NoError(t, err)
			credentials := nats.UserJWT(func() (string, error) { return userJWT, nil }, user.Sign)
			systemKeyPair, systemKey, systemJWT := newRequestInfoJWTAccount(t)
			t.Cleanup(systemKeyPair.Wipe)
			s, _ := runRequestInfoJWTServer(t, accountKey, accountJWT, func(opts *Options) {
				opts.LeafNode.Host, opts.LeafNode.Port = "127.0.0.1", -1
				opts.SystemAccount = systemKey
				require_NoError(t, opts.AccountResolver.Store(systemKey, systemJWT))
				if grant {
					opts.AuthGrant = &testGrantHook{verify: func(r *authverify.GrantRequest) *authverify.GrantVerdict {
						if r.UserNkey != userKey {
							t.Error("grant hook received a different authenticated user")
						}
						return &authverify.GrantVerdict{Generation: 1, Grant: grantAll(), Done: func(bool) {}}
					}}
				}
			})
			svc := natsConnect(t, s.ClientURL(), credentials)
			defer svc.Close()
			requests, err := svc.SubscribeSync("svc.identity")
			require_NoError(t, err)
			require_NoError(t, svc.Flush())
			sys := natsConnect(t, s.ClientURL(), requestInfoJWTUser(t, systemKeyPair))
			defer sys.Close()
			connects, err := sys.SubscribeSync(fmt.Sprintf(connectEventSubj, accountKey))
			require_NoError(t, err)
			disconnects, err := sys.SubscribeSync(fmt.Sprintf(disconnectEventSubj, accountKey))
			require_NoError(t, err)
			require_NoError(t, sys.Flush())
			otherUser, err := nkeys.CreateUser()
			require_NoError(t, err)
			t.Cleanup(otherUser.Wipe)
			otherKey, err := otherUser.PublicKey()
			require_NoError(t, err)
			for _, leaf := range []bool{false, true} {
				protocol := "client"
				if leaf {
					protocol = "leaf"
				}
				for _, fields := range []struct {
					name, nkey, username string
				}{
					{name: "honest"},
					{name: "nkey", nkey: otherKey},
					{name: "username", username: otherKey},
					{name: "both", nkey: otherKey, username: "other-user"},
				} {
					t.Run(protocol+"/"+fields.name, func(t *testing.T) {
						address := s.Addr().String()
						if leaf {
							address = fmt.Sprintf("127.0.0.1:%d", s.getOpts().LeafNode.Port)
						}
						conn, reader := requestInfoIdentityConnect(t, address, credentials, fields.nkey, fields.username)
						defer conn.Close()
						connected := requestInfoIdentityEvent(t, connects)
						requestInfoIdentityCheck(t, "connect event", connected.User, connected.Account, userKey, accountKey)
						command := "PUB"
						if leaf {
							command = "LMSG"
						}
						_, err := fmt.Fprintf(conn, "%s svc.identity _INBOX.identity 0\r\n\r\nPING\r\n", command)
						require_NoError(t, err)
						requestInfoIdentityPong(t, conn, reader)
						message, err := requests.NextMsg(time.Second)
						require_NoError(t, err)
						var stamped ClientInfo
						require_NoError(t, json.Unmarshal([]byte(message.Header.Get(ClientInfoHdr)), &stamped))
						requestInfoIdentityCheck(t, "request stamp", stamped.User, stamped.Account, userKey, accountKey)
						for _, cid := range []uint64{0, connected.ID} {
							for _, filter := range []string{"", userKey, otherKey, "other-user"} {
								inventory, err := s.Connz(&ConnzOptions{Username: true, Account: accountKey, CID: cid, User: filter})
								require_NoError(t, err)
								found := false
								for _, item := range inventory.Conns {
									if item.Cid == connected.ID {
										found = true
										requestInfoIdentityCheck(t, "CONNZ", item.AuthorizedUser, item.Account, userKey, accountKey)
									}
								}
								if want := filter == "" || filter == userKey; found != want {
									t.Errorf("CONNZ filter found connection = %v, want %v (CID selector %d)", found, want, cid)
								}
							}
						}
						require_NoError(t, conn.Close())
						disconnected := requestInfoIdentityEvent(t, disconnects)
						requestInfoIdentityCheck(t, "disconnect event", disconnected.User, disconnected.Account, userKey, accountKey)
					})
				}
			}
		})
	}
}

func requestInfoIdentityConnect(t *testing.T, address string, credentials nats.Option, nkey, username string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	require_NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require_NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	require_NoError(t, err)
	if !strings.HasPrefix(line, "INFO ") {
		t.Fatal("missing initial INFO")
	}
	var info Info
	require_NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(line, "INFO ")), &info))
	opts := nats.GetDefaultOptions()
	require_NoError(t, credentials(&opts))
	token, err := opts.UserJWT()
	require_NoError(t, err)
	signature, err := opts.SignatureCB([]byte(info.Nonce))
	require_NoError(t, err)
	fields := map[string]any{
		"jwt": token, "sig": base64.RawURLEncoding.EncodeToString(signature),
		"headers": true, "protocol": 1, "name": "identity-probe", "verbose": false,
		"nkey": nkey, "user": username,
	}
	data, err := json.Marshal(fields)
	require_NoError(t, err)
	_, err = fmt.Fprintf(conn, "CONNECT %s\r\nPING\r\n", data)
	require_NoError(t, err)
	requestInfoIdentityPong(t, conn, reader)
	return conn, reader
}

func requestInfoIdentityPong(t *testing.T, conn net.Conn, reader *bufio.Reader) {
	t.Helper()
	for {
		line, err := reader.ReadString('\n')
		require_NoError(t, err)
		switch strings.TrimSpace(line) {
		case "PONG":
			return
		case "PING":
			_, err := fmt.Fprint(conn, "PONG\r\n")
			require_NoError(t, err)
		default:
			if strings.HasPrefix(line, "-ERR") {
				t.Fatal("identity probe was rejected")
			}
		}
	}
}

type requestInfoIdentity struct {
	User    string `json:"user"`
	Account string `json:"acc"`
	Name    string `json:"name"`
	ID      uint64 `json:"id"`
}

func requestInfoIdentityEvent(t *testing.T, subscription *nats.Subscription) requestInfoIdentity {
	t.Helper()
	for {
		message, err := subscription.NextMsg(time.Second)
		require_NoError(t, err)
		var event struct {
			Client requestInfoIdentity
		}
		require_NoError(t, json.Unmarshal(message.Data, &event))
		if event.Client.Name == "identity-probe" {
			return event.Client
		}
	}
}

func requestInfoIdentityCheck(t *testing.T, surface, user, account, wantUser, wantAccount string) {
	t.Helper()
	if user != wantUser {
		t.Errorf("%s user is not the authenticated JWT subject", surface)
	}
	if account != wantAccount {
		t.Errorf("%s account is not the authenticated JWT account", surface)
	}
}

// The auth callout decides who a sentinel connection is. Before that decision
// completes, the callout request, both auth error events, and the
// authentication error log name the CONNECT user, as upstream does, not the
// sentinel's JWT subject.
func TestAuthCalloutSentinelKeepsConnectUser(t *testing.T) {
	systemKeyPair, systemKey := createKey(t)
	systemClaims := jwt.NewAccountClaims(systemKey)
	systemClaims.Name = "$SYS"
	systemJWT, err := systemClaims.Encode(oKp)
	require_NoError(t, err)
	targetKeyPair, targetKey := createKey(t)
	targetClaims := jwt.NewAccountClaims(targetKey)
	targetClaims.Name = "TEST"
	targetJWT, err := targetClaims.Encode(oKp)
	require_NoError(t, err)
	authKeyPair, err := nkeys.FromSeed([]byte(authCalloutIssuerSeed))
	require_NoError(t, err)
	authKey, err := authKeyPair.PublicKey()
	require_NoError(t, err)
	serviceKey, serviceCreds := createAuthServiceUser(t, authKeyPair)
	defer removeFile(t, serviceCreds)
	authClaims := jwt.NewAccountClaims(authKey)
	authClaims.Name = "AUTH"
	authClaims.EnableExternalAuthorization(serviceKey)
	authClaims.Authorization.AllowedAccounts.Add(targetKey)
	authJWT, err := authClaims.Encode(oKp)
	require_NoError(t, err)
	conf := fmt.Sprintf(`
		listen: 127.0.0.1:-1
		operator: %s
		system_account: %s
		resolver: MEM
		resolver_preload: {
			%s: %s
			%s: %s
			%s: %s
		}
	`, ojwt, systemKey, authKey, authJWT, targetKey, targetJWT, systemKey, systemJWT)

	requests := make(chan [2]string, 8)
	handler := func(m *nats.Msg) {
		user, server, info, opts, _ := decodeAuthRequest(t, m.Data)
		requests <- [2]string{opts.Username, info.User}
		if opts.Username == "alice" {
			userJWT := createAuthUser(t, user, "alice", targetKey, "", targetKeyPair, 0, nil)
			m.Respond(serviceResponse(t, user, server.ID, userJWT, "", 0))
			return
		}
		m.Respond(nil)
	}
	ac := NewAuthTest(t, conf, handler, nats.UserCredentials(serviceCreds))
	defer ac.Cleanup()
	logged := make(chan string, 64)
	ac.srv.SetLogger(&captureErrorLogger{errCh: logged}, false, false)
	accountErrors, err := ac.authClient.SubscribeSync(authErrorAccountEventSubj)
	require_NoError(t, err)
	require_NoError(t, ac.authClient.Flush())
	sys := natsConnect(t, ac.srv.ClientURL(), createUserCreds(t, nil, systemKeyPair))
	defer sys.Close()
	serverErrors, err := sys.SubscribeSync("$SYS.SERVER.*.CLIENT.AUTH.ERR")
	require_NoError(t, err)
	require_NoError(t, sys.Flush())
	sentinel := createBasicAccountUser(t, authKeyPair)
	defer removeFile(t, sentinel)

	request := func(want string) {
		t.Helper()
		select {
		case got := <-requests:
			if got[0] != want || got[1] != want {
				t.Errorf("callout request for CONNECT user %q has client_info.user %q, want %q", got[0], got[1], want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("no callout request for %q", want)
		}
	}
	event := func(name string, subscription *nats.Subscription) {
		t.Helper()
		message, err := subscription.NextMsg(2 * time.Second)
		require_NoError(t, err)
		var dm DisconnectEventMsg
		require_NoError(t, json.Unmarshal(message.Data, &dm))
		if dm.Client.User != "mallory" {
			t.Errorf("%s user = %q, want the CONNECT user %q", name, dm.Client.User, "mallory")
		}
	}

	nc := ac.Connect(nats.UserCredentials(sentinel), nats.UserInfo("alice", "pwd"))
	defer nc.Close()
	request("alice")

	ac.RequireConnectError(nats.UserCredentials(sentinel), nats.UserInfo("mallory", "pwd"))
	request("mallory")
	event("account auth error event", accountErrors)
	event("server auth error event", serverErrors)
	deadline := time.After(2 * time.Second)
	for {
		select {
		case line := <-logged:
			if !strings.Contains(line, ErrAuthentication.Error()) {
				continue
			}
			if !strings.Contains(line, `User "mallory"`) {
				t.Errorf("authentication error log does not name the CONNECT user: %q", line)
			}
			return
		case <-deadline:
			t.Fatal("no authentication error log")
		}
	}
}
