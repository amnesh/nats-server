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
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// A reload must accept a remote with a SignatureCB: a different func, the same
// func and no func (as after a reload from a config file). The leaf stays
// connected, and the callback from the start keeps signing reconnects, because
// the remote config of a running remote is not replaced by a reload.
func TestLeafNodeSignatureCBReload(t *testing.T) {
	hub, hopts := RunServerWithConfig(createConfFile(t, []byte(`
		port: -1
		server_name: HUB
		operator = "../test/configs/nkeys/op.jwt"
		resolver = MEMORY
		listen: "127.0.0.1:-1"
		leafnodes { listen: "127.0.0.1:-1" }
	`)))
	defer hub.Shutdown()

	_, akp := createAccount(hub)
	kp, _ := nkeys.CreateUser()
	pub, _ := kp.PublicKey()
	ujwt, err := jwt.NewUserClaims(pub).Encode(akp)
	require_NoError(t, err)

	signer := func(calls *atomic.Int32) SignatureHandler {
		return func(nonce []byte) (string, []byte, error) {
			calls.Add(1)
			sig, err := kp.Sign(nonce)
			return ujwt, sig, err
		}
	}
	var startCalls, newCalls atomic.Int32
	startCB := signer(&startCalls)

	u, err := url.Parse(fmt.Sprintf("nats://%s:%d", hopts.LeafNode.Host, hopts.LeafNode.Port))
	require_NoError(t, err)
	lopts := DefaultTestOptions
	lopts.Accounts = []*Account{NewAccount("B")}
	lopts.LeafNode.Remotes = []*RemoteLeafOpts{{URLs: []*url.URL{u}, SignatureCB: startCB}}
	lopts.LeafNode.ReconnectInterval = 50 * time.Millisecond
	leaf := RunServer(&lopts)
	defer leaf.Shutdown()
	checkLeafNodeConnected(t, leaf)

	leafCID := func() uint64 {
		leaf.mu.RLock()
		defer leaf.mu.RUnlock()
		for cid := range leaf.leafs {
			return cid
		}
		return 0
	}

	for _, test := range []struct {
		name string
		cb   SignatureHandler
	}{
		{"different func", signer(&newCalls)},
		{"same func", startCB},
		{"no func", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			cid := leafCID()
			// Options.Clone shares the remotes with the running options, so
			// build a new remote, as a caller or a config file reload does.
			newOpts := leaf.getOpts().Clone()
			remote := *newOpts.LeafNode.Remotes[0]
			remote.SignatureCB = test.cb
			newOpts.LeafNode.Remotes = []*RemoteLeafOpts{&remote}
			require_NoError(t, leaf.ReloadOptions(newOpts))

			// The reload does not reconnect the leaf.
			checkLeafNodeConnected(t, leaf)
			require_Equal(t, leafCID(), cid)

			// Make the leaf reconnect, and check which callback signs.
			before := startCalls.Load()
			var leafs []*client
			hub.mu.RLock()
			for _, c := range hub.leafs {
				leafs = append(leafs, c)
			}
			hub.mu.RUnlock()
			for _, c := range leafs {
				c.closeConnection(ClientClosed)
			}
			checkFor(t, 5*time.Second, 15*time.Millisecond, func() error {
				if id := leafCID(); id == 0 || id == cid {
					return fmt.Errorf("leaf did not reconnect")
				}
				return nil
			})
			checkLeafNodeConnected(t, leaf)
			if startCalls.Load() <= before {
				t.Fatalf("Reconnect was not signed by the callback from the start")
			}
			require_Equal(t, newCalls.Load(), 0)
		})
	}

	// A caller that keeps the running remote and adds another one in the same
	// reload: the kept remote stays connected and the new one connects.
	t.Run("kept remote and added remote", func(t *testing.T) {
		cid := leafCID()
		var addedCalls atomic.Int32
		newOpts := leaf.getOpts().Clone()
		kept := newOpts.LeafNode.Remotes[0]
		added := &RemoteLeafOpts{URLs: []*url.URL{u}, LocalAccount: "B", SignatureCB: signer(&addedCalls)}
		newOpts.LeafNode.Remotes = []*RemoteLeafOpts{kept, added}
		require_NoError(t, leaf.ReloadOptions(newOpts))

		checkLeafNodeConnectedCount(t, leaf, 2)
		leaf.mu.RLock()
		_, ok := leaf.leafs[cid]
		leaf.mu.RUnlock()
		require_True(t, ok)
		require_True(t, addedCalls.Load() > 0)
	})
}
