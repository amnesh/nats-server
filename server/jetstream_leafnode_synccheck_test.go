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

//go:build !skip_js_tests

package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// A leaf connect kicks a hub source that waits in a long backoff, with the
// check on every connect (upstream) and with the coalesced check.
func TestJetStreamLeafNodeSyncCheckKicksSourceBackoff(t *testing.T) {
	for _, tc := range []struct {
		name     string
		interval string
	}{
		{"PerConnect", _EMPTY_},
		{"Coalesced", `, sync_consumers_check_interval: "250ms"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hubConf := createConfFile(t, []byte(fmt.Sprintf(`
				listen: -1
				server_name: hub
				jetstream { store_dir: '%s', domain: HUB }
				leaf { port: -1 %s }
			`, t.TempDir(), tc.interval)))
			sHub, oHub := RunServerWithConfig(hubConf)
			defer sHub.Shutdown()

			// The hub sources from a leaf domain that is not connected yet.
			ncHub, jsHub := jsClientConnect(t, sHub, nats.UserInfo("u", "p"))
			defer ncHub.Close()
			_, err := jsHub.AddStream(&nats.StreamConfig{
				Name: "AGG",
				Sources: []*nats.StreamSource{{
					Name:     "S1",
					External: &nats.ExternalStream{APIPrefix: "$JS.L1.API"},
				}},
			})
			require_NoError(t, err)
			mset, err := sHub.globalAccount().lookupStream("AGG")
			require_NoError(t, err)

			var iname string
			checkFor(t, 5*time.Second, 50*time.Millisecond, func() error {
				mset.mu.RLock()
				defer mset.mu.RUnlock()
				for in := range mset.sources {
					iname = in
					return nil
				}
				return fmt.Errorf("no source yet")
			})

			// Put the source into a long backoff: only a leaf connect can
			// make it retry soon.
			blocked := make(chan struct{})
			mset.mu.Lock()
			if t := mset.sourceSetupSchedules[iname]; t != nil {
				t.Stop()
			}
			if mset.sourceSetupSchedules == nil {
				mset.sourceSetupSchedules = map[string]*time.Timer{}
			}
			mset.sourceSetupSchedules[iname] = time.AfterFunc(time.Hour, func() { close(blocked) })
			si := mset.sources[iname]
			si.fails = 20
			si.sip = false
			before := si.lreq
			mset.mu.Unlock()

			leafConf := createConfFile(t, []byte(fmt.Sprintf(`
				listen: -1
				server_name: leaf1
				jetstream { store_dir: '%s', domain: L1 }
				leaf { remotes [ { url: "nats://127.0.0.1:%d" } ] }
			`, t.TempDir(), oHub.LeafNode.Port)))
			sLeaf, _ := RunServerWithConfig(leafConf)
			defer sLeaf.Shutdown()
			checkLeafNodeConnectedCount(t, sHub, 1)

			// The retry runs after the 2s request throttle plus jitter.
			checkFor(t, 6*time.Second, 50*time.Millisecond, func() error {
				mset.mu.RLock()
				defer mset.mu.RUnlock()
				si := mset.sources[iname]
				if si == nil || !si.lreq.After(before) {
					return fmt.Errorf("source not retried after leaf connect")
				}
				return nil
			})
			select {
			case <-blocked:
				t.Fatalf("long backoff timer fired")
			default:
			}
		})
	}
}
