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

//go:build !skip_js_tests && !skip_js_cluster_tests

package server

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestJetStreamClusterInboxCaptureAdmission(t *testing.T) {
	inboxCaptureAdmission(t, true)
}

func TestJetStreamClusterInboxCaptureDeliveryLeaderChange(t *testing.T) {
	previousWait := srcConsumerWaitTime
	srcConsumerWaitTime = 2 * time.Second
	defer func() { srcConsumerWaitTime = previousWait }()

	c := createJetStreamClusterWithTemplate(t, jsClusterTempl+"\nfeature_flags { js_reject_inbox_capture: true }\n", "ICD", 3)
	defer c.shutdown()
	clientServer := c.randomServer()
	nc, js := jsClientConnect(t, clientServer)
	defer func() { nc.Close() }()
	_, err := js.AddStream(&nats.StreamConfig{Name: "ORIGIN", Subjects: []string{"orders"}, Replicas: 3})
	require_NoError(t, err)
	_, err = js.AddStream(&nats.StreamConfig{Name: "MIRROR", Mirror: &nats.StreamSource{Name: "ORIGIN"}, Replicas: 3})
	require_NoError(t, err)
	_, err = js.AddStream(&nats.StreamConfig{Name: "SOURCE", Sources: []*nats.StreamSource{{Name: "ORIGIN"}}, Replicas: 3})
	require_NoError(t, err)
	for pass := 0; pass < 3; pass++ {
		for _, name := range []string{"ORIGIN", "MIRROR", "SOURCE"} {
			c.waitOnStreamLeader(globalAccountName, name)
		}
		// Create replies precede data-plane leadership and route propagation.
		checkFor(t, 10*time.Second, 25*time.Millisecond, func() error {
			if !clientServer.globalAccount().sl.HasInterest("orders") {
				return fmt.Errorf("origin publish interest has not reached the client server")
			}
			return nil
		})
		if pass == 2 {
			for _, name := range []string{"MIRROR", "SOURCE"} {
				inboxCaptureClusterDeliveryEqual(t, c, "after-restart-before-publish", name, 40*time.Second)
			}
		}
		ack, err := js.Publish("orders", []byte(fmt.Sprintf("cluster-%d", pass)))
		require_NoError(t, err)
		require_Equal(t, ack.Sequence, uint64(pass+1))
		for _, name := range []string{"MIRROR", "SOURCE"} {
			c.waitOnStreamLeader(globalAccountName, name)
			checkFor(t, 10*time.Second, 25*time.Millisecond, func() error {
				info, err := js.StreamInfo(name)
				if err != nil {
					return err
				}
				if info.State.Msgs != uint64(pass+1) {
					phase := []string{"initial", "after-leader-change", "after-restart"}[pass]
					return inboxCaptureClusterDeliveryDiagnostic(c, phase, name, uint64(pass+1), info)
				}
				return nil
			})
			phase := []string{"initial", "after-leader-change", "after-restart"}[pass]
			inboxCaptureClusterDeliveryEqual(t, c, phase, name, 10*time.Second)
			msg, err := js.GetMsg(name, uint64(pass+1))
			require_NoError(t, err)
			require_Equal(t, string(msg.Data), fmt.Sprintf("cluster-%d", pass))
		}
		if pass == 0 {
			for _, name := range []string{"MIRROR", "SOURCE"} {
				old := c.streamLeader(globalAccountName, name)
				response, err := nc.Request(fmt.Sprintf(JSApiStreamLeaderStepDownT, name), nil, 5*time.Second)
				require_NoError(t, err)
				var stepped JSApiStreamLeaderStepDownResponse
				require_NoError(t, json.Unmarshal(response.Data, &stepped))
				require_True(t, stepped.Error == nil)
				checkFor(t, 10*time.Second, 25*time.Millisecond, func() error {
					next := c.streamLeader(globalAccountName, name)
					if next == nil || next == old {
						return fmt.Errorf("leader has not changed")
					}
					return nil
				})
			}
		} else if pass == 1 {
			nc.Close()
			c.stopAll()
			c.restartAll()
			clientServer = c.randomServer()
			nc, js = jsClientConnect(t, clientServer)
		}
	}
}

func TestJetStreamClusterInboxCaptureOriginAPI(t *testing.T) {
	tmpl := `
        listen: 127.0.0.1:-1
        server_name: %s
        jetstream {store_dir: '%s'}
        cluster {name: %s, listen: 127.0.0.1:%d, routes: [%s]}
    ` + inboxCaptureOriginAccounts
	c := createJetStreamClusterWithTemplate(t, tmpl, "ORIGIN_API", 3)
	defer c.shutdown()
	inboxCaptureOriginAPIControls(t, c.randomNonLeader(), 3)
}

func TestJetStreamClusterInboxCaptureOriginTransit(t *testing.T) {
	a, _, _ := inboxCaptureOriginServer(t, func(o *Options) {
		o.ServerName = "A"
		o.Cluster.Name, o.Cluster.Host, o.Cluster.Port = "ORIGIN", "127.0.0.1", -1
	})
	b, _, _ := inboxCaptureOriginServer(t, func(o *Options) {
		o.ServerName = "B"
		o.Cluster.Name, o.Cluster.Host, o.Cluster.Port = "ORIGIN", "127.0.0.1", -1
		u, err := url.Parse("nats-route://" + a.ClusterAddr().String())
		require_NoError(t, err)
		o.Routes = []*url.URL{u}
	})
	checkClusterFormed(t, a, b)
	svc := inboxCaptureOriginConnect(t, b, "sys", false)
	_, err := svc.QueueSubscribe("$JS.ORIGIN", "origin", func(m *nats.Msg) { _ = m.Respond([]byte(m.Header.Get(ClientInfoHdr))) })
	require_NoError(t, err)
	require_NoError(t, svc.Flush())
	for _, tc := range []struct {
		user        string
		iproc, want bool
	}{{"host", true, true}, {"bounded", true, false}, {"host", false, false}} {
		nc := inboxCaptureOriginConnect(t, a, tc.user, tc.iproc)
		checkFor(t, 5*time.Second, 20*time.Millisecond, func() error {
			request := nats.NewMsg("$JS.ORIGIN")
			request.Header.Set(ClientInfoHdr, `{"acc":"APP","iproc_unrestricted":true}`)
			response, err := nc.RequestMsg(request, 250*time.Millisecond)
			if err != nil {
				return err
			}
			var ci ClientInfo
			if err := json.Unmarshal(response.Data, &ci); err != nil {
				return err
			}
			if ci.InProcessUnrestricted != tc.want {
				return fmt.Errorf("proof = %v, want %v", ci.InProcessUnrestricted, tc.want)
			}
			return nil
		})
	}
}

func TestJetStreamClusterInboxCaptureRestoreAdmission(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			tmpl := jsClusterTempl + fmt.Sprintf("\nfeature_flags: {js_reject_inbox_capture: %t}\n", enabled)
			c := createJetStreamClusterWithTemplate(t, tmpl, "CAPTURE_RESTORE", 3)
			defer c.shutdown()
			inboxCaptureRestoreAdmission(t, c.leader(), enabled, 3)
		})
	}
}

func TestJetStreamClusterInboxCaptureRestoreFinalGate(t *testing.T) {
	c := createJetStreamClusterWithTemplate(t, jsClusterTempl+"\nfeature_flags {js_reject_inbox_capture: true}\n", "FINAL_RESTORE", 3)
	defer c.shutdown()
	receiver := c.randomNonLeader()
	require_True(t, receiver != nil && receiver != c.leader())
	inboxCaptureFinalTransfer(t, receiver, true)
}

func TestJetStreamClusterInboxCaptureLeaderChange(t *testing.T) {
	c := createJetStreamClusterWithTemplate(t, jsClusterTempl+"\nfeature_flags {js_reject_inbox_capture: true}\n", "CAPTURE_LEADER", 3)
	defer c.shutdown()
	leader := c.leader()
	inboxCaptureRestoreAdmission(t, leader, true, 3)
	require_NoError(t, leader.getJetStream().getMetaGroup().StepDown())
	c.waitOnLeader()
	checkFor(t, 5*time.Second, 10*time.Millisecond, func() error {
		if c.leader() == leader {
			return fmt.Errorf("old meta leader was re-elected")
		}
		return nil
	})
	inboxCaptureRestoreAdmission(t, c.leader(), true, 3)
}

func TestJetStreamClusterInboxCaptureRestoreLiveHandoff(t *testing.T) {
	c := createJetStreamClusterWithTemplateAndModHook(t, inboxCaptureRestoreClusterTemplate, "LIVE_RESTORE", 3, func(serverName, clusterName, storeDir, conf string) string {
		return conf + fmt.Sprintf("\nserver_tags: [%q]\n", "restore-"+serverName)
	})
	defer c.shutdown()
	receiver := c.randomNonLeader()
	require_True(t, receiver != nil && receiver != c.leader())
	// The origin is a follower, so the authentic marker must cross its route to
	// the meta leader before placement selects the distinct restore receiver.
	inboxCaptureLiveRestore(t, receiver, receiver, true)
}
