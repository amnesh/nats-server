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
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// lateLink is a hub (domain HUB) and a leaf (domain L1) that solicits the hub.
// A config reload or a restart of the leaf turns the link on or off.
type lateLink struct {
	t        *testing.T
	hub      *Server
	leaf     *Server
	leafConf string
	leafDir  string
	hubPort  int
}

func newLateLink(t *testing.T, up bool) *lateLink {
	t.Helper()
	hubConf := createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:-1
		server_name: hub
		jetstream { store_dir: '%s', domain: HUB }
		leaf { listen: 127.0.0.1:-1 }
	`, t.TempDir())))
	hub, oHub := RunServerWithConfig(hubConf)
	t.Cleanup(hub.Shutdown)
	l := &lateLink{t: t, hub: hub, leafDir: t.TempDir(), hubPort: oHub.LeafNode.Port}
	l.leafConf = createConfFile(t, l.leafConfig(up))
	l.leaf, _ = RunServerWithConfig(l.leafConf)
	t.Cleanup(func() { l.leaf.Shutdown() })
	if up {
		checkLeafNodeConnectedCount(t, hub, 1)
	}
	return l
}

func (l *lateLink) leafConfig(up bool) []byte {
	return []byte(fmt.Sprintf(`
		listen: 127.0.0.1:-1
		server_name: leaf1
		jetstream { store_dir: '%s', domain: L1 }
		leaf { remotes [ { url: "nats://127.0.0.1:%d", disabled: %t } ] }
	`, l.leafDir, l.hubPort, !up))
}

// setLink turns the link on or off with a config reload of the leaf. It
// returns when the hub sees the change.
func (l *lateLink) setLink(up bool) time.Time {
	l.t.Helper()
	reloadUpdateConfig(l.t, l.leaf, l.leafConf, string(l.leafConfig(up)))
	want := 0
	if up {
		want = 1
	}
	checkLeafNodeConnectedCount(l.t, l.hub, want)
	return time.Now()
}

// restartLeaf starts the leaf again on its store, with the link on or off.
func (l *lateLink) restartLeaf(up bool) {
	l.t.Helper()
	l.leaf.Shutdown()
	l.leaf.WaitForShutdown()
	checkLeafNodeConnectedCount(l.t, l.hub, 0)
	if err := os.WriteFile(l.leafConf, l.leafConfig(up), 0666); err != nil {
		l.t.Fatalf("write leaf config: %v", err)
	}
	l.leaf, _ = RunServerWithConfig(l.leafConf)
}

func addLateLinkOrigin(t *testing.T, s *Server, n int) {
	t.Helper()
	nc, js := jsClientConnect(t, s)
	defer nc.Close()
	_, err := js.AddStream(&nats.StreamConfig{Name: "ORIGIN", Subjects: []string{"origin"}})
	require_NoError(t, err)
	publishLateLinkOrigin(t, s, n)
}

func publishLateLinkOrigin(t *testing.T, s *Server, n int) {
	t.Helper()
	nc, js := jsClientConnect(t, s)
	defer nc.Close()
	for range n {
		_, err := js.Publish("origin", nil)
		require_NoError(t, err)
	}
}

// lateLinkDest is stream DEST with a mirror or a source of ORIGIN in the
// domain of apiPrefix.
func lateLinkDest(kind, apiPrefix string) *nats.StreamConfig {
	ext := &nats.ExternalStream{APIPrefix: apiPrefix}
	if kind == "Mirror" {
		return &nats.StreamConfig{Name: "DEST", Mirror: &nats.StreamSource{Name: "ORIGIN", External: ext}}
	}
	return &nats.StreamConfig{Name: "DEST", Sources: []*nats.StreamSource{{Name: "ORIGIN", External: ext}}}
}

func waitLateLinkDest(t *testing.T, s *Server, want uint64, within time.Duration) {
	t.Helper()
	mset, err := s.globalAccount().lookupStream("DEST")
	require_NoError(t, err)
	checkFor(t, within, 25*time.Millisecond, func() error {
		if got := mset.state().Msgs; got != want {
			return fmt.Errorf("DEST has %d of %d messages", got, want)
		}
		return nil
	})
}

// lateLinkRequestInFlight reports whether the mirror or a source of DEST waits
// for the reply to its consumer request.
func lateLinkRequestInFlight(s *Server) error {
	mset, err := s.globalAccount().lookupStream("DEST")
	if err != nil {
		return err
	}
	mset.mu.RLock()
	defer mset.mu.RUnlock()
	if mset.mirror != nil && mset.mirror.sip {
		return nil
	}
	for _, si := range mset.sources {
		if si.sip {
			return nil
		}
	}
	return fmt.Errorf("no consumer request in flight")
}

// A mirror or a source sends its first consumer request while no leaf link to
// the origin exists, so the request gets no reply. When the link comes up, the
// stream gets the origin data within a few seconds, and not after the 30s wait
// for the reply.
func TestJetStreamLeafNodeLateLinkEndsRequestWait(t *testing.T) {
	for _, kind := range []string{"Source", "Mirror"} {
		for _, tc := range []struct {
			name  string
			delay time.Duration
		}{
			{"LinkUpAtOnce", 0},
			{"LinkUpAfterThrottle", sourceConsumerRetryThreshold + 500*time.Millisecond},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				l := newLateLink(t, false)
				addLateLinkOrigin(t, l.leaf, 10)

				nc, js := jsClientConnect(t, l.hub)
				defer nc.Close()
				reqs := natsSubSync(t, nc, "$JS.L1.API.CONSUMER.>")
				natsFlush(t, nc)
				_, err := js.AddStream(lateLinkDest(kind, "$JS.L1.API"))
				require_NoError(t, err)
				_, err = reqs.NextMsg(5 * time.Second)
				require_NoError(t, err)

				time.Sleep(tc.delay)
				up := l.setLink(true)
				waitLateLinkDest(t, l.hub, 10, 5*time.Second)
				t.Logf("%s has the data %v after the link came up", kind, time.Since(up).Round(time.Millisecond))
			})
		}
	}
}

// The link drops for longer than the first retry backoff. A request waits for
// its reply when the link comes back. The stream gets the new data within a
// few seconds.
func TestJetStreamLeafNodeLateLinkAfterOutage(t *testing.T) {
	owt := srcConsumerWaitTime
	srcConsumerWaitTime = 3 * time.Second
	defer func() { srcConsumerWaitTime = owt }()

	for _, kind := range []string{"Source", "Mirror"} {
		t.Run(kind, func(t *testing.T) {
			l := newLateLink(t, true)
			addLateLinkOrigin(t, l.leaf, 10)
			nc, js := jsClientConnect(t, l.hub)
			defer nc.Close()
			_, err := js.AddStream(lateLinkDest(kind, "$JS.L1.API"))
			require_NoError(t, err)
			waitLateLinkDest(t, l.hub, 10, 5*time.Second)

			reqs := natsSubSync(t, nc, "$JS.L1.API.CONSUMER.>")
			natsFlush(t, nc)
			drop := l.setLink(false)
			publishLateLinkOrigin(t, l.leaf, 5)

			// The stall check runs every 10s. Do now what it does for a
			// stalled mirror or source.
			mset, err := l.hub.globalAccount().lookupStream("DEST")
			require_NoError(t, err)
			if kind == "Mirror" {
				require_NoError(t, mset.retryMirrorConsumer())
			} else {
				mset.mu.Lock()
				for _, si := range mset.sources {
					mset.setupSourceConsumer(si.iname, si.sseq+1, time.Time{})
				}
				mset.mu.Unlock()
			}

			// The first request gets no reply and counts a failure. With no
			// leaf link event, the next request comes after the first backoff.
			_, err = reqs.NextMsg(5 * time.Second)
			require_NoError(t, err)
			first := time.Now()
			_, err = reqs.NextMsg(srcConsumerWaitTime + calculateRetryBackoff(1) + 5*time.Second)
			require_NoError(t, err)
			if gap := time.Since(first); gap < calculateRetryBackoff(1) {
				t.Fatalf("second request %v after the first, expected the backoff of %v", gap, calculateRetryBackoff(1))
			}

			up := l.setLink(true)
			if outage := up.Sub(drop); outage <= calculateRetryBackoff(1) {
				t.Fatalf("outage %v is not longer than the first backoff", outage)
			}
			waitLateLinkDest(t, l.hub, 15, 5*time.Second)
			t.Logf("%s has the new data %v after the link came up (outage %v)", kind,
				time.Since(up).Round(time.Millisecond), up.Sub(drop).Round(time.Millisecond))
		})
	}
}

// A leaf server restarts with a stored mirror or source of a hub stream while
// its link is off. The stream sends its first consumer request during the
// server start. When the link comes up some seconds later, the stream gets
// the new data within a few seconds.
func TestJetStreamLeafNodeLateLinkAfterRestart(t *testing.T) {
	for _, kind := range []string{"Mirror", "Source"} {
		t.Run(kind, func(t *testing.T) {
			l := newLateLink(t, true)
			addLateLinkOrigin(t, l.hub, 10)
			nc, js := jsClientConnect(t, l.leaf)
			_, err := js.AddStream(lateLinkDest(kind, "$JS.HUB.API"))
			require_NoError(t, err)
			nc.Close()
			waitLateLinkDest(t, l.leaf, 10, 5*time.Second)

			l.restartLeaf(false)
			publishLateLinkOrigin(t, l.hub, 5)
			checkFor(t, 5*time.Second, 25*time.Millisecond, func() error {
				return lateLinkRequestInFlight(l.leaf)
			})

			time.Sleep(sourceConsumerRetryThreshold + time.Second)
			up := l.setLink(true)
			waitLateLinkDest(t, l.leaf, 15, 5*time.Second)
			t.Logf("restored %s has the new data %v after the link came up", kind, time.Since(up).Round(time.Millisecond))
		})
	}
}

// A link event ends the wait for the reply to the first request, and a new
// request makes the consumer that the source uses. Then the reply to the
// first request arrives late at the hub. The source must not take that
// consumer as a second one.
func TestJetStreamLeafNodeLateLinkLateReply(t *testing.T) {
	l := newLateLink(t, false)
	addLateLinkOrigin(t, l.leaf, 10)

	nc, js := jsClientConnect(t, l.hub)
	defer nc.Close()
	reqs := natsSubSync(t, nc, "$JS.L1.API.CONSUMER.>")
	natsFlush(t, nc)
	_, err := js.AddStream(lateLinkDest("Source", "$JS.L1.API"))
	require_NoError(t, err)
	first, err := reqs.NextMsg(5 * time.Second)
	require_NoError(t, err)
	// Interest in the reply subject of the first request lets its late reply
	// cross the link to the hub.
	late := natsSubSync(t, nc, first.Reply)
	natsFlush(t, nc)

	l.setLink(true)
	waitLateLinkDest(t, l.hub, 10, 5*time.Second)

	// The origin gets the first request only now, and its reply is late.
	require_NoError(t, nc.PublishMsg(&nats.Msg{Subject: first.Subject, Reply: first.Reply, Header: first.Header, Data: first.Data}))
	rmsg, err := late.NextMsg(5 * time.Second)
	require_NoError(t, err)
	var ccr JSApiConsumerCreateResponse
	require_NoError(t, json.Unmarshal(rmsg.Data, &ccr))
	if ccr.Error != nil || ccr.ConsumerInfo == nil {
		t.Fatalf("late reply has no consumer: %+v", ccr.Error)
	}

	publishLateLinkOrigin(t, l.leaf, 5)
	waitLateLinkDest(t, l.hub, 15, 5*time.Second)

	mset, err := l.hub.globalAccount().lookupStream("DEST")
	require_NoError(t, err)
	var cname string
	mset.mu.RLock()
	for _, si := range mset.sources {
		cname = si.cname
	}
	mset.mu.RUnlock()
	if cname == _EMPTY_ || cname == ccr.ConsumerInfo.Name {
		t.Fatalf("source uses consumer %q, the late reply named %q", cname, ccr.ConsumerInfo.Name)
	}

	// Only the consumer that the source uses has interest on the origin. The
	// consumer API does not list direct consumers.
	origin, err := l.leaf.globalAccount().lookupStream("ORIGIN")
	require_NoError(t, err)
	var all, active []string
	for _, o := range origin.getDirectConsumers() {
		all = append(all, o.name)
		if o.isActive() {
			active = append(active, o.name)
		}
	}
	if len(active) != 1 || active[0] != cname {
		t.Fatalf("origin consumers %q, with interest %q, expected interest only for %q", all, active, cname)
	}
	t.Logf("origin consumers %q, with interest %q", all, active)
}
