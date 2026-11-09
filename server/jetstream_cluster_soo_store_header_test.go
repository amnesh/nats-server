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
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// storeHeaderMoveStreamLeader moves the leader of a stream to server to.
func storeHeaderMoveStreamLeader(t *testing.T, c *cluster, nc *nats.Conn, stream string, to *Server) {
	t.Helper()
	req, err := json.Marshal(&JSApiLeaderStepdownRequest{Placement: &Placement{Preferred: to.Name()}})
	require_NoError(t, err)
	checkFor(t, 30*time.Second, 250*time.Millisecond, func() error {
		c.waitOnStreamLeader(globalAccountName, stream)
		if c.streamLeader(globalAccountName, stream) == to {
			return nil
		}
		nc.Request(fmt.Sprintf(JSApiStreamLeaderStepDownT, stream), req, 2*time.Second)
		return fmt.Errorf("leader of stream %q is not %s", stream, to.Name())
	})
}

func storeHeaderPeerMsgs(t *testing.T, s *Server, stream string) uint64 {
	t.Helper()
	mset, err := s.GlobalAccount().lookupStream(stream)
	require_NoError(t, err)
	return mset.state().Msgs
}

// A two-server cluster: S-1 has stamping on, and S-2 has stamping off. A raw
// client of S-2 publishes loose header blocks. S-2 does not check them (no
// stamping), and the route to S-1 is not checked at ingress. For a stream
// with its leader on S-1, the store check rejects them: before the store
// (R1, no Raft node) and before the proposal (R2). The stream count does not
// change on any peer, and a publish with a reply gets the error. For a stream
// with its leader on S-2, nothing changes. A mirror and a source with their
// leader on S-1 store a loose block from a stream on S-2: ingest is not
// checked.
func TestJetStreamClusterStampRequestInfoStoreHeaderBlock(t *testing.T) {
	c := createJetStreamClusterWithTemplateAndModHook(t, jsClusterTempl, "SH", 2,
		func(serverName, clusterName, storeDir, conf string) string {
			if serverName == "S-1" {
				return conf + "\nstamp_request_info: true\nserver_tags: [\"stamp:on\"]\n"
			}
			return conf + "\nserver_tags: [\"stamp:off\"]\n"
		})
	defer c.shutdown()
	on, off := c.serverByName("S-1"), c.serverByName("S-2")
	require_True(t, on.stampReqInfo.Load())
	require_False(t, off.stampReqInfo.Load())
	l := &storeHeaderLogger{}
	on.SetLogger(l, false, false)

	nc, _ := jsClientConnect(t, off)
	defer nc.Close()
	sub := natsSubSync(t, nc, "reply.>")
	natsFlush(t, nc)
	checkSubInterest(t, on, globalAccountName, "reply.x", 10*time.Second)
	raw := dialRawStorePub(t, off)

	for _, tc := range []struct {
		name     string
		replicas int
	}{{"ON1", 1}, {"ON2", 2}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &StreamConfig{Name: tc.name, Subjects: []string{tc.name + ".>"}, Storage: FileStorage, Replicas: tc.replicas}
			if tc.replicas == 1 {
				cfg.Placement = &Placement{Tags: []string{"stamp:on"}}
			}
			addStream(t, nc, cfg)
			storeHeaderMoveStreamLeader(t, c, nc, tc.name, on)
			// S-2 must know the stream interest of S-1, or it drops the
			// publish for no interest.
			checkSubInterest(t, off, globalAccountName, tc.name+".x", 10*time.Second)

			// Without a reply: dropped, with a warning. The strict publish
			// with a reply from the same connection is the barrier.
			raw.hpub(tc.name+".a", _EMPTY_, looseStoreHeaderBlocks[0], "x")
			raw.hpub(tc.name+".b", "reply."+tc.name+".1", strictStoreHeaderBlock, "x")
			requireStoreHeaderSeq(t, natsNexMsg(t, sub, 5*time.Second), 1)
			require_Equal(t, l.rejects(tc.name), 1)

			// With a reply: the PubAck has the error.
			for i, hdr := range looseStoreHeaderBlocks {
				raw.hpub(tc.name+".c", fmt.Sprintf("reply.%s.loose.%d", tc.name, i), hdr, "x")
				requireStoreHeaderReject(t, natsNexMsg(t, sub, 5*time.Second))
			}
			raw.hpub(tc.name+".d", "reply."+tc.name+".2", strictStoreHeaderBlock, "x")
			requireStoreHeaderSeq(t, natsNexMsg(t, sub, 5*time.Second), 2)

			checkFor(t, 10*time.Second, 50*time.Millisecond, func() error {
				for _, s := range c.servers {
					if tc.replicas == 1 && s != on {
						continue
					}
					if n := storeHeaderPeerMsgs(t, s, tc.name); n != 2 {
						return fmt.Errorf("%s has %d messages on %s", tc.name, n, s.Name())
					}
				}
				return nil
			})
			for _, s := range c.servers {
				if tc.replicas == 2 || s == on {
					requireStoredHeaderBlocksStrict(t, s, s.GlobalAccount(), tc.name)
				}
			}
		})
	}

	// An R2 stream with its leader on S-2 (stamping off) and its follower on
	// S-1 (stamping on) stores the loose block on both peers. The follower
	// applies the entry without the check, so the replicas stay equal.
	addStream(t, nc, &StreamConfig{Name: "OFF2", Subjects: []string{"OFF2.>"}, Storage: FileStorage, Replicas: 2})
	storeHeaderMoveStreamLeader(t, c, nc, "OFF2", off)
	raw.hpub("OFF2.a", "reply.OFF2.1", looseStoreHeaderBlocks[0], "x")
	requireStoreHeaderSeq(t, natsNexMsg(t, sub, 5*time.Second), 1)
	checkFor(t, 10*time.Second, 50*time.Millisecond, func() error {
		for _, s := range c.servers {
			if n := storeHeaderPeerMsgs(t, s, "OFF2"); n != 1 {
				return fmt.Errorf("OFF2 has %d messages on %s", n, s.Name())
			}
		}
		return nil
	})
	for _, s := range c.servers {
		got := storedHeaderBlocks(t, s, s.GlobalAccount(), "OFF2")
		if len(got) != 1 || string(got[0]) != looseStoreHeaderBlocks[0] {
			t.Fatalf("OFF2 on %s: want the loose block, got %q", s.Name(), got)
		}
	}
	require_Equal(t, l.rejects("OFF2"), 0)

	// A stream with its leader on S-2 (stamping off) stores the loose block:
	// no change. The mirrors and sources exist before the loose message, with
	// their leaders on S-1, so S-1 does their ingest.
	addStream(t, nc, &StreamConfig{Name: "OFF", Subjects: []string{"OFF.>"}, Storage: FileStorage,
		Placement: &Placement{Tags: []string{"stamp:off"}}})
	ingest := []string{"MIR1", "SRC1", "MIR2", "SRC2"}
	for _, name := range ingest {
		cfg := &StreamConfig{Name: name, Storage: FileStorage, Replicas: 1, Placement: &Placement{Tags: []string{"stamp:on"}}}
		if name[3] == '2' {
			cfg.Replicas, cfg.Placement = 2, nil
		}
		if name[0] == 'M' {
			cfg.Mirror = &StreamSource{Name: "OFF"}
		} else {
			cfg.Sources = []*StreamSource{{Name: "OFF"}}
		}
		addStream(t, nc, cfg)
		storeHeaderMoveStreamLeader(t, c, nc, name, on)
	}
	raw.hpub("OFF.a", "reply.OFF.1", looseStoreHeaderBlocks[1], "x")
	requireStoreHeaderSeq(t, natsNexMsg(t, sub, 5*time.Second), 1)
	stored := storedHeaderBlocks(t, off, off.GlobalAccount(), "OFF")
	require_Len(t, len(stored), 1)
	require_Equal(t, string(stored[0]), looseStoreHeaderBlocks[1])

	checkFor(t, 20*time.Second, 50*time.Millisecond, func() error {
		for _, name := range ingest {
			if n := storeHeaderPeerMsgs(t, on, name); n != 1 {
				return fmt.Errorf("%s has %d messages on S-1", name, n)
			}
		}
		return nil
	})
	for _, name := range ingest {
		got := storedHeaderBlocks(t, on, on.GlobalAccount(), name)
		require_Len(t, len(got), 1)
		if requestInfoHeaderBlockValid(got[0]) {
			t.Fatalf("%s: want the loose block, got %q", name, got[0])
		}
		if name[0] == 'M' && string(got[0]) != looseStoreHeaderBlocks[1] {
			t.Fatalf("%s: want %q, got %q", name, looseStoreHeaderBlocks[1], got[0])
		}
		require_Equal(t, l.rejects(name), 0)
	}
}
