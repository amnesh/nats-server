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
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func requireSubjectRollupPolicy(t *testing.T, nc *nats.Conn, js nats.JetStreamContext, stream, own, foreign string) {
	t.Helper()
	msg := nats.NewMsg(own)
	msg.Header.Set(JSMsgRollup, JSMsgRollupAll)
	msg.Data = []byte("rejected")
	reply, err := nc.RequestMsg(msg, 5*time.Second)
	require_NoError(t, err)
	var ack JSPubAckResponse
	require_NoError(t, json.Unmarshal(reply.Data, &ack))
	if ack.Error == nil || ack.Error.ErrCode != uint16(JSStreamRollupFailedF) {
		t.Fatalf("stream rollup error = %v, want rollup rejection", ack.Error)
	}
	retained, err := js.GetLastMsg(stream, foreign)
	require_NoError(t, err)
	require_Equal(t, string(retained.Data), "foreign")
	msg.Header.Set(JSMsgRollup, JSMsgRollupSubject)
	msg.Data = []byte("subject replacement")
	_, err = js.PublishMsg(msg)
	require_NoError(t, err)
	retained, err = js.GetLastMsg(stream, foreign)
	require_NoError(t, err)
	require_Equal(t, string(retained.Data), "foreign")
}

func TestJetStreamSubjectRollupOnlyLifecycle(t *testing.T) {
	t.Run("restart", func(t *testing.T) {
		opts := DefaultTestOptions
		opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
		opts.FeatureFlags = map[string]bool{"js_subject_rollup_only": true}
		s := RunServer(&opts)
		defer func() {
			s.Shutdown()
			s.WaitForShutdown()
		}()
		nc, js := jsClientConnect(t, s)
		_, err := js.AddStream(&nats.StreamConfig{Name: "RESTORED", Subjects: []string{"restored.*"}, Storage: nats.FileStorage, AllowRollup: true})
		require_NoError(t, err)
		_, err = js.Publish("restored.foreign", []byte("foreign"))
		require_NoError(t, err)
		_, err = js.Publish("restored.own", []byte("own"))
		require_NoError(t, err)
		requireSubjectRollupPolicy(t, nc, js, "RESTORED", "restored.own", "restored.foreign")
		nc.Close()
		s.Shutdown()
		s.WaitForShutdown()

		s = RunServer(&opts)
		nc, js = jsClientConnect(t, s)
		defer nc.Close()
		requireSubjectRollupPolicy(t, nc, js, "RESTORED", "restored.own", "restored.foreign")
	})

	t.Run("failed reload", func(t *testing.T) {
		opts := DefaultTestOptions
		opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
		opts.FeatureFlags = map[string]bool{"js_subject_rollup_only": true}
		s := RunServer(&opts)
		defer s.Shutdown()
		nc, js := jsClientConnect(t, s)
		defer nc.Close()
		_, err := js.AddStream(&nats.StreamConfig{Name: "RELOAD", Subjects: []string{"reload.*"}, Storage: nats.MemoryStorage, AllowRollup: true})
		require_NoError(t, err)
		_, err = js.Publish("reload.foreign", []byte("foreign"))
		require_NoError(t, err)
		next := s.getOpts().Clone()
		next.FeatureFlags = map[string]bool{"js_subject_rollup_only": false}
		if err := s.ReloadOptions(next); err == nil || !strings.Contains(err.Error(), "FeatureFlags") {
			t.Fatalf("flag reload error = %v, want unsupported FeatureFlags change", err)
		}
		requireSubjectRollupPolicy(t, nc, js, "RELOAD", "reload.own", "reload.foreign")
	})

	t.Run("subject transform", func(t *testing.T) {
		opts := DefaultTestOptions
		opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
		opts.FeatureFlags = map[string]bool{"js_subject_rollup_only": true}
		s := RunServer(&opts)
		defer s.Shutdown()
		nc, js := jsClientConnect(t, s)
		defer nc.Close()
		_, err := jsStreamCreate(t, nc, &StreamConfig{
			Name: "CUSTOM", Subjects: []string{"incoming.own", "stored.foreign"}, Storage: FileStorage,
			AllowRollup: true, SubjectTransform: &SubjectTransformConfig{Source: "incoming.own", Destination: "stored.own"},
		})
		require_NoError(t, err)
		_, err = js.Publish("stored.foreign", []byte("foreign"))
		require_NoError(t, err)
		_, err = js.Publish("incoming.own", []byte("own"))
		require_NoError(t, err)
		stored, err := js.GetLastMsg("CUSTOM", "stored.own")
		require_NoError(t, err)
		require_Equal(t, string(stored.Data), "own")
		requireSubjectRollupPolicy(t, nc, js, "CUSTOM", "incoming.own", "stored.foreign")
	})

	t.Run("leader change", func(t *testing.T) {
		c := createJetStreamClusterWithTemplate(t, jsClusterTempl+"\nfeature_flags { js_subject_rollup_only: true }\n", "ROLLUP_LIFECYCLE", 3)
		defer c.shutdown()
		nc, js := jsClientConnect(t, c.randomServer())
		defer nc.Close()
		_, err := js.AddStream(&nats.StreamConfig{Name: "LEADER", Subjects: []string{"leader.*"}, Storage: nats.FileStorage, Replicas: 3, AllowRollup: true})
		require_NoError(t, err)
		_, err = js.Publish("leader.foreign", []byte("foreign"))
		require_NoError(t, err)
		requireSubjectRollupPolicy(t, nc, js, "LEADER", "leader.own", "leader.foreign")
		old := c.streamLeader(globalAccountName, "LEADER")
		var next *Server
		for _, peer := range c.servers {
			if peer != old {
				next = peer
				break
			}
		}
		if next == nil {
			t.Fatal("no peer available for leader change")
		}
		c.stepDownStreamLeader(nc, globalAccountName, "LEADER", next)
		if c.streamLeader(globalAccountName, "LEADER") == old {
			t.Fatal("stream leader did not change")
		}
		requireSubjectRollupPolicy(t, nc, js, "LEADER", "leader.own", "leader.foreign")
	})

	t.Run("source replay", func(t *testing.T) {
		opts := DefaultTestOptions
		opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
		s := RunServer(&opts)
		defer func() {
			s.Shutdown()
			s.WaitForShutdown()
		}()
		nc, js := jsClientConnect(t, s)
		_, err := js.AddStream(&nats.StreamConfig{Name: "ORIGIN", Subjects: []string{"origin.*"}, Storage: nats.FileStorage, AllowRollup: true})
		require_NoError(t, err)
		msg := nats.NewMsg("origin.own")
		msg.Header.Set(JSMsgRollup, JSMsgRollupAll)
		msg.Data = []byte("historical rollup")
		_, err = js.PublishMsg(msg)
		require_NoError(t, err)
		nc.Close()
		s.Shutdown()
		s.WaitForShutdown()

		opts.FeatureFlags = map[string]bool{"js_subject_rollup_only": true}
		s = RunServer(&opts)
		nc, js = jsClientConnect(t, s)
		defer nc.Close()
		_, err = js.AddStream(&nats.StreamConfig{Name: "COPY", Storage: nats.FileStorage, Sources: []*nats.StreamSource{{Name: "ORIGIN"}}})
		require_NoError(t, err)
		checkFor(t, 5*time.Second, 10*time.Millisecond, func() error {
			info, err := js.StreamInfo("COPY")
			if err != nil {
				return err
			}
			if info.State.Msgs != 1 {
				return fmt.Errorf("source replay has %d messages, want 1", info.State.Msgs)
			}
			return nil
		})
		copied, err := js.GetLastMsg("COPY", "origin.own")
		require_NoError(t, err)
		require_Equal(t, string(copied.Data), "historical rollup")
		require_Equal(t, copied.Header.Get(JSMsgRollup), JSMsgRollupAll)
	})
}
