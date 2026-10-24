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
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestJetStreamSubjectRollupOnly(t *testing.T) {
	for _, clustered := range []bool{false, true} {
		for _, storage := range []StorageType{MemoryStorage, FileStorage} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("cluster=%t/%s/enabled=%t", clustered, storage, enabled), func(t *testing.T) {
					var s *Server
					replicas := 1
					if clustered {
						tmpl := jsClusterTempl
						if enabled {
							tmpl += "\nfeature_flags { js_subject_rollup_only: true }\n"
						}
						c := createJetStreamClusterWithTemplate(t, tmpl, "ROLLUP", 3)
						defer c.shutdown()
						s = c.randomServer()
						replicas = 3
					} else {
						opts := DefaultTestOptions
						opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
						if enabled {
							opts.FeatureFlags = map[string]bool{"js_subject_rollup_only": true}
						}
						s = RunServer(&opts)
						defer s.Shutdown()
					}
					nc, js := jsClientConnect(t, s)
					defer nc.Close()
					for _, mode := range []string{"ordinary", "atomic", "fast"} {
						t.Run(mode, func(t *testing.T) {
							name := "ROLLUP_" + mode
							own, foreign := name+".own", name+".foreign"
							_, err := jsStreamCreate(t, nc, &StreamConfig{
								Name: name, Subjects: []string{name + ".*"}, Storage: storage,
								Replicas: replicas, AllowRollup: true,
								AllowAtomicPublish: true, AllowBatchPublish: true,
							})
							require_NoError(t, err)
							_, err = js.Publish(foreign, []byte("foreign"))
							require_NoError(t, err)
							_, err = js.Publish(own, []byte("old"))
							require_NoError(t, err)
							_, err = js.Publish(own, []byte("new"))
							require_NoError(t, err)

							publish := func(rollup, id string) JSPubAckResponse {
								t.Helper()
								m := nats.NewMsg(own)
								m.Data = []byte(id)
								m.Header.Set(JSMsgRollup, rollup)
								var reply *nats.Msg
								var err error
								switch mode {
								case "ordinary":
									reply, err = nc.RequestMsg(m, 5*time.Second)
								case "atomic":
									m.Header.Set("Nats-Batch-Id", id)
									m.Header.Set("Nats-Batch-Sequence", "1")
									m.Header.Set("Nats-Batch-Commit", "1")
									reply, err = nc.RequestMsg(m, 5*time.Second)
								case "fast":
									inbox := nats.NewInbox()
									var sub *nats.Subscription
									sub, err = nc.SubscribeSync(inbox + ".>")
									require_NoError(t, err)
									defer sub.Unsubscribe()
									m.Reply = generateFastBatchReply(inbox, id, 1, 0, FastBatchGapFail, FastBatchOpCommit)
									require_NoError(t, nc.PublishMsg(m))
									reply, err = sub.NextMsg(5 * time.Second)
								}
								require_NoError(t, err)
								var ack JSPubAckResponse
								require_NoError(t, json.Unmarshal(reply.Data, &ack))
								return ack
							}

							ack := publish(JSMsgRollupSubject, "subject")
							if ack.Error != nil {
								t.Fatalf("subject rollup failed: %v", ack.Error)
							}
							info, err := js.StreamInfo(name)
							require_NoError(t, err)
							require_Equal(t, info.State.Msgs, uint64(2))
							retained, err := js.GetLastMsg(name, foreign)
							require_NoError(t, err)
							require_Equal(t, string(retained.Data), "foreign")

							ack = publish(JSMsgRollupAll, "stream")
							if enabled {
								if ack.Error == nil {
									t.Error("stream rollup was accepted with subject-only policy enabled")
								} else {
									require_Equal(t, ack.Error.ErrCode, uint16(JSStreamRollupFailedF))
								}
								retained, err = js.GetLastMsg(name, foreign)
								if err != nil {
									t.Errorf("foreign subject was removed: %v", err)
								} else {
									require_Equal(t, string(retained.Data), "foreign")
								}
							} else {
								if ack.Error != nil {
									t.Fatalf("default stream rollup failed: %v", ack.Error)
								}
								info, err = js.StreamInfo(name)
								require_NoError(t, err)
								require_Equal(t, info.State.Msgs, uint64(1))
							}
							require_NoError(t, js.PurgeStream(name))
							info, err = js.StreamInfo(name)
							require_NoError(t, err)
							require_Equal(t, info.State.Msgs, uint64(0))
						})
					}
				})
			}
		}
	}
}
