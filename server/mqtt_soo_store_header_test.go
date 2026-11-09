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

//go:build !skip_mqtt_tests && !skip_js_tests

package server

import (
	"fmt"
	"testing"
	"time"
)

// MQTT writes its own header blocks and stores them in JetStream through
// internal clients: QoS 1 and QoS 2 messages, retained messages and their
// delete markers, sessions, and incoming QoS 2 messages. Each stored header
// block must be strict: a block that is not strict stops a mirror, a source,
// or an ordered consumer across a leaf link into a server with
// stamp_request_info on (FORK-CHANGES 2.4). Before the fork correction of the
// MQTT request header block (FORK-CHANGES 13), each session record had the
// block "NATS/1.0\r\n\r\n\r\n". The server runs with stamping on, so the
// test also shows that MQTT stores its messages while stamping is on.
func TestMQTTStampRequestInfoStoreHeaderBlocks(t *testing.T) {
	o := testMQTTDefaultOptions()
	o.StampRequestInfo = true
	s := testMQTTRunServer(t, o)
	defer testMQTTShutdownServer(s)

	// A subscriber with a session and a QoS 2 subscription, so that the
	// server stores QoS 1 and QoS 2 messages for it.
	sc, sr := testMQTTConnect(t, &mqttConnInfo{clientID: "sub", cleanSess: false}, o.MQTT.Host, o.MQTT.Port)
	defer sc.Close()
	testMQTTCheckConnAck(t, sr, mqttConnAckRCConnectionAccepted, false)
	testMQTTSub(t, 1, sc, sr, []*mqttFilter{{filter: "foo/#", qos: 2}}, []byte{2})
	testMQTTFlush(t, sc, nil, sr)

	// Each publish waits for the PUBACK or the PUBCOMP. The server sends it
	// only after JetStream stores the message.
	pc, pr := testMQTTConnect(t, &mqttConnInfo{clientID: "pub", cleanSess: true}, o.MQTT.Host, o.MQTT.Port)
	defer pc.Close()
	testMQTTCheckConnAck(t, pr, mqttConnAckRCConnectionAccepted, false)
	testMQTTPublish(t, pc, pr, 1, false, true, "foo/retained", 1, []byte("r"))
	testMQTTPublish(t, pc, pr, 1, false, false, "foo/qos1", 2, []byte("q1"))
	testMQTTPublish(t, pc, pr, 2, false, false, "foo/qos2", 3, []byte("q2"))
	// A retained message with an empty payload deletes the retained message.
	// The server stores a delete marker for it.
	testMQTTPublish(t, pc, pr, 1, false, true, "foo/retained2", 4, []byte("r2"))
	testMQTTPublish(t, pc, pr, 1, false, true, "foo/retained2", 5, nil)

	acc := s.GlobalAccount()
	strict := func(name string) int {
		t.Helper()
		mset, err := acc.lookupStream(name)
		require_NoError(t, err)
		var state StreamState
		mset.store.FastState(&state)
		var n int
		var smv StoreMsg
		for seq := state.FirstSeq; state.Msgs > 0 && seq <= state.LastSeq; seq++ {
			sm, err := mset.store.LoadMsg(seq, &smv)
			if err != nil || len(sm.hdr) == 0 {
				continue
			}
			if !requestInfoHeaderBlockValid(sm.hdr) {
				t.Fatalf("Stream %q stores a header block that is not strict: %q", name, sm.hdr)
			}
			n++
		}
		return n
	}
	checkFor(t, 10*time.Second, 50*time.Millisecond, func() error {
		for _, name := range []string{mqttStreamName, mqttRetainedMsgsStreamName, mqttSessStreamName} {
			mset, err := acc.lookupStream(name)
			if err != nil {
				return err
			}
			if n := mset.state().Msgs; n == 0 {
				return fmt.Errorf("stream %q has no messages", name)
			}
		}
		return nil
	})
	for _, name := range []string{mqttRetainedMsgsStreamName, mqttSessStreamName, mqttQoS2IncomingMsgsStreamName, mqttOutStreamName} {
		if _, err := acc.lookupStream(name); err == nil {
			strict(name)
		}
	}
	if n := strict(mqttStreamName); n < 2 {
		t.Fatalf("Want the QoS 1 and QoS 2 messages in %q, got %d", mqttStreamName, n)
	}
}
