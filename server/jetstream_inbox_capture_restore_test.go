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
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestJetStreamInboxCaptureRestoreAdmission(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			opts := DefaultTestOptions
			opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
			opts.FeatureFlags = map[string]bool{"js_reject_inbox_capture": enabled}
			s := RunServer(&opts)
			defer s.Shutdown()
			inboxCaptureRestoreAdmission(t, s, enabled, 1)
		})
	}
}

func TestJetStreamInboxCaptureRestoreSnapshotConfig(t *testing.T) {
	opts := DefaultTestOptions
	opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
	opts.FeatureFlags = map[string]bool{"js_reject_inbox_capture": true}
	s := RunServer(&opts)
	defer s.Shutdown()
	acc := s.GlobalAccount()
	// Request-free creation models a snapshot retained from before F1.
	mset, err := acc.addStream(&StreamConfig{Name: "HIDDEN", Subjects: []string{"_INBOX.foreign.x"}, Storage: FileStorage})
	require_NoError(t, err)
	require_NoError(t, mset.store.StoreRawMsg("_INBOX.foreign.x", nil, []byte("retained"), 1, time.Now().UnixNano(), 0, false))
	snapshot, err := mset.store.Snapshot(5*time.Second, false, false)
	require_NoError(t, err)
	data, err := io.ReadAll(snapshot.Reader)
	require_NoError(t, err)
	require_NoError(t, snapshot.Reader.Close())
	for err := range snapshot.errCh {
		require_NoError(t, err)
	}
	require_NoError(t, mset.delete())
	nc := natsConnect(t, s.ClientURL())
	defer nc.Close()
	payload, err := json.Marshal(&JSApiStreamRestoreRequest{Config: StreamConfig{Name: "HIDDEN", Subjects: []string{"safe"}, Storage: FileStorage}})
	require_NoError(t, err)
	msg, err := nc.Request(fmt.Sprintf(JSApiStreamRestoreT, "HIDDEN"), payload, 5*time.Second)
	require_NoError(t, err)
	var response JSApiStreamRestoreResponse
	require_NoError(t, json.Unmarshal(msg.Data, &response))
	if response.Error != nil || !IsValidLiteralSubject(response.DeliverSubject) {
		t.Fatalf("restore admission: %s", msg.Data)
	}
	msg, err = nc.Request(response.DeliverSubject, data, 5*time.Second)
	require_NoError(t, err)
	if len(msg.Data) == 0 {
		msg, err = nc.Request(response.DeliverSubject, nil, 5*time.Second)
		require_NoError(t, err)
	}
	var result JSApiStreamCreateResponse
	require_NoError(t, json.Unmarshal(msg.Data, &result))
	if result.Error == nil || result.Error.ErrCode != 10052 || !strings.Contains(result.Error.Description, "stream configuration captures inbox subjects") {
		t.Fatalf("restore completion = %s, want structured snapshot inbox-capture rejection", msg.Data)
	}
	_, err = acc.lookupStream("HIDDEN")
	require_Error(t, err)
}

func TestJetStreamInboxCaptureRestoreFinalGate(t *testing.T) {
	opts := DefaultTestOptions
	opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
	opts.FeatureFlags = map[string]bool{"js_reject_inbox_capture": true}
	s := RunServer(&opts)
	defer s.Shutdown()
	inboxCaptureFinalTransfer(t, s, false)
}

func TestJetStreamInboxCaptureRestoreAssignmentLifetime(t *testing.T) {
	opts := DefaultTestOptions
	opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
	opts.FeatureFlags = map[string]bool{"js_reject_inbox_capture": true}
	s := RunServer(&opts)
	defer s.Shutdown()
	js := s.getJetStream()
	cfg := &StreamConfig{Name: "ASSIGN", Subjects: []string{"safe"}, Storage: FileStorage}
	configJSON, err := json.Marshal(cfg)
	require_NoError(t, err)
	sa := &streamAssignment{Client: &ClientInfo{Account: globalAccountName, InProcessUnrestricted: true}, Config: cfg, ConfigJSON: configJSON, Group: &raftGroup{Storage: FileStorage}, Restore: &StreamState{}, RestoreInboxExempt: true}
	copied := sa.clone()
	require_True(t, copied.Restore != nil && copied.RestoreInboxExempt)
	// The encoder carries an operation byte before valid assignment JSON.
	// Check fixture validity explicitly because the production encoder ignores
	// serialization errors for its already-validated assignment values.
	_, err = json.Marshal(sa)
	require_NoError(t, err)
	encoded := encodeAddStreamAssignment(sa)
	require_True(t, len(encoded) > 1 && encoded[0] == byte(assignStreamOp))
	decoded, err := decodeStreamAssignment(s, encoded[1:])
	require_NoError(t, err)
	require_True(t, decoded.Restore != nil && decoded.RestoreInboxExempt)
	require_False(t, decoded.Client.InProcessUnrestricted)
	decoded.Client = decoded.Client.forAssignmentSnap()
	gate := restoreInboxGateFromAssignment(decoded)
	require_True(t, gate.exempt)
	decoded.RestoreInboxExempt = false
	gate = restoreInboxGateFromAssignment(decoded)
	require_False(t, gate.exempt)
	final := *cfg
	final.Subjects = []string{"_INBOX.foreign.x"}
	require_Error(t, js.checkRestoredInboxCapture(gate, &final))
	snapshot, _, _, err := js.encodeMetaSnapshot(map[string]map[string]*streamAssignment{globalAccountName: {cfg.Name: sa}})
	require_NoError(t, err)
	restored, err := js.decodeMetaSnapshot(snapshot)
	require_NoError(t, err)
	snapAssignment := restored[globalAccountName][cfg.Name]
	require_True(t, snapAssignment.Restore == nil)
	require_False(t, snapAssignment.RestoreInboxExempt)
	js.setStreamAssignmentRecovering(copied)
	require_True(t, copied.Restore == nil)
	require_False(t, copied.RestoreInboxExempt)
}

func TestJetStreamInboxCaptureLifecycle(t *testing.T) {
	opts := DefaultTestOptions
	opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
	s := RunServer(&opts)
	defer func() {
		s.Shutdown()
		s.WaitForShutdown()
	}()
	nc, js := jsClientConnect(t, s)
	_, err := js.AddStream(&nats.StreamConfig{Name: "RECOVER", Subjects: []string{"_INBOX.foreign.recover"}, Storage: nats.FileStorage})
	require_NoError(t, err)
	_, err = js.Publish("_INBOX.foreign.recover", []byte("before"))
	require_NoError(t, err)
	nc.Close()
	s.Shutdown()
	s.WaitForShutdown()
	opts.FeatureFlags = map[string]bool{"js_reject_inbox_capture": true}
	s = RunServer(&opts)
	nc, js = jsClientConnect(t, s)
	defer nc.Close()
	info, err := js.StreamInfo("RECOVER")
	require_NoError(t, err)
	require_Equal(t, info.State.Msgs, uint64(1))
	_, err = js.Publish("_INBOX.foreign.recover", []byte("after"))
	require_NoError(t, err)
	msg, err := js.GetMsg("RECOVER", 2)
	require_NoError(t, err)
	require_Equal(t, string(msg.Data), "after")
	for _, reload := range []bool{false, true} {
		if reload {
			next := s.getOpts().Clone()
			next.FeatureFlags = map[string]bool{"js_reject_inbox_capture": false}
			err := s.ReloadOptions(next)
			if err == nil || !strings.Contains(err.Error(), "FeatureFlags") {
				t.Fatalf("flag reload: %v", err)
			}
		}
		_, err := js.UpdateStream(&info.Config)
		if err == nil || !strings.Contains(err.Error(), ErrJSStreamInboxCapture.Error()) {
			t.Fatalf("ordinary recovered-config update: %v", err)
		}
		info, err = js.StreamInfo("RECOVER")
		require_NoError(t, err)
		require_Equal(t, info.State.Msgs, uint64(2))
		require_Equal(t, info.Config.Subjects[0], "_INBOX.foreign.recover")
	}
}

func TestJetStreamInboxCaptureRestoreLiveAPI(t *testing.T) {
	conf := createConfFile(t, []byte(fmt.Sprintf("listen: 127.0.0.1:-1\njetstream {store_dir: %q}\n", t.TempDir())+inboxCaptureOriginAccounts))
	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()
	inboxCaptureLiveRestore(t, s, s, false)
}

func TestJetStreamInboxCaptureRestoreLegacyCompatibility(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			accounts := strings.Replace(inboxCaptureOriginAccounts, "js_reject_inbox_capture: true", fmt.Sprintf("js_reject_inbox_capture: %t", enabled), 1)
			conf := createConfFile(t, []byte(fmt.Sprintf("listen: 127.0.0.1:-1\njetstream {store_dir: %q}\n", t.TempDir())+accounts))
			s, _ := RunServerWithConfig(conf)
			defer s.Shutdown()
			// With F1 on this is the authenticated unrestricted host; with it
			// off this is an ordinary network origin.
			nc := inboxCaptureOriginConnect(t, s, "host", enabled)
			cfg := StreamConfig{Name: "COMPAT", Subjects: []string{"safe.compat"}, Storage: FileStorage}
			data, state := inboxCaptureTransferSnapshot(t, cfg, true)
			data = inboxCaptureLegacyMetadataAge(t, data)
			payload, err := json.Marshal(&JSApiStreamRestoreRequest{Config: cfg, State: state})
			require_NoError(t, err)
			msg, err := nc.Request(fmt.Sprintf(JSApiStreamRestoreT, cfg.Name), payload, 5*time.Second)
			require_NoError(t, err)
			var response JSApiStreamRestoreResponse
			require_NoError(t, json.Unmarshal(msg.Data, &response))
			if response.Error != nil {
				t.Fatalf("compatibility restore admission: %s", msg.Data)
			}
			require_True(t, IsValidLiteralSubject(response.DeliverSubject))
			msg, err = nc.Request(response.DeliverSubject, data, 5*time.Second)
			require_NoError(t, err)
			if len(msg.Data) == 0 {
				msg, err = nc.Request(response.DeliverSubject, nil, 5*time.Second)
				require_NoError(t, err)
			}
			var result JSApiStreamCreateResponse
			require_NoError(t, json.Unmarshal(msg.Data, &result))
			if result.Error != nil {
				t.Fatalf("compatibility restore completion: %s", msg.Data)
			}
			account, err := s.LookupAccount("APP")
			require_NoError(t, err)
			mset, err := account.lookupStream(cfg.Name)
			require_NoError(t, err)
			require_Equal(t, mset.config().MaxAge, time.Duration(0))
			retained, err := mset.store.LoadMsg(1, nil)
			require_NoError(t, err)
			require_Equal(t, string(retained.msg), "retained")
		})
	}
}
