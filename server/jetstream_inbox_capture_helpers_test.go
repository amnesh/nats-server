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
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/s2"
	"github.com/nats-io/nats.go"
)

func requireInboxCaptureError(t *testing.T, apiErr *ApiError) {
	t.Helper()
	if apiErr == nil || apiErr.ErrCode != uint16(JSStreamInvalidConfigF) || !strings.Contains(apiErr.Description, "stream configuration captures inbox subjects") {
		t.Fatalf("error = %v, want inbox-capture rejection with API code 10052", apiErr)
	}
}

func inboxCaptureAdmission(t *testing.T, clustered bool) {
	for _, storage := range []StorageType{MemoryStorage, FileStorage} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("cluster=%t/%s/enabled=%t", clustered, storage, enabled), func(t *testing.T) {
				var s *Server
				replicas := 1
				if clustered {
					tmpl := jsClusterTempl
					if enabled {
						tmpl += "\nfeature_flags { js_reject_inbox_capture: true }\n"
					}
					c := createJetStreamClusterWithTemplate(t, tmpl, "INBOX_CAPTURE", 3)
					defer c.shutdown()
					s, replicas = c.randomServer(), 3
				} else {
					opts := DefaultTestOptions
					opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
					if enabled {
						opts.FeatureFlags = map[string]bool{"js_reject_inbox_capture": true}
					}
					s = RunServer(&opts)
					defer s.Shutdown()
				}
				nc, js := jsClientConnect(t, s)
				defer nc.Close()
				for i, subjects := range [][]string{{"_INBOX.foreign.x"}, {"orders.>", "_INBOX.a.>"}, {"*.>"}, {"*.*"}, {">"}} {
					name := fmt.Sprintf("CAPTURE_%d", i)
					cfg := &StreamConfig{Name: name, Subjects: subjects, Storage: storage, Replicas: 1, NoAck: true}
					data, err := json.Marshal(cfg)
					require_NoError(t, err)
					reply, err := nc.Request(fmt.Sprintf(JSApiStreamCreateT, name), data, 5*time.Second)
					require_NoError(t, err)
					var response JSApiStreamCreateResponse
					require_NoError(t, json.Unmarshal(reply.Data, &response))
					if enabled {
						requireInboxCaptureError(t, response.Error)
						_, err = js.StreamInfo(name)
						if err == nil {
							t.Fatalf("rejected stream %s exists", name)
						}
					} else {
						if response.Error != nil {
							t.Fatal(response.Error)
						}
						require_NoError(t, js.DeleteStream(name))
					}
				}
				// Keep positive publication/read controls outside the capture namespace.
				_, err := jsStreamCreate(t, nc, &StreamConfig{Name: "SAFE", Subjects: []string{"orders.>"}, Storage: storage, Replicas: replicas})
				require_NoError(t, err)
				_, err = js.Publish("orders.one", []byte("safe"))
				require_NoError(t, err)
				m, err := js.GetLastMsg("SAFE", "orders.one")
				require_NoError(t, err)
				require_Equal(t, string(m.Data), "safe")
				update := &StreamConfig{Name: "SAFE", Subjects: []string{"orders.>", "_INBOX.foreign.>"}, Storage: storage, Replicas: replicas}
				data, err := json.Marshal(update)
				require_NoError(t, err)
				reply, err := nc.Request(fmt.Sprintf(JSApiStreamUpdateT, "SAFE"), data, 5*time.Second)
				require_NoError(t, err)
				var response JSApiStreamUpdateResponse
				require_NoError(t, json.Unmarshal(reply.Data, &response))
				if enabled {
					requireInboxCaptureError(t, response.Error)
					require_NoError(t, nc.Publish("_INBOX.foreign.x", []byte("foreign")))
					require_NoError(t, nc.Flush())
					_, err = js.Publish("orders.two", []byte("retained"))
					require_NoError(t, err)
					info, err := js.StreamInfo("SAFE")
					require_NoError(t, err)
					require_Equal(t, info.State.Msgs, uint64(2))
					require_Equal(t, len(info.Config.Subjects), 1)
				} else {
					if response.Error != nil {
						t.Fatal(response.Error)
					}
				}
			})
		}
	}
}

// Each installed subscription must equal the consumer's declared delivery.
func inboxCaptureDeliveryEqual(t *testing.T, destination, origin *stream) {
	t.Helper()
	checkFor(t, 10*time.Second, 25*time.Millisecond, func() error {
		return inboxCaptureDeliveryEqualOnce(destination, origin)
	})
}

func inboxCaptureDeliveryEqualOnce(destination, origin *stream) error {
	type delivery struct {
		consumer, subject string
		inProgress        bool
		failures          int
		setupErr          *ApiError
		requestAge        time.Duration
		waitGroup         string
	}
	destination.mu.RLock()
	var infos []*sourceInfo
	if destination.mirror != nil {
		infos = append(infos, destination.mirror)
	}
	for _, si := range destination.sources {
		infos = append(infos, si)
	}
	var deliveries []delivery
	for _, si := range infos {
		state := delivery{consumer: si.cname, inProgress: si.sip, failures: si.fails, setupErr: si.err}
		state.waitGroup = fmt.Sprintf("%p", &si.wg)
		if !si.lreq.IsZero() {
			state.requestAge = time.Since(si.lreq)
		}
		if si.sub != nil {
			state.subject = string(si.sub.subject)
		}
		deliveries = append(deliveries, state)
	}
	destination.mu.RUnlock()
	if len(deliveries) == 0 {
		return fmt.Errorf("delivery source info not ready")
	}
	for _, state := range deliveries {
		if state.inProgress || state.subject == "" {
			return fmt.Errorf("delivery setup: consumer=%q subscription=%q in_progress=%t failures=%d request_age=%s request_wait=%s wait_group=%s error=%v", state.consumer, state.subject, state.inProgress, state.failures, state.requestAge, srcConsumerWaitTime, state.waitGroup, state.setupErr)
		}
		o := origin.lookupConsumer(state.consumer)
		if o == nil {
			return fmt.Errorf("consumer %s not ready", state.consumer)
		}
		want := o.config().DeliverSubject
		if state.subject != want {
			return fmt.Errorf("delivery mismatch: consumer %q, subscription %q", want, state.subject)
		}
	}
	return nil
}

func inboxCaptureClusterDeliveryEqual(t *testing.T, c *cluster, phase, name string, budget time.Duration) {
	t.Helper()
	defer func() {
		if !t.Failed() {
			return
		}
		stacks := make([]byte, 2<<20)
		n := runtime.Stack(stacks, true)
		for _, stack := range strings.Split(string(stacks[:n]), "\n\n") {
			if strings.Contains(stack, ".setupMirrorConsumer") || strings.Contains(stack, ".processMirrorMsgs") || strings.Contains(stack, ".trySetupSourceConsumer") || strings.Contains(stack, ".processSourceMsgs") || strings.Contains(stack, ".processAllSourceMsgs") {
				t.Logf("delivery-readiness phase=%s stream=%s stack:\n%s", phase, name, stack)
			}
		}
	}()
	checkFor(t, budget, 25*time.Millisecond, func() error {
		originLeader := c.streamLeader(globalAccountName, "ORIGIN")
		destLeader := c.streamLeader(globalAccountName, name)
		if originLeader == nil || destLeader == nil {
			return fmt.Errorf("phase=%s stream=%s: current leader absent", phase, name)
		}
		origin, err := originLeader.globalAccount().lookupStream("ORIGIN")
		if err != nil {
			return err
		}
		dest, err := destLeader.globalAccount().lookupStream(name)
		if err != nil {
			return err
		}
		err = inboxCaptureDeliveryEqualOnce(dest, origin)
		if !dest.isLeader() || !origin.isLeader() {
			err = fmt.Errorf("stream leadership changed during lookup: %v", err)
		}
		if err == nil {
			return nil
		}
		currentDest, currentOrigin := "none", "none"
		if leader := c.streamLeader(globalAccountName, name); leader != nil {
			currentDest = leader.Name()
		}
		if leader := c.streamLeader(globalAccountName, "ORIGIN"); leader != nil {
			currentOrigin = leader.Name()
		}
		return fmt.Errorf("phase=%s stream=%s captured_destination=%s captured_destination_is_leader=%t current_destination=%s captured_origin=%s captured_origin_is_leader=%t current_origin=%s: %w", phase, name, dest.srv.Name(), dest.isLeader(), currentDest, origin.srv.Name(), origin.isLeader(), currentOrigin, err)
	})
}

// Keep a stalled count tied to its lifecycle phase and the delivery boundary.
func inboxCaptureClusterDeliveryDiagnostic(c *cluster, phase, name string, expected uint64, info *nats.StreamInfo) error {
	originLeader := c.streamLeader(globalAccountName, "ORIGIN")
	destLeader := c.streamLeader(globalAccountName, name)
	originState := StreamState{}
	originName, destName := "none", "none"
	var origin *stream
	if originLeader != nil {
		originName = originLeader.Name()
		origin, _ = originLeader.globalAccount().lookupStream("ORIGIN")
		if origin != nil {
			origin.store.FastState(&originState)
		}
	}
	wire := "destination has no leader"
	if destLeader != nil {
		destName = destLeader.Name()
		if dest, err := destLeader.globalAccount().lookupStream(name); err != nil {
			wire = err.Error()
		} else {
			var cname, subject string
			var setupErr *ApiError
			var sip bool
			var fails int
			var sseq, dseq uint64
			dest.mu.RLock()
			si := dest.mirror
			if si == nil {
				for _, source := range dest.sources {
					si = source
					break
				}
			}
			if si != nil {
				cname, setupErr, sip, fails, sseq, dseq = si.cname, si.err, si.sip, si.fails, si.sseq, si.dseq
				if si.sub != nil {
					subject = string(si.sub.subject)
				}
			}
			dest.mu.RUnlock()
			consumerSubject := "consumer-not-found"
			if origin != nil {
				if consumer := origin.lookupConsumer(cname); consumer != nil {
					consumerSubject = consumer.config().DeliverSubject
				}
			}
			wire = fmt.Sprintf("consumer=%q subscription=%q consumer_delivery=%q equal=%t setup_in_progress=%t failures=%d source_sequence=%d delivery_sequence=%d setup_error=%v", cname, subject, consumerSubject, subject == consumerSubject, sip, fails, sseq, dseq, setupErr)
		}
	}
	state, _ := json.Marshal(info)
	return fmt.Errorf("phase=%s stream=%s expected=%d actual=%d origin_leader=%s origin_state=%+v destination_leader=%s destination_info=%s wire={%s}", phase, name, expected, info.State.Msgs, originName, originState, destName, state, wire)
}

func inboxCaptureOriginOptions(t *testing.T) (*Options, *Account, *Account) {
	t.Helper()
	sys, app, chain := NewAccount("SYS"), NewAccount("APP"), NewAccount("CHAIN")
	require_NoError(t, sys.AddServiceExport("$JS.ORIGIN", nil))
	require_NoError(t, app.AddServiceImport(sys, "$JS.ORIGIN", "$JS.ORIGIN"))
	require_NoError(t, app.AddServiceExport("$JS.ORIGIN", nil))
	require_NoError(t, chain.AddServiceImport(app, "$JS.ORIGIN", "$JS.ORIGIN"))
	o := DefaultOptions()
	// DefaultOptions enables a test cluster listener. Origins are standalone
	// unless their transport fixture explicitly configures routes.
	o.Cluster = ClusterOpts{}
	o.Host, o.Port = "127.0.0.1", -1
	o.SystemAccount = "SYS"
	o.Accounts = []*Account{sys, app, chain}
	o.Users = []*User{
		{Username: "sys", Password: "pwd", Account: sys},
		{Username: "host", Password: "pwd", Account: app},
		{Username: "bounded", Password: "pwd", Account: app, Permissions: &Permissions{
			Publish:   &SubjectPermission{Allow: []string{">"}},
			Subscribe: &SubjectPermission{Allow: []string{">"}},
		}},
		{Username: "chain", Password: "pwd", Account: chain},
	}
	return o, sys, app
}

func inboxCaptureOriginServer(t *testing.T, changes ...func(*Options)) (*Server, *Account, *Account) {
	t.Helper()
	o, sys, app := inboxCaptureOriginOptions(t)
	for _, change := range changes {
		change(o)
	}
	s := RunServer(o)
	t.Cleanup(s.Shutdown)
	return s, sys, app
}

func inboxCaptureOriginConnect(t *testing.T, s *Server, user string, inProcess bool) *nats.Conn {
	t.Helper()
	opts := []nats.Option{nats.UserInfo(user, "pwd")}
	if inProcess {
		opts = append(opts, nats.InProcessServer(s))
	}
	nc := natsConnect(t, s.ClientURL(), opts...)
	t.Cleanup(nc.Close)
	return nc
}

const inboxCaptureOriginAccounts = `
    system_account: SYS
    accounts {
        SYS { users: [{user: sys, password: pwd}] }
        APP {
            jetstream: enabled
            exports: [{service: "$JS.API.>"}]
            users: [
                {user: host, password: pwd}
                {user: bounded, password: pwd, permissions: {publish: ">", subscribe: ">"}}
            ]
        }
        CHAIN {
            users: [{user: chain, password: pwd}]
            imports: [{service: {account: APP, subject: "$JS.API.>"}}]
        }
    }
    feature_flags {js_reject_inbox_capture: true}
`

func inboxCaptureOriginAPIControls(t *testing.T, s *Server, replicas int) {
	t.Helper()
	host := inboxCaptureOriginConnect(t, s, "host", true)
	inspect, err := host.JetStream()
	require_NoError(t, err)
	for i, origin := range []struct {
		user  string
		iproc bool
	}{{"bounded", true}, {"host", false}} {
		nc := inboxCaptureOriginConnect(t, s, origin.user, origin.iproc)
		js, err := nc.JetStream()
		require_NoError(t, err)
		name := fmt.Sprintf("SAFE_ORIGIN_%d", i)
		cfg := &StreamConfig{Name: name, Subjects: []string{name + ".>"}, Storage: FileStorage, Replicas: replicas}
		_, err = jsStreamCreate(t, nc, cfg)
		require_NoError(t, err)
		_, err = js.Publish(name+".one", []byte("safe"))
		require_NoError(t, err)
		msg, err := js.GetLastMsg(name, name+".one")
		require_NoError(t, err)
		require_Equal(t, string(msg.Data), "safe")
		badName := fmt.Sprintf("BAD_ORIGIN_%d", i)
		bad := &StreamConfig{Name: badName, Subjects: []string{"_INBOX.foreign.x"}, Storage: FileStorage, Replicas: replicas}
		payload, err := json.Marshal(bad)
		require_NoError(t, err)
		request := nats.NewMsg(fmt.Sprintf(JSApiStreamCreateT, badName))
		request.Data = payload
		request.Header.Set(ClientInfoHdr, `{"acc":"APP","iproc_unrestricted":true}`)
		response, err := nc.RequestMsg(request, 5*time.Second)
		require_NoError(t, err)
		var create JSApiStreamCreateResponse
		require_NoError(t, json.Unmarshal(response.Data, &create))
		requireInboxCaptureError(t, create.Error)
		_, err = inspect.StreamInfo(badName)
		require_Error(t, err)
		cfg.Subjects = []string{"_INBOX.foreign.x"}
		payload, err = json.Marshal(cfg)
		require_NoError(t, err)
		response, err = nc.Request(fmt.Sprintf(JSApiStreamUpdateT, name), payload, 5*time.Second)
		require_NoError(t, err)
		var update JSApiStreamUpdateResponse
		require_NoError(t, json.Unmarshal(response.Data, &update))
		requireInboxCaptureError(t, update.Error)
		info, err := inspect.StreamInfo(name)
		require_NoError(t, err)
		require_Equal(t, len(info.Config.Subjects), 1)
		require_Equal(t, info.Config.Subjects[0], name+".>")
		payload, err = json.Marshal(&JSApiStreamRestoreRequest{Config: *bad})
		require_NoError(t, err)
		response, err = nc.Request(fmt.Sprintf(JSApiStreamRestoreT, badName), payload, 5*time.Second)
		require_NoError(t, err)
		var restore JSApiStreamRestoreResponse
		require_NoError(t, json.Unmarshal(response.Data, &restore))
		requireInboxCaptureError(t, restore.Error)
		require_Equal(t, restore.DeliverSubject, "")
		_, err = inspect.StreamInfo(badName)
		require_Error(t, err)
		require_NoError(t, nc.Publish("_INBOX.foreign.x", []byte("foreign")))
		require_NoError(t, nc.Flush())
		_, err = js.Publish(name+".two", []byte("retained"))
		require_NoError(t, err)
		info, err = inspect.StreamInfo(name)
		require_NoError(t, err)
		require_Equal(t, info.State.Msgs, uint64(2))
		require_NoError(t, inspect.DeleteStream(name))
	}
	for i, subjects := range [][]string{{"_INBOX.>"}, {">"}, {"ordinary.>", "_INBOX.>"}} {
		name := fmt.Sprintf("TRUSTED_%d", i)
		_, err := jsStreamCreate(t, host, &StreamConfig{Name: name, Subjects: subjects, Storage: MemoryStorage, Replicas: 1, NoAck: true})
		require_NoError(t, err)
		require_NoError(t, inspect.DeleteStream(name))
	}
	// A system-account network client can select APP in CI, but cannot forge
	// the admission exemption. Observe a structured response, not a timeout.
	sys := inboxCaptureOriginConnect(t, s, "sys", false)
	payload, err := json.Marshal(&StreamConfig{Name: "SYS_SPOOF", Subjects: []string{"_INBOX.>"}, Storage: MemoryStorage, NoAck: true})
	require_NoError(t, err)
	request := nats.NewMsg(fmt.Sprintf(JSApiStreamCreateT, "SYS_SPOOF"))
	request.Data = payload
	request.Header.Set(ClientInfoHdr, `{"acc":"APP","iproc_unrestricted":true}`)
	response, err := sys.RequestMsg(request, 5*time.Second)
	require_NoError(t, err)
	var create JSApiStreamCreateResponse
	require_NoError(t, json.Unmarshal(response.Data, &create))
	requireInboxCaptureError(t, create.Error)
	_, err = inspect.StreamInfo("SYS_SPOOF")
	require_Error(t, err)
	// A trusted in-process origin loses its exemption at a second import.
	chained := inboxCaptureOriginConnect(t, s, "chain", true)
	for _, operation := range []string{"create", "update", "restore"} {
		name, api := "CHAIN_BAD", JSApiStreamCreateT
		if operation == "update" {
			name, api = "CHAIN_SAFE", JSApiStreamUpdateT
		}
		if operation == "restore" {
			api = JSApiStreamRestoreT
		}
		if operation == "update" {
			_, err = jsStreamCreate(t, host, &StreamConfig{Name: name, Subjects: []string{"chain.safe"}, Storage: MemoryStorage, Replicas: replicas})
			require_NoError(t, err)
		}
		cfg := StreamConfig{Name: name, Subjects: []string{"_INBOX.foreign.x"}, Storage: MemoryStorage, Replicas: replicas}
		var value any = cfg
		if operation == "restore" {
			value = JSApiStreamRestoreRequest{Config: cfg}
		}
		payload, err := json.Marshal(value)
		require_NoError(t, err)
		response, err := chained.Request(fmt.Sprintf(api, name), payload, 5*time.Second)
		require_NoError(t, err)
		var result ApiResponse
		require_NoError(t, json.Unmarshal(response.Data, &result))
		requireInboxCaptureError(t, result.Error)
	}
	info, err := inspect.StreamInfo("CHAIN_SAFE")
	require_NoError(t, err)
	require_Equal(t, info.Config.Subjects[0], "chain.safe")
	_, err = inspect.StreamInfo("CHAIN_BAD")
	require_Error(t, err)
}

func inboxCaptureRestoreAdmission(t *testing.T, s *Server, enabled bool, replicas int) {
	t.Helper()
	nc := natsConnect(t, s.ClientURL())
	defer nc.Close()
	for _, storage := range []StorageType{MemoryStorage, FileStorage} {
		t.Run(storage.String(), func(t *testing.T) {
			req := JSApiStreamRestoreRequest{Config: StreamConfig{
				Name: "RESTORE_" + storage.String(), Subjects: []string{"_INBOX.foreign." + storage.String()},
				Storage: storage, Replicas: replicas,
			}}
			payload, err := json.Marshal(&req)
			require_NoError(t, err)
			msg, err := nc.Request(fmt.Sprintf(JSApiStreamRestoreT, req.Config.Name), payload, 5*time.Second)
			require_NoError(t, err)
			var resp JSApiStreamRestoreResponse
			require_NoError(t, json.Unmarshal(msg.Data, &resp))
			if enabled {
				if resp.Error == nil || resp.Error.ErrCode != 10052 || !strings.Contains(resp.Error.Description, "stream configuration captures inbox subjects") {
					t.Fatalf("restore response = %s, want structured inbox-capture rejection", msg.Data)
				}
				require_Equal(t, resp.DeliverSubject, "")
				if js, cc := s.getJetStreamCluster(); cc != nil {
					js.mu.RLock()
					assigned := js.streamAssignmentOrInflight(globalAccountName, req.Config.Name) != nil
					js.mu.RUnlock()
					require_False(t, assigned)
				} else {
					_, err := s.GlobalAccount().lookupStream(req.Config.Name)
					require_Error(t, err)
				}
			} else {
				if resp.Error != nil || !IsValidLiteralSubject(resp.DeliverSubject) {
					t.Fatalf("restore response = %s, want transfer admission with policy off", msg.Data)
				}
				// Finish this intentionally empty transfer so it retains no worker.
				_, err := nc.Request(resp.DeliverSubject, nil, 5*time.Second)
				require_NoError(t, err)
			}
		})
	}
}

// inboxCaptureTransferSnapshot creates real native snapshots of both formats.
func inboxCaptureTransferSnapshot(t *testing.T, cfg StreamConfig, legacy bool) ([]byte, StreamState) {
	t.Helper()
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()
	cfg.Storage = FileStorage
	mset, err := s.GlobalAccount().addStream(&cfg)
	require_NoError(t, err)
	require_NoError(t, mset.store.StoreRawMsg(cfg.Subjects[0], nil, []byte("retained"), 1, time.Now().UnixNano(), 0, false))
	var snapshot *SnapshotResult
	if legacy {
		snapshot, err = mset.store.Snapshot(5*time.Second, false, false)
	} else {
		snapshot, err = mset.snapshot(5*time.Second, false, false)
	}
	require_NoError(t, err)
	data, err := io.ReadAll(snapshot.Reader)
	require_NoError(t, err)
	require_NoError(t, snapshot.Reader.Close())
	for err := range snapshot.errCh {
		require_NoError(t, err)
	}
	return data, snapshot.State
}

func inboxCaptureFinalTransfer(t *testing.T, s *Server, clustered bool) {
	t.Helper()
	for _, legacy := range []bool{true, false} {
		for _, scenario := range []struct {
			name            string
			exempt, capture bool
		}{
			{"ordinary-safe", false, false}, {"ordinary-capture", false, true}, {"trusted-capture", true, true},
		} {
			t.Run(fmt.Sprintf("legacy=%t/%s", legacy, scenario.name), func(t *testing.T) {
				cfg := StreamConfig{Name: fmt.Sprintf("FINAL_%t_%s", legacy, scenario.name), Subjects: []string{"safe." + scenario.name}, Storage: FileStorage}
				normalized, apiErr := s.checkStreamCfg(&cfg, s.GlobalAccount(), false)
				if apiErr != nil {
					t.Fatal(apiErr)
				}
				origin := &ClientInfo{Account: globalAccountName, InProcessUnrestricted: scenario.exempt}
				g, apiErr := s.newRestoreInboxGate(origin, &normalized)
				if apiErr != nil {
					t.Fatal(apiErr)
				}
				ci := origin
				if clustered {
					// Proposal/snapshot identity does not carry the origin marker.
					sa := &streamAssignment{Client: origin.forAssignmentSnap(), Config: &normalized, Restore: &StreamState{}, RestoreInboxExempt: g.exempt}
					require_False(t, sa.Client.InProcessUnrestricted)
					g = restoreInboxGateFromAssignment(sa)
					ci = sa.Client
					// The transfer must retain its immutable gate after assignment fields change.
					sa.Client, sa.Restore, sa.Config = nil, nil, nil
					sa.RestoreInboxExempt = false
				}
				final := normalized
				if scenario.capture {
					final.Subjects = []string{"_INBOX.foreign." + cfg.Name}
				}
				data, _ := inboxCaptureTransferSnapshot(t, final, legacy)
				nc := natsConnect(t, s.ClientURL())
				defer nc.Close()
				inbox := nats.NewInbox()
				initialResponse := make(chan []byte, 1)
				// Admission publishes from the SYSTEM client with echo disabled.
				// Receive on the system account's distinct ACCOUNT client.
				systemAccount := s.SystemAccount()
				require_True(t, systemAccount != nil)
				sub, err := systemAccount.subscribeInternal(inbox, func(_ *subscription, _ *client, _ *Account, _, _ string, payload []byte) {
					initialResponse <- append([]byte(nil), payload...)
				})
				require_NoError(t, err)
				defer systemAccount.unsubscribeInternal(sub)
				s.mu.RLock()
				publisher := s.sys.client
				s.mu.RUnlock()
				require_True(t, sub.client != publisher)
				require_Equal(t, sub.client.kind, ACCOUNT)
				require_Equal(t, publisher.kind, SYSTEM)
				// Prove the exact publisher/subscriber path before starting work.
				require_NoError(t, s.sendInternalAccountMsg(nil, inbox, "restore-reply-control"))
				select {
				case control := <-initialResponse:
					require_Equal(t, string(bytes.TrimSpace(control)), "restore-reply-control")
				case <-time.After(5 * time.Second):
					t.Fatal("distinct internal clients did not deliver reply control")
				}
				require_NoError(t, nc.Flush())
				done := s.processStreamRestore(ci, s.GlobalAccount(), &final, fmt.Sprintf(JSApiStreamRestoreT, final.Name), inbox, "", g)
				require_True(t, done != nil)
				var admissionPayload []byte
				select {
				case admissionPayload = <-initialResponse:
				case <-time.After(5 * time.Second):
					t.Fatal("restore admission response absent from system account")
				}
				var admission JSApiStreamRestoreResponse
				require_NoError(t, json.Unmarshal(admissionPayload, &admission))
				if admission.Error != nil {
					t.Fatalf("transfer admission: %s", admissionPayload)
				}
				require_True(t, IsValidLiteralSubject(admission.DeliverSubject))
				msg, err := nc.Request(admission.DeliverSubject, data, 5*time.Second)
				require_NoError(t, err)
				if len(msg.Data) == 0 {
					msg, err = nc.Request(admission.DeliverSubject, nil, 5*time.Second)
					require_NoError(t, err)
				}
				var result JSApiStreamCreateResponse
				require_NoError(t, json.Unmarshal(msg.Data, &result))
				var transferErr error
				select {
				case transferErr = <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("restore worker did not finish")
				}
				if scenario.capture && !scenario.exempt {
					if result.Error == nil || result.Error.ErrCode != 10052 || !strings.Contains(result.Error.Description, ErrJSStreamInboxCapture.Error()) {
						t.Fatalf("restore completion = %s, want structured final-config rejection", msg.Data)
					}
					require_True(t, IsNatsErr(transferErr, JSStreamInvalidConfigF))
					_, err := s.GlobalAccount().lookupStream(final.Name)
					require_Error(t, err)
				} else {
					if result.Error != nil {
						t.Fatalf("restore completion: %s", msg.Data)
					}
					require_NoError(t, transferErr)
					mset, err := s.GlobalAccount().lookupStream(final.Name)
					require_NoError(t, err)
					require_Equal(t, mset.state().Msgs, uint64(1))
					msg, err := mset.store.LoadMsg(1, nil)
					require_NoError(t, err)
					require_Equal(t, string(msg.msg), "retained")
					require_NoError(t, mset.delete())
				}
			})
		}
	}
}

const inboxCaptureRestoreClusterTemplate = `
    listen: 127.0.0.1:-1
    server_name: %s
    jetstream {store_dir: '%s'}
    cluster {name: %s, listen: 127.0.0.1:%d, routes: [%s]}
` + inboxCaptureOriginAccounts

func inboxCaptureLiveRestore(t *testing.T, origin, receiver *Server, clustered bool) {
	t.Helper()
	account, err := receiver.LookupAccount("APP")
	require_NoError(t, err)
	for _, legacy := range []bool{true, false} {
		for _, trusted := range []bool{false, true} {
			t.Run(fmt.Sprintf("legacy=%t/trusted=%t", legacy, trusted), func(t *testing.T) {
				name := fmt.Sprintf("LIVE_%t_%t", legacy, trusted)
				capture := "_INBOX.foreign." + name
				final := StreamConfig{Name: name, Subjects: []string{capture}, Storage: FileStorage, Replicas: 1}
				data, state := inboxCaptureTransferSnapshot(t, final, legacy)
				admitted := final
				admitted.Subjects = []string{"safe." + name}
				if clustered {
					admitted.Placement = &Placement{Tags: []string{"restore-" + receiver.Name()}}
				} else if !legacy {
					// V2 carries no stream config metadata. Standalone API admission
					// covers a declared capture; the immutable final-config matrix
					// separately exercises an adversarial post-admission change.
					admitted.Subjects = final.Subjects
				}
				nc := inboxCaptureOriginConnect(t, origin, "host", trusted)
				payload, err := json.Marshal(&JSApiStreamRestoreRequest{Config: admitted, State: state})
				require_NoError(t, err)
				msg, err := nc.Request(fmt.Sprintf(JSApiStreamRestoreT, name), payload, 5*time.Second)
				require_NoError(t, err)
				var response JSApiStreamRestoreResponse
				require_NoError(t, json.Unmarshal(msg.Data, &response))
				if !clustered && !legacy && !trusted {
					requireInboxCaptureError(t, response.Error)
					_, err := account.lookupStream(name)
					require_Error(t, err)
					return
				}
				if response.Error != nil {
					t.Fatalf("live restore admission: %s", msg.Data)
				}
				require_True(t, IsValidLiteralSubject(response.DeliverSubject))
				if clustered {
					js := receiver.getJetStream()
					js.mu.Lock()
					sa := js.streamAssignment("APP", name)
					if sa == nil {
						js.mu.Unlock()
						t.Fatal("restore assignment absent on selected stream receiver")
					}
					gotExempt := sa.RestoreInboxExempt
					restoring := sa.Restore != nil
					// Strip the real proposed assignment while its transfer waits.
					// Its saved exemption must survive independently of ClientInfo.
					sa.Client = sa.Client.forAssignmentSnap()
					marker := sa.Client.InProcessUnrestricted
					if !legacy {
						// V2 has no config entry, so expose a different final config
						// through the real assignment's retained transfer pointer.
						sa.Config.Subjects = final.Subjects
					}
					js.mu.Unlock()
					require_Equal(t, gotExempt, trusted)
					require_True(t, restoring)
					require_False(t, marker)
					require_True(t, !receiver.JetStreamIsLeader())
				}
				msg, err = nc.Request(response.DeliverSubject, data, 5*time.Second)
				require_NoError(t, err)
				if len(msg.Data) == 0 {
					msg, err = nc.Request(response.DeliverSubject, nil, 5*time.Second)
					require_NoError(t, err)
				}
				var result JSApiStreamCreateResponse
				require_NoError(t, json.Unmarshal(msg.Data, &result))
				if !trusted {
					requireInboxCaptureError(t, result.Error)
					_, err := account.lookupStream(name)
					require_Error(t, err)
					return
				}
				if result.Error != nil {
					t.Fatalf("trusted live restore completion: %s", msg.Data)
				}
				mset, err := account.lookupStream(name)
				require_NoError(t, err)
				require_Equal(t, mset.state().Msgs, uint64(1))
				retained, err := mset.store.LoadMsg(1, nil)
				require_NoError(t, err)
				require_Equal(t, retained.subj, capture)
				require_Equal(t, string(retained.msg), "retained")
			})
		}
	}
}

func inboxCaptureLegacyMetadataAge(t *testing.T, data []byte) []byte {
	t.Helper()
	reader := tar.NewReader(s2.NewReader(bytes.NewReader(data)))
	var output bytes.Buffer
	compressed := s2.NewWriter(&output)
	writer := tar.NewWriter(compressed)
	changed := false
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		require_NoError(t, err)
		payload, err := io.ReadAll(reader)
		require_NoError(t, err)
		if header.Name == JetStreamMetaFile {
			var metadata FileStreamInfo
			require_NoError(t, json.Unmarshal(payload, &metadata))
			// This field is ignored in favor of the admitted request by the
			// upstream restore path, but a fresh normalization rejects it.
			metadata.MaxAge = -time.Second
			payload, err = json.Marshal(&metadata)
			require_NoError(t, err)
			changed = true
		}
		header.Size = int64(len(payload))
		require_NoError(t, writer.WriteHeader(header))
		_, err = writer.Write(payload)
		require_NoError(t, err)
	}
	require_True(t, changed)
	require_NoError(t, writer.Close())
	require_NoError(t, compressed.Close())
	return output.Bytes()
}
