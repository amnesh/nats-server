// Copyright 2026 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build !skip_js_tests

package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestJetStreamInboxCaptureSourceRetryProgress(t *testing.T) {
	opts := DefaultTestOptions
	opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
	opts.FeatureFlags = map[string]bool{"js_reject_inbox_capture": true}
	s := RunServer(&opts)
	defer s.Shutdown()
	nc, js := jsClientConnect(t, s)
	defer nc.Close()
	_, err := js.AddStream(&nats.StreamConfig{Name: "ORIGIN", Subjects: []string{"orders"}, Storage: nats.MemoryStorage})
	require_NoError(t, err)

	proxy := natsConnect(t, s.ClientURL())
	defer proxy.Close()
	var allowValid atomic.Bool
	var requests atomic.Int64
	proxyErrors := make(chan error, 1)
	reportProxyError := func(err error) {
		select {
		case proxyErrors <- err:
		default:
		}
	}
	_, err = proxy.Subscribe("XAPI.CONSUMER.CREATE.>", func(m *nats.Msg) {
		var req CreateConsumerRequest
		if err := json.Unmarshal(m.Data, &req); err != nil {
			reportProxyError(err)
			return
		}
		requests.Add(1)
		var body []byte
		if !allowValid.Load() {
			req.Config.DeliverSubject = "_INBOX.foreign.x"
			response := JSApiConsumerCreateResponse{ConsumerInfo: &ConsumerInfo{
				Name: req.Config.Name, Config: &req.Config,
			}}
			response.Delivered.Stream = 100
			body, _ = json.Marshal(response)
		} else {
			// Forward unchanged to a real consumer-create handler. Neither reply
			// forwards identity headers, so stream recreation cannot reset progress.
			subject := strings.Replace(m.Subject, "XAPI", JSApiPrefix, 1)
			response, err := nc.Request(subject, m.Data, time.Second)
			if err != nil {
				reportProxyError(err)
				return
			}
			var created JSApiConsumerCreateResponse
			if err := json.Unmarshal(response.Data, &created); err != nil {
				reportProxyError(err)
				return
			}
			if created.Error != nil || created.ConsumerInfo == nil || created.Config == nil {
				reportProxyError(fmt.Errorf("real consumer create failed: %s", response.Data))
				return
			}
			if created.Config.DeliverSubject != req.Config.DeliverSubject {
				reportProxyError(fmt.Errorf("real consumer changed delivery subject: %s", response.Data))
				return
			}
			if created.Delivered.Stream != 0 {
				reportProxyError(fmt.Errorf("real empty source returned nonzero progress: %s", response.Data))
				return
			}
			t.Logf("valid source retry: policy=%v start_sequence=%d delivered_stream=%d", req.Config.DeliverPolicy, req.Config.OptStartSeq, created.Delivered.Stream)
			body = response.Data
		}
		if err := m.Respond(body); err != nil {
			reportProxyError(err)
		}
	})
	require_NoError(t, err)
	require_NoError(t, proxy.Flush())
	addStream(t, nc, &StreamConfig{
		Name: "DEST", Storage: MemoryStorage,
		Sources: []*StreamSource{{Name: "ORIGIN", External: &ExternalStream{ApiPrefix: "XAPI", DeliverPrefix: "delivery"}}},
	})
	checkFor(t, 5*time.Second, 25*time.Millisecond, func() error {
		select {
		case err := <-proxyErrors:
			return err
		default:
		}
		si, err := jsPoisonStreamInfo(nc, "DEST")
		if err != nil {
			return err
		}
		if len(si.Sources) != 1 || si.Sources[0].Error == nil {
			return fmt.Errorf("missing rejected-response source setup failure")
		}
		setupErr := si.Sources[0].Error
		if setupErr.ErrCode != uint16(JSSourceConsumerSetupFailedErrF) || !strings.Contains(setupErr.Description, ErrJSSourceDeliverSubjectChanged.Error()) {
			return fmt.Errorf("unexpected source setup failure: %+v", setupErr)
		}
		return nil
	})
	var subs []*subscription
	s.globalAccount().sl.All(&subs)
	for _, sub := range subs {
		if sub.client != nil && sub.client.kind == JETSTREAM && SubjectsCollide(string(sub.subject), "_INBOX.foreign.x") {
			t.Fatalf("rejected response installed inbox interest %q", sub.subject)
		}
	}

	allowValid.Store(true)
	origin, err := s.globalAccount().lookupStream("ORIGIN")
	require_NoError(t, err)
	destination, err := s.globalAccount().lookupStream("DEST")
	require_NoError(t, err)
	// A rejected setup uses the ordinary source retry backoff.
	checkFor(t, 40*time.Second, 25*time.Millisecond, func() error {
		select {
		case err := <-proxyErrors:
			return err
		default:
		}
		return inboxCaptureDeliveryEqualOnce(destination, origin)
	})
	if requests.Load() < 2 {
		t.Fatalf("source setup did not retry: %d requests", requests.Load())
	}
	for i := 1; i <= 3; i++ {
		ack, err := js.Publish("orders", []byte(fmt.Sprintf("genuine-%d", i)))
		require_NoError(t, err)
		require_Equal(t, ack.Sequence, uint64(i))
	}
	checkFor(t, 10*time.Second, 25*time.Millisecond, func() error {
		si, err := js.StreamInfo("DEST")
		if err != nil {
			return err
		}
		if si.State.Msgs != 3 {
			return fmt.Errorf("source retry lost genuine payloads: got %d messages, want 3", si.State.Msgs)
		}
		return nil
	})
	for i := 1; i <= 3; i++ {
		msg, err := js.GetMsg("DEST", uint64(i))
		require_NoError(t, err)
		require_Equal(t, msg.Subject, "orders")
		require_Equal(t, string(msg.Data), fmt.Sprintf("genuine-%d", i))
	}
	inboxCaptureDeliveryEqual(t, destination, origin)
}
