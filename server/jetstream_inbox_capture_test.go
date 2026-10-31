// Copyright 2026 The NATS Authors
// Licensed under the Apache License, Version 2.0.

//go:build !skip_js_tests

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestJetStreamInboxCaptureAdmission(t *testing.T) {
	inboxCaptureAdmission(t, false)
}

func TestJetStreamInboxCapturePredicate(t *testing.T) {
	for _, subject := range []string{"_INBOX.>", "_INBOX.*", "_INBOX.ukey.x", "*.>", "*.*", ">"} {
		t.Run(subject, func(t *testing.T) {
			field, got, found := streamInboxCapture(&StreamConfig{Subjects: []string{subject}})
			if !found || got != subject || field != "subjects[0]" {
				t.Fatalf("capture = %q %q %t", field, got, found)
			}
		})
	}
	for _, subject := range []string{"_INBOX", "*", "_INBOXES.>", "inbox.>", "ORDERS"} {
		if field, got, found := streamInboxCapture(&StreamConfig{Subjects: []string{subject}}); found {
			t.Fatalf("safe %q captures as %s %q", subject, field, got)
		}
	}
	tests := []struct {
		cfg            StreamConfig
		field, subject string
	}{
		{StreamConfig{Subjects: []string{"orders.>", "_INBOX.a.>"}}, "subjects[1]", "_INBOX.a.>"},
		{StreamConfig{Mirror: &StreamSource{External: &ExternalStream{DeliverPrefix: "_INBOX.v"}}}, "mirror.external.deliver", "_INBOX.v.>"},
		{StreamConfig{Mirror: &StreamSource{Consumer: &StreamConsumerSource{DeliverSubject: "_INBOX.v.1"}}}, "mirror.consumer.deliver_subject", "_INBOX.v.1"},
		{StreamConfig{Sources: []*StreamSource{{Name: "ONE"}, {External: &ExternalStream{DeliverPrefix: "_INBOX.v"}}}}, "sources[1].external.deliver", "_INBOX.v.>"},
		{StreamConfig{Sources: []*StreamSource{{Name: "ONE"}, {Consumer: &StreamConsumerSource{DeliverSubject: "_INBOX.v.1"}}}}, "sources[1].consumer.deliver_subject", "_INBOX.v.1"},
	}
	for _, test := range tests {
		field, subject, found := streamInboxCapture(&test.cfg)
		if !found || field != test.field || subject != test.subject {
			t.Fatalf("capture = %s %q %t, want %s %q", field, subject, found, test.field, test.subject)
		}
	}
}

func TestJetStreamInboxCaptureRestoreGate(t *testing.T) {
	opts := DefaultTestOptions
	opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
	opts.FeatureFlags = map[string]bool{FeatureFlagJsRejectInboxCapture: true}
	s := RunServer(&opts)
	defer s.Shutdown()
	cfg := &StreamConfig{Name: "GATE", Subjects: []string{"safe"}, Storage: MemoryStorage,
		Mirror:  &StreamSource{Name: "ORIGIN", External: &ExternalStream{DeliverPrefix: "delivery"}, Consumer: &StreamConsumerSource{DeliverSubject: "delivery.one"}},
		Sources: []*StreamSource{{Name: "OTHER", External: &ExternalStream{DeliverPrefix: "other"}, Consumer: &StreamConsumerSource{DeliverSubject: "other.one"}}}}
	baseline, err := json.Marshal(cfg)
	require_NoError(t, err)
	var expected StreamConfig
	require_NoError(t, json.Unmarshal(baseline, &expected))
	g, apiErr := s.newRestoreInboxGate(nil, cfg)
	if apiErr != nil {
		t.Fatal(apiErr)
	}
	cfg.Subjects[0] = "_INBOX.foreign.x"
	cfg.Mirror.External.DeliverPrefix = "_INBOX.mirror"
	cfg.Mirror.Consumer.DeliverSubject = "_INBOX.mirror.x"
	cfg.Sources[0].External.DeliverPrefix = "_INBOX.source"
	cfg.Sources[0].Consumer.DeliverSubject = "_INBOX.source.x"
	if !reflect.DeepEqual(g.admitted, &expected) {
		t.Fatal("admitted config changed after caller mutation")
	}
	err = s.getJetStream().checkRestoredInboxCapture(g, cfg)
	ae, ok := err.(*ApiError)
	if !ok {
		t.Fatalf("restore error %v is not structured", err)
	}
	requireInboxCaptureError(t, ae)
	trustedCI := &ClientInfo{InProcessUnrestricted: true}
	trusted, apiErr := s.newRestoreInboxGate(trustedCI, &expected)
	if apiErr != nil {
		t.Fatal(apiErr)
	}
	trustedCI.InProcessUnrestricted, trustedCI.Service = false, "changed"
	require_NoError(t, s.getJetStream().checkRestoredInboxCapture(trusted, cfg))
	// The final scan must continue past an already admitted capture field.
	admitted := &StreamConfig{Subjects: []string{"_INBOX.first.x"}}
	gate := restoreInboxGate{admitted: admitted}
	final := &StreamConfig{Subjects: []string{"_INBOX.first.x", "_INBOX.new.x"}}
	err = s.getJetStream().checkRestoredInboxCapture(gate, final)
	if err == nil || !strings.Contains(err.Error(), "_INBOX.new.x") {
		t.Fatalf("new capture not rejected: %v", err)
	}
	require_NoError(t, s.checkSourceDeliverSubject("delivery.one", "delivery.one"))
	if !errors.Is(s.checkSourceDeliverSubject("delivery.one", "_INBOX.foreign.x"), ErrJSSourceDeliverSubjectChanged) {
		t.Fatal("delivery mismatch did not wrap sentinel")
	}
	// A chained service cannot use a proof copied from an earlier system import.
	if s.inboxCaptureExempt(&ClientInfo{InProcessUnrestricted: true, Service: "chained"}) {
		t.Fatal("chained service origin is exempt")
	}
}

func TestJetStreamInboxCaptureNormalControls(t *testing.T) {
	opts := DefaultTestOptions
	opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
	opts.FeatureFlags = map[string]bool{FeatureFlagJsRejectInboxCapture: true}
	s := RunServer(&opts)
	defer s.Shutdown()
	normalized, apiErr := s.checkStreamCfg(&StreamConfig{Name: "DEFAULT", Storage: MemoryStorage}, s.GlobalAccount(), false)
	if apiErr != nil {
		t.Fatal(apiErr)
	}
	require_Equal(t, len(normalized.Subjects), 1)
	require_Equal(t, normalized.Subjects[0], "DEFAULT")
	if _, _, found := streamInboxCapture(&normalized); found {
		t.Fatal("stream-name default captures inbox")
	}
	nc, js := jsClientConnect(t, s)
	defer nc.Close()
	_, err := js.AddStream(&nats.StreamConfig{Name: "DEFAULT", Storage: nats.MemoryStorage})
	require_NoError(t, err)
	cfg := &nats.StreamConfig{Name: "DEFAULT", Subjects: []string{"orders"}, Storage: nats.MemoryStorage, Description: "updated"}
	_, err = js.UpdateStream(cfg)
	require_NoError(t, err)
	inbox := nats.NewInbox()
	sub, err := nc.SubscribeSync(inbox)
	require_NoError(t, err)
	_, err = js.AddConsumer("DEFAULT", &nats.ConsumerConfig{Durable: "OWN", DeliverSubject: inbox, AckPolicy: nats.AckNonePolicy})
	require_NoError(t, err)
	_, err = js.Publish("orders", []byte("own-inbox"))
	require_NoError(t, err)
	msg, err := sub.NextMsg(5 * time.Second)
	require_NoError(t, err)
	require_Equal(t, string(msg.Data), "own-inbox")
	kv, err := js.CreateKeyValue(&nats.KeyValueConfig{Bucket: "CONTROL"})
	require_NoError(t, err)
	_, err = kv.PutString("one", "kv")
	require_NoError(t, err)
	entry, err := kv.Get("one")
	require_NoError(t, err)
	require_Equal(t, string(entry.Value()), "kv")
	object, err := js.CreateObjectStore(&nats.ObjectStoreConfig{Bucket: "CONTROL"})
	require_NoError(t, err)
	_, err = object.PutString("one", "object")
	require_NoError(t, err)
	value, err := object.GetString("one")
	require_NoError(t, err)
	require_Equal(t, value, "object")
}

func TestJetStreamInboxCaptureTrustedReplay(t *testing.T) {
	opts := DefaultTestOptions
	opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
	s := RunServer(&opts)
	defer func() { s.Shutdown(); s.WaitForShutdown() }()
	nc, js := jsClientConnect(t, s)
	_, err := js.AddStream(&nats.StreamConfig{Name: "HISTORY", Subjects: []string{"_INBOX.foreign.history"}, Storage: nats.FileStorage})
	require_NoError(t, err)
	_, err = js.Publish("_INBOX.foreign.history", []byte("retained history"))
	require_NoError(t, err)
	nc.Close()
	s.Shutdown()
	s.WaitForShutdown()
	opts.FeatureFlags = map[string]bool{FeatureFlagJsRejectInboxCapture: true}
	s = RunServer(&opts)
	nc, js = jsClientConnect(t, s)
	defer nc.Close()
	_, err = js.AddStream(&nats.StreamConfig{Name: "REPLAY", Storage: nats.FileStorage, Sources: []*nats.StreamSource{{Name: "HISTORY"}}})
	require_NoError(t, err)
	checkFor(t, 5*time.Second, 10*time.Millisecond, func() error {
		info, err := js.StreamInfo("REPLAY")
		if err != nil {
			return err
		}
		if info.State.Msgs != 1 {
			return fmt.Errorf("replay has %d messages, want 1", info.State.Msgs)
		}
		return nil
	})
	retained, err := js.GetLastMsg("REPLAY", "_INBOX.foreign.history")
	require_NoError(t, err)
	require_Equal(t, string(retained.Data), "retained history")
}

func TestJetStreamInboxCaptureDeclaredDeliveryAdmission(t *testing.T) {
	opts := DefaultTestOptions
	opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
	opts.FeatureFlags = map[string]bool{FeatureFlagJsRejectInboxCapture: true}
	s := RunServer(&opts)
	defer s.Shutdown()
	nc, js := jsClientConnect(t, s)
	defer nc.Close()
	for _, mirror := range []bool{false, true} {
		for _, prefix := range []bool{false, true} {
			t.Run(fmt.Sprintf("mirror=%t/prefix=%t", mirror, prefix), func(t *testing.T) {
				source := &StreamSource{Name: "ORIGIN"}
				if prefix {
					source.External = &ExternalStream{ApiPrefix: "XAPI", DeliverPrefix: "_INBOX.foreign"}
				} else {
					source.Consumer = &StreamConsumerSource{Name: "DURABLE", DeliverSubject: "_INBOX.foreign.x"}
				}
				cfg := StreamConfig{Name: "DECLARED", Storage: MemoryStorage}
				if mirror {
					cfg.Mirror = source
				} else {
					cfg.Sources = []*StreamSource{source}
				}
				payload, err := json.Marshal(&cfg)
				require_NoError(t, err)
				msg, err := nc.Request(fmt.Sprintf(JSApiStreamCreateT, cfg.Name), payload, 5*time.Second)
				require_NoError(t, err)
				var response ApiResponse
				require_NoError(t, json.Unmarshal(msg.Data, &response))
				requireInboxCaptureError(t, response.Error)
				_, err = js.StreamInfo(cfg.Name)
				require_Error(t, err)
				payload, err = json.Marshal(&JSApiStreamRestoreRequest{Config: cfg})
				require_NoError(t, err)
				msg, err = nc.Request(fmt.Sprintf(JSApiStreamRestoreT, cfg.Name), payload, 5*time.Second)
				require_NoError(t, err)
				response = ApiResponse{}
				require_NoError(t, json.Unmarshal(msg.Data, &response))
				requireInboxCaptureError(t, response.Error)
			})
		}
	}
}
