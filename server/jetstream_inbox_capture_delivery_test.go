// Copyright 2026 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0

//go:build !skip_js_tests

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// No real consumer-create handler owns XAPI, so each forged response wins
// without a scheduling race against a genuine response.
func TestJetStreamInboxCaptureDeliveryResponse(t *testing.T) {
	for _, mirror := range []bool{true, false} {
		for _, imported := range []bool{false, true} {
			for _, got := range []string{"_INBOX.>", "_INBOX.foreign.x"} {
				t.Run(fmt.Sprintf("mirror=%t/imported=%t/%s", mirror, imported, got), func(t *testing.T) {
					conf := fmt.Sprintf(`port: -1
jetstream { store_dir: %q }
feature_flags { js_reject_inbox_capture: true }
accounts {
 A { jetstream: enabled; users: [{user: a, password: p}] }
 B { users: [{user: b, password: p}] }
}`, t.TempDir())
					if imported {
						conf = fmt.Sprintf(`port: -1
jetstream { store_dir: %q }
feature_flags { js_reject_inbox_capture: true }
accounts {
 A { jetstream: enabled; users: [{user: a, password: p}]; imports: [{service: {account: B, subject: "XAPI.>"}}] }
 B { users: [{user: b, password: p}]; exports: [{service: "XAPI.>", response_type: stream}] }
}`, t.TempDir())
					}
					path := createConfFile(t, []byte(conf))
					s, _ := RunServerWithConfig(path)
					defer s.Shutdown()
					nc, _ := jsClientConnect(t, s, nats.UserInfo("a", "p"))
					defer nc.Close()
					responder := nc
					if imported {
						responder = natsConnect(t, s.ClientURL(), nats.UserInfo("b", "p"))
						defer responder.Close()
					}
					var requests atomic.Int64
					_, err := responder.Subscribe("XAPI.CONSUMER.CREATE.>", func(m *nats.Msg) {
						var req CreateConsumerRequest
						if json.Unmarshal(m.Data, &req) != nil {
							return
						}
						requests.Add(1)
						// The request comes from a server sync token, under the declared prefix.
						parts := strings.Split(req.Config.DeliverSubject, ".")
						kind := "S"
						if mirror {
							kind = "M"
						}
						if len(parts) != 3 || parts[0] != "delivery" || parts[1] != kind || len(parts[2]) != replySuffixLen {
							t.Errorf("unexpected requested delivery subject %q", req.Config.DeliverSubject)
						} else {
							for _, token := range parts[2] {
								if !strings.ContainsRune(digits, token) {
									t.Errorf("invalid server sync token %q", parts[2])
								}
							}
						}
						req.Config.DeliverSubject = got
						body, _ := json.Marshal(JSApiConsumerCreateResponse{ConsumerInfo: &ConsumerInfo{Name: req.Config.Name, Config: &req.Config}})
						_ = m.Respond(body)
					})
					require_NoError(t, err)
					require_NoError(t, responder.Flush())
					src := &StreamSource{Name: "ORIGIN", External: &ExternalStream{ApiPrefix: "XAPI", DeliverPrefix: "delivery"}}
					cfg := &StreamConfig{Name: "DEST", Storage: MemoryStorage}
					if mirror {
						cfg.Mirror = src
					} else {
						cfg.Sources = []*StreamSource{src}
					}
					addStream(t, nc, cfg)
					checkFor(t, 15*time.Second, 50*time.Millisecond, func() error {
						si, err := jsPoisonStreamInfo(nc, "DEST")
						if err != nil {
							return err
						}
						var apiErr *ApiError
						if mirror && si.Mirror != nil {
							apiErr = si.Mirror.Error
						}
						if !mirror && len(si.Sources) == 1 {
							apiErr = si.Sources[0].Error
						}
						wantCode := uint16(JSSourceConsumerSetupFailedErrF)
						if mirror {
							wantCode = uint16(JSMirrorConsumerSetupFailedErrF)
						}
						if apiErr == nil || apiErr.ErrCode != wantCode || !strings.Contains(apiErr.Description, "consumer create response changed the delivery subject") {
							return fmt.Errorf("missing setup failure: %+v", apiErr)
						}
						if requests.Load() < 2 {
							return fmt.Errorf("setup did not retry")
						}
						return nil
					})
					acc, err := s.LookupAccount("A")
					require_NoError(t, err)
					var subs []*subscription
					acc.sl.All(&subs)
					for _, sub := range subs {
						if sub.client != nil && sub.client.kind == JETSTREAM && SubjectsCollide(string(sub.subject), "_INBOX.foreign.x") {
							t.Fatalf("forged response installed inbox interest %q", sub.subject)
						}
					}
				})
			}
		}
	}
}

func TestJetStreamInboxCaptureDeliveryNormal(t *testing.T) {
	opts := DefaultTestOptions
	opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
	opts.FeatureFlags = map[string]bool{"js_reject_inbox_capture": true}
	s := RunServer(&opts)
	defer func() { s.Shutdown() }()
	for pass := 0; pass < 2; pass++ {
		nc, js := jsClientConnect(t, s)
		if pass == 0 {
			_, err := js.AddStream(&nats.StreamConfig{Name: "ORIGIN", Subjects: []string{"orders"}})
			require_NoError(t, err)
			_, err = js.AddStream(&nats.StreamConfig{Name: "MIRROR", Mirror: &nats.StreamSource{Name: "ORIGIN"}})
			require_NoError(t, err)
			_, err = js.AddStream(&nats.StreamConfig{Name: "SOURCE", Sources: []*nats.StreamSource{{Name: "ORIGIN"}}})
			require_NoError(t, err)
		}
		_, err := js.Publish("orders", []byte(fmt.Sprintf("payload-%d", pass)))
		require_NoError(t, err)
		for _, name := range []string{"MIRROR", "SOURCE"} {
			checkFor(t, 10*time.Second, 25*time.Millisecond, func() error {
				si, err := js.StreamInfo(name)
				if err != nil {
					return err
				}
				if si.State.Msgs != uint64(pass+1) {
					return fmt.Errorf("%s: got %d messages", name, si.State.Msgs)
				}
				return nil
			})
			dest, err := s.globalAccount().lookupStream(name)
			require_NoError(t, err)
			origin, err := s.globalAccount().lookupStream("ORIGIN")
			require_NoError(t, err)
			inboxCaptureDeliveryEqual(t, dest, origin)
			msg, err := js.GetMsg(name, uint64(pass+1))
			require_NoError(t, err)
			require_Equal(t, string(msg.Data), fmt.Sprintf("payload-%d", pass))
		}
		nc.Close()
		if pass == 0 {
			s.Shutdown()
			s = RunServer(&opts)
		}
	}
}

func TestJetStreamInboxCaptureDeliveryExternal(t *testing.T) {
	for _, mode := range []string{"ordinary", "trusted-prefix", "trusted-durable"} {
		t.Run(mode, func(t *testing.T) {
			prefix := "delivery"
			if mode != "ordinary" {
				prefix = "_INBOX.trusted"
			}
			conf := createConfFile(t, []byte(fmt.Sprintf(`port: -1
jetstream { store_dir: %q }
feature_flags { js_reject_inbox_capture: true }
accounts {
 A { jetstream: enabled; users: [{user: a, password: p}]; exports: [
  {service: "$JS.API.>", response_type: stream}, {service: "$JS.FC.>"}, {stream: "%s.>"}
 ] }
 B { jetstream: enabled; users: [{user: b, password: p}]; imports: [
  {service: {account: A, subject: "$JS.API.>"}, to: "XAPI.>"},
  {service: {account: A, subject: "$JS.FC.>"}}, {stream: {account: A, subject: "%s.>"}}
 ] }
}`, t.TempDir(), prefix, prefix)))
			s, _ := RunServerWithConfig(conf)
			defer func() { s.Shutdown() }()
			for pass := 0; pass < 2; pass++ {
				ac, ajs := jsClientConnect(t, s, nats.UserInfo("a", "p"))
				options := []nats.Option{nats.UserInfo("b", "p")}
				if mode != "ordinary" {
					options = append(options, nats.InProcessServer(s))
				}
				bc := natsConnect(t, s.ClientURL(), options...)
				bjs, err := bc.JetStream()
				require_NoError(t, err)
				if pass == 0 {
					_, err = ajs.AddStream(&nats.StreamConfig{Name: "ORIGIN", Subjects: []string{"orders"}})
					require_NoError(t, err)
					for _, name := range []string{"MIRROR", "SOURCE"} {
						src := &StreamSource{Name: "ORIGIN", External: &ExternalStream{ApiPrefix: "XAPI", DeliverPrefix: prefix}}
						if mode == "trusted-durable" {
							deliver := prefix + "." + name
							_, err = jsConsumerCreate(t, ac, "ORIGIN", ConsumerConfig{Durable: name, DeliverSubject: deliver, AckPolicy: AckFlowControl, Heartbeat: time.Second}, false)
							require_NoError(t, err)
							src.Consumer = &StreamConsumerSource{Name: name, DeliverSubject: deliver}
						}
						cfg := &StreamConfig{Name: name, Storage: FileStorage}
						if name == "MIRROR" {
							cfg.Mirror = src
						} else {
							cfg.Sources = []*StreamSource{src}
						}
						addStream(t, bc, cfg)
					}
				}
				_, err = ajs.Publish("orders", []byte(fmt.Sprintf("external-%d", pass)))
				require_NoError(t, err)
				aa, err := s.LookupAccount("A")
				require_NoError(t, err)
				ba, err := s.LookupAccount("B")
				require_NoError(t, err)
				origin, err := aa.lookupStream("ORIGIN")
				require_NoError(t, err)
				for _, name := range []string{"MIRROR", "SOURCE"} {
					checkFor(t, 10*time.Second, 25*time.Millisecond, func() error {
						si, err := bjs.StreamInfo(name)
						if err != nil {
							return err
						}
						if si.State.Msgs != uint64(pass+1) {
							return fmt.Errorf("%s: got %d messages", name, si.State.Msgs)
						}
						return nil
					})
					dest, err := ba.lookupStream(name)
					require_NoError(t, err)
					inboxCaptureDeliveryEqual(t, dest, origin)
					msg, err := bjs.GetMsg(name, uint64(pass+1))
					require_NoError(t, err)
					require_Equal(t, string(msg.Data), fmt.Sprintf("external-%d", pass))
				}
				ac.Close()
				bc.Close()
				if pass == 0 {
					s.Shutdown()
					s, _ = RunServerWithConfig(conf)
				}
			}
		})
	}
}

func TestJetStreamInboxCaptureDeliveryGuard(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		s := &Server{}
		s.js.Store(&jetStream{rejectInboxCapture: enabled})
		for _, got := range []string{"delivery.token", "_INBOX.>", "_INBOX.foreign.x", ""} {
			err := s.checkSourceDeliverSubject("delivery.token", got)
			if enabled && got != "delivery.token" {
				if !errors.Is(err, ErrJSSourceDeliverSubjectChanged) {
					t.Fatalf("expected wrapped sentinel, got %v", err)
				}
			} else {
				require_NoError(t, err)
			}
		}
	}
}

func TestJetStreamInboxCaptureDeliveryOwnInboxConsumer(t *testing.T) {
	opts := DefaultTestOptions
	opts.Port, opts.JetStream, opts.StoreDir = -1, true, t.TempDir()
	opts.FeatureFlags = map[string]bool{"js_reject_inbox_capture": true}
	s := RunServer(&opts)
	defer s.Shutdown()
	nc, js := jsClientConnect(t, s)
	defer nc.Close()
	_, err := js.AddStream(&nats.StreamConfig{Name: "ORDERS", Subjects: []string{"orders"}})
	require_NoError(t, err)
	inbox := nats.NewInbox()
	sub, err := nc.SubscribeSync(inbox)
	require_NoError(t, err)
	_, err = js.AddConsumer("ORDERS", &nats.ConsumerConfig{DeliverSubject: inbox, AckPolicy: nats.AckNonePolicy})
	require_NoError(t, err)
	require_NoError(t, nc.Flush())
	_, err = js.Publish("orders", []byte("own inbox"))
	require_NoError(t, err)
	msg, err := sub.NextMsg(5 * time.Second)
	require_NoError(t, err)
	require_Equal(t, string(msg.Data), "own inbox")
}
