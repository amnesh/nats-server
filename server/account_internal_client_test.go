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

package server

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// removeAllServiceImportSubs clears the internal client of the account. Two
// goroutines then remove their internal subscriptions at the same time, as
// two deferred unsubscribeInternal calls do after a cleanup of the account.
// Each must unsubscribe through the client that the subscription records,
// and must not read a.ic. Run this test with -race.
func TestUnsubscribeInternalAfterAccountClear(t *testing.T) {
	s := RunServer(DefaultOptions())
	defer s.Shutdown()

	acc, err := s.RegisterAccount("A")
	if err != nil {
		t.Fatalf("register the account: %v", err)
	}
	noop := func(*subscription, *client, *Account, string, string, []byte) {}
	subs := make([]*subscription, 2)
	for i, subject := range []string{"internal.one", "internal.two"} {
		sub, err := acc.subscribeInternal(subject, noop)
		if err != nil {
			t.Fatalf("subscribe to %q: %v", subject, err)
		}
		subs[i] = sub
	}
	acc.removeAllServiceImportSubs()

	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, sub := range subs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			acc.unsubscribeInternal(sub)
		}()
	}
	close(start)
	wg.Wait()
}

// removeAllServiceImportSubs closes the internal client of the account, but
// a closed ACCOUNT client keeps its subscriptions in the account sublist.
// A deferred unsubscribeInternal after the clear must remove each
// subscription through the client that holds it.
func TestUnsubscribeInternalAfterAccountClearRemovesInterest(t *testing.T) {
	s := RunServer(DefaultOptions())
	defer s.Shutdown()

	acc, err := s.RegisterAccount("A")
	if err != nil {
		t.Fatalf("register the account: %v", err)
	}
	var stale atomic.Int32
	count := func(*subscription, *client, *Account, string, string, []byte) { stale.Add(1) }
	subjects := []string{"internal.one", "internal.two"}
	var subs []*subscription
	for _, subject := range subjects {
		sub, err := acc.subscribeInternal(subject, count)
		if err != nil {
			t.Fatalf("subscribe to %q: %v", subject, err)
		}
		subs = append(subs, sub)
	}
	acc.removeAllServiceImportSubs()
	for _, sub := range subs {
		acc.unsubscribeInternal(sub)
	}
	acc.unsubscribeInternal(nil) // A nil subscription must not panic.

	for _, subject := range subjects {
		if r := acc.sl.Match(subject); len(r.psubs)+len(r.qsubs) != 0 {
			t.Fatalf("the account sublist keeps %d interest for %q", len(r.psubs)+len(r.qsubs), subject)
		}
	}
	acc.mu.RLock()
	ic := acc.ic
	acc.mu.RUnlock()
	if ic != nil {
		t.Fatalf("unsubscribeInternal made a new internal client")
	}

	// One send loop delivers the messages in order, so the barrier message
	// arrives after each message to the two subjects.
	barrier := make(chan struct{}, 1)
	if _, err := acc.subscribeInternal("internal.barrier", func(*subscription, *client, *Account, string, string, []byte) {
		barrier <- struct{}{}
	}); err != nil {
		t.Fatalf("subscribe to the barrier: %v", err)
	}
	for _, subject := range append(subjects, "internal.barrier") {
		if err := s.sendInternalAccountMsgWithReply(acc, subject, _EMPTY_, nil, nil, true); err != nil {
			t.Fatalf("publish to %q: %v", subject, err)
		}
	}
	select {
	case <-barrier:
	case <-time.After(5 * time.Second):
		t.Fatalf("the barrier message did not arrive")
	}
	if n := stale.Load(); n != 0 {
		t.Fatalf("a removed subscription got %d messages", n)
	}
}
