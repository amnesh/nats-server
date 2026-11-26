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
	"testing"
)

// removeAllServiceImportSubs clears the internal client of the account. Two
// goroutines then remove their internal subscriptions at the same time, as
// two deferred unsubscribeInternal calls do after a cleanup of the account.
// Each must read the internal client with the account lock. Run this test
// with -race.
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
