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
	"time"
)

// Upstream runs checkInternalSyncConsumers on the readloop of every leafnode
// connect and on every INFO that a solicited leafnode receives. It locks every
// sourcing or mirroring stream of the account and kicks their disconnected
// sources, so a connect costs O(sourcing streams + their sources). With
// leafnodes { sync_consumers_check_interval: <duration> }, the check runs on
// its own goroutine, at most once per interval for each account. The first
// trigger after an idle period runs the check at once. A trigger during a check
// or during the wait after it causes one more check after the wait, so every
// trigger is followed by a check that starts after it: at most one interval
// after the check that is running ends. Shutdown drops pending checks. When a
// reload sets the interval to 0, new triggers check synchronously as upstream,
// while a running goroutine finishes its pending check; upstream also runs
// checks of different connections at the same time.

// syncCheckCoalescer coalesces the checks of one account.
type syncCheckCoalescer struct {
	mu      sync.Mutex
	running bool // A goroutine runs checks.
	pending bool // A trigger arrived since the current check started.
}

// trigger runs fn now on a new goroutine if none is running, or marks that one
// more run is needed. After each run, the goroutine waits interval() and runs
// fn again if a trigger arrived. No lock may be held by the caller of fn.
func (q *syncCheckCoalescer) trigger(s *Server, interval func() time.Duration, fn func()) {
	q.mu.Lock()
	if q.running {
		q.pending = true
		q.mu.Unlock()
		return
	}
	q.running = true
	q.mu.Unlock()

	if !s.startGoRoutine(func() {
		defer s.grWG.Done()
		q.loop(s, interval, fn)
	}) {
		// The server is shutting down.
		q.stop()
	}
}

func (q *syncCheckCoalescer) loop(s *Server, interval func() time.Duration, fn func()) {
	for {
		fn()
		if !waitSyncCheckInterval(s, interval) {
			q.stop()
			return
		}
		q.mu.Lock()
		if !q.pending {
			q.running = false
			q.mu.Unlock()
			return
		}
		q.pending = false
		q.mu.Unlock()
	}
}

// syncCheckWaitStep bounds how long a wait uses an old interval after a config
// reload changes it.
const syncCheckWaitStep = 100 * time.Millisecond

// waitSyncCheckInterval waits until interval() has passed since the call. It
// reads interval() again at least every syncCheckWaitStep, so a reload that
// shortens or disables the interval applies to a wait in progress. It returns
// false if the server shuts down.
func waitSyncCheckInterval(s *Server, interval func() time.Duration) bool {
	start := time.Now()
	for {
		rem := interval() - time.Since(start)
		if rem <= 0 {
			return true
		}
		if rem > syncCheckWaitStep {
			rem = syncCheckWaitStep
		}
		t := time.NewTimer(rem)
		select {
		case <-t.C:
		case <-s.quitCh:
			t.Stop()
			return false
		}
	}
}

func (q *syncCheckCoalescer) stop() {
	q.mu.Lock()
	q.running, q.pending = false, false
	q.mu.Unlock()
}

// scheduleInternalSyncConsumersCheck replaces the direct calls of
// checkInternalSyncConsumers after a leafnode connect or INFO. Without the
// option it is the upstream call. No lock may be held.
func (s *Server) scheduleInternalSyncConsumersCheck(acc *Account) {
	interval := func() time.Duration { return s.getOpts().LeafNode.SyncConsumersCheckInterval }
	if acc == nil || interval() <= 0 {
		s.checkInternalSyncConsumers(acc)
		return
	}
	acc.syncCheck.trigger(s, interval, func() { s.checkInternalSyncConsumers(acc) })
}
