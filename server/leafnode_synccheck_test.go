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
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLeafNodeSyncCheckIntervalConfig(t *testing.T) {
	for _, tc := range []struct {
		conf string
		want time.Duration
		err  string
	}{
		{conf: `leafnodes { listen: "127.0.0.1:-1" }`, want: 0},
		{conf: `leafnodes { listen: "127.0.0.1:-1", sync_consumers_check_interval: "250ms" }`, want: 250 * time.Millisecond},
		{conf: `leafnodes { listen: "127.0.0.1:-1", sync_consumers_check_interval: "0s" }`, want: 0},
		{conf: `leafnodes { listen: "127.0.0.1:-1", sync_consumers_check_interval: "-1s" }`, err: "sync_consumers_check_interval"},
		{conf: `leafnodes { listen: "127.0.0.1:-1", sync_consumers_check_interval: 2 }`, want: 2 * time.Second},
		{conf: `leafnodes { listen: "127.0.0.1:-1", sync_consumers_check_interval: -1 }`, err: "sync_consumers_check_interval"},
		// Would wrap to a positive duration if converted first.
		{conf: `leafnodes { listen: "127.0.0.1:-1", sync_consumers_check_interval: -18446744073 }`, err: "sync_consumers_check_interval"},
		{conf: `leafnodes { listen: "127.0.0.1:-1", sync_consumers_check_interval: 18446744073 }`, err: "sync_consumers_check_interval"},
	} {
		opts, err := ProcessConfigFile(createConfFile(t, []byte(tc.conf)))
		if tc.err != _EMPTY_ {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("%s: expected error with %q, got %v", tc.conf, tc.err, err)
			}
			continue
		}
		require_NoError(t, err)
		require_Equal(t, opts.LeafNode.SyncConsumersCheckInterval, tc.want)
	}
}

func TestLeafNodeSyncCheckIntervalReload(t *testing.T) {
	tmpl := `
		listen: "127.0.0.1:-1"
		leafnodes { listen: "127.0.0.1:-1" %s }
	`
	conf := createConfFile(t, []byte(fmt.Sprintf(tmpl, _EMPTY_)))
	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()
	require_Equal(t, s.getOpts().LeafNode.SyncConsumersCheckInterval, 0)

	reloadUpdateConfig(t, s, conf, fmt.Sprintf(tmpl, `, sync_consumers_check_interval: "250ms"`))
	require_Equal(t, s.getOpts().LeafNode.SyncConsumersCheckInterval, 250*time.Millisecond)

	reloadUpdateConfig(t, s, conf, fmt.Sprintf(tmpl, _EMPTY_))
	require_Equal(t, s.getOpts().LeafNode.SyncConsumersCheckInterval, 0)
}

// Many triggers run few checks, every trigger is followed by a check that
// starts after it, and no goroutine stays after the burst or after shutdown.
func TestLeafNodeSyncCheckCoalescer(t *testing.T) {
	s := RunServer(DefaultOptions())
	defer s.Shutdown()

	const interval = 50 * time.Millisecond
	var (
		q      syncCheckCoalescer
		runs   atomic.Int64
		mu     sync.Mutex
		starts []time.Time
	)
	run := func() {
		mu.Lock()
		starts = append(starts, time.Now())
		mu.Unlock()
		runs.Add(1)
		time.Sleep(5 * time.Millisecond)
	}
	every := func() time.Duration { return interval }

	begin := time.Now()
	var wg sync.WaitGroup
	var last atomic.Int64
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				// Record before the trigger: the check that covers it
				// starts after the trigger begins.
				now := time.Now().UnixNano()
				for {
					old := last.Load()
					if now <= old || last.CompareAndSwap(old, now) {
						break
					}
				}
				q.trigger(s, every, run)
				time.Sleep(time.Millisecond)
			}
		}()
	}
	wg.Wait()
	burst := time.Since(begin)

	idle := func() bool {
		q.mu.Lock()
		defer q.mu.Unlock()
		return !q.running && !q.pending
	}
	checkFor(t, 2*time.Second, 10*time.Millisecond, func() error {
		if !idle() {
			return fmt.Errorf("still running")
		}
		return nil
	})

	n := runs.Load()
	max := int64(burst/interval) + 3
	if n < 2 || n > max {
		t.Fatalf("got %d checks for 1600 triggers in %v, want between 2 and %d", n, burst, max)
	}
	mu.Lock()
	lastStart := starts[len(starts)-1]
	mu.Unlock()
	if !lastStart.After(time.Unix(0, last.Load())) {
		t.Fatalf("last check started %v, before the last trigger %v", lastStart, time.Unix(0, last.Load()))
	}

	// After shutdown, a trigger does not start a goroutine and leaves the
	// coalescer idle.
	s.Shutdown()
	q.trigger(s, every, run)
	require_True(t, idle())
}

// A reload that shortens the interval applies to a wait in progress.
func TestLeafNodeSyncCheckWaitFollowsReload(t *testing.T) {
	s := RunServer(DefaultOptions())
	defer s.Shutdown()

	var d atomic.Int64
	d.Store(int64(time.Hour))
	every := func() time.Duration { return time.Duration(d.Load()) }
	var q syncCheckCoalescer
	var runs atomic.Int64
	run := func() { runs.Add(1) }

	q.trigger(s, every, run)
	checkFor(t, time.Second, 5*time.Millisecond, func() error {
		if runs.Load() != 1 {
			return fmt.Errorf("first check not run")
		}
		return nil
	})
	// Pending while the worker waits one hour.
	q.trigger(s, every, run)
	time.Sleep(50 * time.Millisecond)
	require_Equal(t, runs.Load(), 1)

	d.Store(int64(10 * time.Millisecond))
	checkFor(t, time.Second, 5*time.Millisecond, func() error {
		if runs.Load() != 2 {
			return fmt.Errorf("pending check not run after the interval was shortened")
		}
		return nil
	})

	// Shutdown during a long wait ends the worker and leaves it idle.
	d.Store(int64(time.Hour))
	q.trigger(s, every, run)
	q.trigger(s, every, run)
	s.Shutdown()
	checkFor(t, time.Second, 5*time.Millisecond, func() error {
		q.mu.Lock()
		defer q.mu.Unlock()
		if q.running || q.pending {
			return fmt.Errorf("worker still running after shutdown")
		}
		return nil
	})
}
