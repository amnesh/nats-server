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
	"testing"
)

// traceLineLogger keeps the trace lines.
type traceLineLogger struct {
	DummyLogger
	mu    sync.Mutex
	lines []string
}

func (l *traceLineLogger) Tracef(format string, v ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, v...))
	l.mu.Unlock()
}

func (l *traceLineLogger) traced(subject string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.lines {
		if strings.Contains(line, subject) {
			return true
		}
	}
	return false
}

// A host that embeds the server changes the trace flag with SetLoggerV2. A
// connection that is already open uses the new flag only after
// RefreshClientTraceLevel. NoLog is set, as for a host with its own logger.
func TestRefreshClientTraceLevel(t *testing.T) {
	opts := DefaultOptions()
	opts.NoLog = true
	s := RunServer(opts)
	defer s.Shutdown()
	l := &traceLineLogger{}
	s.SetLoggerV2(l, false, false, false)

	nc := natsConnect(t, s.ClientURL())
	defer nc.Close()
	publish := func(subject string) {
		natsPub(t, nc, subject, nil)
		natsFlush(t, nc)
	}

	s.SetLoggerV2(l, false, true, false)
	publish("trace.on.before.refresh")
	if l.traced("trace.on.before.refresh") {
		t.Fatalf("the open connection traced before the refresh")
	}
	s.RefreshClientTraceLevel()
	publish("trace.on.after.refresh")
	if !l.traced("trace.on.after.refresh") {
		t.Fatalf("the open connection did not trace after the refresh")
	}

	s.SetLoggerV2(l, false, false, false)
	s.RefreshClientTraceLevel()
	publish("trace.off.after.refresh")
	if l.traced("trace.off.after.refresh") {
		t.Fatalf("the open connection traced after trace off and the refresh")
	}
	// The server flag alone stops the lines. The refresh also clears the
	// flag that the connection keeps, so the parser stops the trace work.
	s.mu.RLock()
	for _, c := range s.clients {
		c.mu.Lock()
		trace := c.trace
		c.mu.Unlock()
		if trace {
			t.Errorf("connection %d keeps trace on after the refresh", c.cid)
		}
	}
	s.mu.RUnlock()
}

// The setup of a leaf link, a route, or a gateway connection writes the
// temporary client map while a host calls RefreshClientTraceLevel. The
// refresh must read that map with its lock. Run this test with -race.
func TestRefreshClientTraceLevelWithTempClients(t *testing.T) {
	opts := DefaultOptions()
	opts.NoLog = true
	s := RunServer(opts)
	defer s.Shutdown()

	const firstID, numIDs, rounds = uint64(1_000_000), 8, 200
	clients := make([]*client, numIDs)
	for i := range clients {
		// setTraceLevel reads c.srv.
		clients[i] = &client{srv: s, kind: LEAF}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range rounds {
			for i, c := range clients {
				if !s.addToTempClients(firstID+uint64(i), c) {
					t.Errorf("the server did not add temporary client %d", i)
					return
				}
			}
			for i := range clients {
				s.removeFromTempClients(firstID + uint64(i))
			}
		}
	}()
	for range rounds {
		s.RefreshClientTraceLevel()
	}
	wg.Wait()
}
