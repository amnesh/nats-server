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
	"bufio"
	"fmt"
	"net"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"
)

// A leaf closes while one subscription of its initial interest snapshot is
// still in tsub. processSubEx inserts a subscription into the account sublist
// before it updates the leaf nodes, so the snapshot can record it first. The
// close calls removeLeafNodeConnection, which stops the tsub timer, before the
// account drops the leaf. The late leaf update of that subscription must not
// use the stopped timer.
func TestLeafNodeTsubUpdateAfterLeafRemoval(t *testing.T) {
	o := LoadConfig(createConfFile(t, []byte(`
		listen: 127.0.0.1:-1
		accounts { A {} }
		leafnodes { listen: 127.0.0.1:-1 }
	`)))
	o.LeafNode.Account = "A"
	// Without system imports the snapshot records only the test subscription.
	o.NoSystemAccount = true
	hub := RunServer(o)
	defer hub.Shutdown()
	acc, err := hub.LookupAccount("A")
	require_NoError(t, err)

	// The subscription is in the sublist, its leaf update has not run.
	sub := &subscription{client: hub.createInternalAccountClient(), subject: []byte("tsub.value"), sid: []byte("1")}
	require_NoError(t, acc.sl.Insert(sub))

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", hub.getOpts().LeafNode.Port), time.Second)
	require_NoError(t, err)
	defer conn.Close()
	require_NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	require_NoError(t, err)
	require_True(t, strings.HasPrefix(line, "INFO "))
	_, err = fmt.Fprint(conn, "CONNECT {\"name\":\"tsub-leaf\"}\r\nPING\r\n")
	require_NoError(t, err)
	var lines []string
	for {
		line, err = r.ReadString('\n')
		require_NoError(t, err)
		if line = strings.TrimSpace(line); line == "PONG" {
			break
		}
		lines = append(lines, line)
	}
	require_True(t, slices.Contains(lines, "LS+ tsub.value"))

	var lc *client
	hub.mu.Lock()
	for _, l := range hub.leafs {
		lc = l
	}
	hub.mu.Unlock()
	require_True(t, lc != nil)
	lc.mu.Lock()
	_, recorded := lc.leaf.tsub[sub]
	var pending []string
	for s := range lc.leaf.tsub {
		pending = append(pending, string(s.subject))
	}
	lc.mu.Unlock()
	slices.Sort(pending)
	require_True(t, recorded)
	if len(pending) != 1 {
		t.Fatalf("tsub holds %q, want only %q", pending, sub.subject)
	}

	// closeConnection removes the leaf connection here; the account still
	// lists the leaf until acc.removeClient runs.
	hub.removeLeafNodeConnection(lc)
	func() {
		defer func() {
			if v := recover(); v != nil {
				stack := debug.Stack()
				// updateLeafNodesEx holds the leaf lock across updateSmap and
				// does not release it on panic. No other goroutine holds it
				// now. Take it if it is free, then release it either way so
				// that the server can shut down.
				_ = lc.mu.TryLock()
				lc.mu.Unlock()
				t.Fatalf("leaf interest update after leaf removal panicked: %v\n%s", v, stack)
			}
		}()
		acc.updateLeafNodes(sub, 1)
	}()
}
