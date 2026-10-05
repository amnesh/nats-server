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
	"math/rand/v2"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

const isolationHubTmpl = `
	port: -1
	server_name: "%s"
	accounts {
		HA { users: [%s] }
	}
	cluster {
		name: HUB
		listen: 127.0.0.1:-1
		routes: [%s]
	}
	leafnodes {
		port: -1
		isolate_leafnode_interest: %v
	}
`

const isolationSpokeTmpl = `
	port: -1
	server_name: "%s"
	accounts {
		A { users: [{user: A, password: pwd}] }
	}
	leafnodes {
		remotes [{ url: "nats://HA:pwd@127.0.0.1:%d", local: "A" }]
	}
`

func runIsolationSpoke(t *testing.T, name string, leafPort int) *Server {
	t.Helper()
	conf := createConfFile(t, []byte(fmt.Sprintf(isolationSpokeTmpl, name, leafPort)))
	s, _ := RunServerWithConfig(conf)
	return s
}

// hubLeafFor returns the hub-side leaf connection whose remote server is name.
func hubLeafFor(t *testing.T, hub *Server, name string) *client {
	t.Helper()
	var found *client
	checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
		hub.mu.RLock()
		defer hub.mu.RUnlock()
		for _, l := range hub.leafs {
			l.mu.Lock()
			rs := l.leaf.remoteServer
			l.mu.Unlock()
			if rs == name {
				found = l
				return nil
			}
		}
		return fmt.Errorf("no leaf for %q", name)
	})
	return found
}

// The initial interest snapshot that a hub sends to a new isolated leaf must
// contain local and routed client interest, but no leaf interest: not from
// leaves on the same server (kind LEAF) and not from leaves on another server
// of the hub cluster (routed with sub.leaf). A normal leaf gets everything.
func TestLeafNodeIsolatedSnapshotExcludesLeafInterest(t *testing.T) {
	for tname, isolated := range map[string]bool{"Isolated": true, "Normal": false} {
		t.Run(tname, func(t *testing.T) {
			user := `{user: HA, password: pwd}`
			c1 := createConfFile(t, []byte(fmt.Sprintf(isolationHubTmpl, "H1", user, "", isolated)))
			h1, o1 := RunServerWithConfig(c1)
			defer h1.Shutdown()
			c2 := createConfFile(t, []byte(fmt.Sprintf(isolationHubTmpl, "H2", user,
				fmt.Sprintf("nats://127.0.0.1:%d", o1.Cluster.Port), isolated)))
			h2, o2 := RunServerWithConfig(c2)
			defer h2.Shutdown()
			checkClusterFormed(t, h1, h2)

			// A leaf on each hub server, with interest that exists before the
			// new leaf connects.
			sp1 := runIsolationSpoke(t, "SP1", o1.LeafNode.Port)
			defer sp1.Shutdown()
			sp2 := runIsolationSpoke(t, "SP2", o2.LeafNode.Port)
			defer sp2.Shutdown()
			checkLeafNodeConnectedCount(t, h1, 1)
			checkLeafNodeConnectedCount(t, h2, 1)

			nh1 := natsConnect(t, h1.ClientURL(), nats.UserInfo("HA", "pwd"))
			defer nh1.Close()
			nh2 := natsConnect(t, h2.ClientURL(), nats.UserInfo("HA", "pwd"))
			defer nh2.Close()
			nsp1 := natsConnect(t, sp1.ClientURL(), nats.UserInfo("A", "pwd"))
			defer nsp1.Close()
			nsp2 := natsConnect(t, sp2.ClientURL(), nats.UserInfo("A", "pwd"))
			defer nsp2.Close()

			natsSubSync(t, nh1, "h1client")
			natsQueueSubSync(t, nh1, "h1queue", "q")
			natsSubSync(t, nh2, "h2client")
			natsQueueSubSync(t, nh2, "h2queue", "q")
			natsSubSync(t, nsp1, "h1leaf")
			natsQueueSubSync(t, nsp1, "h1leafqueue", "q")
			natsSubSync(t, nsp2, "h2leaf")
			for _, nc := range []*nats.Conn{nh1, nh2, nsp1, nsp2} {
				natsFlush(t, nc)
			}
			for _, subj := range []string{"h1client", "h1queue", "h2client", "h2queue", "h1leaf", "h1leafqueue", "h2leaf"} {
				checkSubInterest(t, h1, "HA", subj, 2*time.Second)
			}

			// The new leaf connects after all interest exists: it gets its
			// interest only from the snapshot.
			sp3 := runIsolationSpoke(t, "SP3", o1.LeafNode.Port)
			defer sp3.Shutdown()
			checkLeafNodeConnectedCount(t, h1, 2)
			ln := hubLeafFor(t, h1, "SP3")

			for _, subj := range []string{"h1client", "h1queue", "h2client", "h2queue"} {
				checkSubInterest(t, sp3, "A", subj, 2*time.Second)
			}
			leafSubjects := []string{"h1leaf", "h1leafqueue", "h2leaf"}
			for _, subj := range leafSubjects {
				if isolated {
					checkSubNoInterest(t, sp3, "A", subj, 250*time.Millisecond)
				} else {
					checkSubInterest(t, sp3, "A", subj, 2*time.Second)
				}
			}

			ln.mu.Lock()
			smap := make(map[string]int32, len(ln.leaf.smap))
			for k, v := range ln.leaf.smap {
				smap[k] = v
			}
			ln.mu.Unlock()
			for _, key := range []string{"h1client", "h1queue q", "h2client", "h2queue q"} {
				if smap[key] <= 0 {
					t.Fatalf("expected %q in smap, got %v", key, smap)
				}
			}
			for _, key := range []string{"h1leaf", "h1leafqueue q", "h2leaf"} {
				if _, ok := smap[key]; ok == isolated {
					t.Fatalf("isolated=%v: unexpected presence of %q in smap %v", isolated, key, smap)
				}
			}
		})
	}
}

// Each account tracks its non-isolated leaves, so that leaf interest is not
// propagated in a loop when no leaf can receive it. The tracking must survive a
// config reload, or interest from one normal leaf would stop reaching another.
func TestLeafNodeSharedLeafTrackingFollowsReload(t *testing.T) {
	for tname, isolated := range map[string]bool{"Isolated": true, "Normal": false} {
		t.Run(tname, func(t *testing.T) {
			conf := createConfFile(t, []byte(fmt.Sprintf(isolationHubTmpl, "H1",
				`{user: HA, password: pwd}`, "", isolated)))
			h1, o1 := RunServerWithConfig(conf)
			defer h1.Shutdown()

			sp1 := runIsolationSpoke(t, "SP1", o1.LeafNode.Port)
			defer sp1.Shutdown()
			sp2 := runIsolationSpoke(t, "SP2", o1.LeafNode.Port)
			defer sp2.Shutdown()
			checkLeafNodeConnectedCount(t, h1, 2)

			checkShared := func(want int) {
				t.Helper()
				checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
					acc, err := h1.LookupAccount("HA")
					if err != nil {
						return err
					}
					acc.lmu.RLock()
					n := len(acc.sharedLeafs)
					acc.lmu.RUnlock()
					if n != want {
						return fmt.Errorf("shared leafs: got %d, want %d", n, want)
					}
					return nil
				})
			}
			want := 2
			if isolated {
				want = 0
			}
			checkShared(want)

			// Change the users of the account so that the reload re-authorizes
			// and re-registers the leaves.
			reloadUpdateConfig(t, h1, conf, fmt.Sprintf(isolationHubTmpl, "H1",
				`{user: HA, password: pwd}, {user: HB, password: pwd}`, "", isolated))
			checkLeafNodeConnectedCount(t, h1, 2)
			checkShared(want)

			// Interest made after the reload still follows the isolation rule.
			nsp1 := natsConnect(t, sp1.ClientURL(), nats.UserInfo("A", "pwd"))
			defer nsp1.Close()
			natsSubSync(t, nsp1, "afterreload")
			natsFlush(t, nsp1)
			checkSubInterest(t, h1, "HA", "afterreload", 2*time.Second)
			if isolated {
				// checkSubNoInterest passes at once; give the update time to arrive.
				time.Sleep(250 * time.Millisecond)
				checkSubNoInterest(t, sp2, "A", "afterreload", 250*time.Millisecond)
			} else {
				checkSubInterest(t, sp2, "A", "afterreload", 2*time.Second)
			}

			// A closed normal leaf leaves the tracking.
			sp2.Shutdown()
			checkLeafNodeConnectedCount(t, h1, 1)
			if !isolated {
				want = 1
			}
			checkShared(want)
		})
	}
}

func newIsolationTestLeaf(isolated bool) *client {
	c := &client{kind: LEAF, leaf: &leaf{}}
	c.setLeafIsolated(isolated)
	return c
}

// The shared-leaf set follows lleafs exactly, through the only two places that
// change lleafs, also when a leaf moves between Account objects.
func TestLeafNodeSharedLeafTrackingHooks(t *testing.T) {
	a1, a2 := NewAccount("A1"), NewAccount("A2")
	iso, shared := newIsolationTestLeaf(true), newIsolationTestLeaf(false)

	noReceiver := func(a *Account) bool {
		a.lmu.RLock()
		defer a.lmu.RUnlock()
		return a.noLeafReceivesLeafInterest()
	}

	a1.addClient(iso)
	require_True(t, noReceiver(a1))
	a1.addClient(shared)
	require_False(t, noReceiver(a1))
	// Adding the same client again does not change anything.
	a1.addClient(shared)
	a1.removeClient(shared)
	require_True(t, noReceiver(a1))

	// Move the shared leaf to another account object.
	a1.addClient(shared)
	a2.addClient(shared)
	a1.removeClient(shared)
	require_True(t, noReceiver(a1))
	require_False(t, noReceiver(a2))
	a2.removeClient(shared)
	require_True(t, noReceiver(a2))

	// A leaf that becomes isolated after it was added stays tracked: the
	// shortcut is lost, but no update is dropped.
	late := newIsolationTestLeaf(false)
	a1.addClient(late)
	late.setLeafIsolated(true)
	require_False(t, noReceiver(a1))
	a1.removeClient(late)
	require_True(t, noReceiver(a1))

	// Isolation can only be turned on.
	late.setLeafIsolated(false)
	require_True(t, late.leaf.isolated)
	require_True(t, late.leaf.isolatedHint.Load())
}

// The snapshot walk keeps exactly the subscriptions that are not leaf
// interest, for plain and queue subscriptions.
func TestLeafNodeNonLeafSubsFilter(t *testing.T) {
	sl := NewSublistWithCache()
	cl := &client{kind: CLIENT}
	rt := &client{kind: ROUTER}
	lf := &client{kind: LEAF}
	keep := []*subscription{
		{client: cl, subject: []byte("a.b")},
		{client: cl, subject: []byte("a.*"), queue: []byte("q")},
		{client: rt, subject: []byte("a.>")},
		{client: rt, subject: []byte("r.q"), queue: []byte("q")},
	}
	drop := []*subscription{
		{client: lf, subject: []byte("a.b")},
		{client: lf, subject: []byte("l.q"), queue: []byte("q")},
		{client: rt, subject: []byte("a.b"), leaf: true},
		{client: rt, subject: []byte("r.q"), queue: []byte("q"), leaf: true},
	}
	for _, sub := range append(append([]*subscription{}, keep...), drop...) {
		require_NoError(t, sl.Insert(sub))
	}
	var all, got []*subscription
	sl.All(&all)
	require_Equal(t, len(all), len(keep)+len(drop))
	sl.nonLeafSubs(&got)
	require_Equal(t, len(got), len(keep))
	set := make(map[*subscription]struct{}, len(got))
	for _, sub := range got {
		set[sub] = struct{}{}
	}
	for _, sub := range keep {
		if _, ok := set[sub]; !ok {
			t.Fatalf("missing kept subscription %q", sub.subject)
		}
	}
}

// After first use, the non-leaf set is kept in Insert and remove. It must
// always equal All() filtered by isLeafInterest, after any mix of inserts,
// removes, batch removes, duplicate inserts, failed removes and invalid
// subjects.
func TestLeafNodeNonLeafSubsTracking(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	clients := []*client{{kind: CLIENT}, {kind: ROUTER}, {kind: LEAF}, {kind: SYSTEM}, {kind: JETSTREAM}, {kind: GATEWAY}}
	subjects := []string{"a", "a.b", "a.*", "a.>", ">", "b.c.d", "*.c.*", "x.y"}
	queues := [][]byte{nil, nil, []byte("q1"), []byte("q2")}

	check := func(sl *Sublist) {
		t.Helper()
		var all, got []*subscription
		sl.All(&all)
		want := make(map[*subscription]struct{})
		for _, sub := range all {
			if !isLeafInterest(sub) {
				want[sub] = struct{}{}
			}
		}
		sl.nonLeafSubs(&got)
		if len(got) != len(want) {
			t.Fatalf("got %d non-leaf subs, want %d", len(got), len(want))
		}
		for _, sub := range got {
			if _, ok := want[sub]; !ok {
				t.Fatalf("unexpected sub %q in non-leaf set", sub.subject)
			}
		}
	}

	for _, cache := range []bool{true, false} {
		sl := NewSublist(cache)
		var live []*subscription
		for i := 0; i < 5000; i++ {
			switch op := rng.IntN(10); {
			case op < 5:
				sub := &subscription{
					client:  clients[rng.IntN(len(clients))],
					subject: []byte(subjects[rng.IntN(len(subjects))]),
					queue:   queues[rng.IntN(len(queues))],
					leaf:    rng.IntN(4) == 0,
				}
				require_NoError(t, sl.Insert(sub))
				live = append(live, sub)
			case op < 6 && len(live) > 0:
				// Insert an existing sub again.
				require_NoError(t, sl.Insert(live[rng.IntN(len(live))]))
			case op < 8 && len(live) > 0:
				j := rng.IntN(len(live))
				sl.Remove(live[j])
				// A second remove fails and must not change anything.
				sl.Remove(live[j])
				live = append(live[:j], live[j+1:]...)
			case op < 9 && len(live) > 1:
				n := rng.IntN(len(live)/2 + 1)
				sl.RemoveBatch(live[:n])
				live = live[n:]
			default:
				// Invalid subjects are rejected and must not be tracked.
				sl.Insert(&subscription{client: clients[0], subject: []byte("a..b")})
			}
			// Seed the set at a random point, then keep checking it.
			if i == 100 || (i > 100 && i%97 == 0) {
				check(sl)
			}
		}
		check(sl)
	}
}

// An isolated hub-side leaf with subscribe denies gets its delivery deny
// filter in the snapshot, also when the account has no other interest. Upstream
// could load it only as a side effect of permission checks on leaf interest.
func TestLeafNodeIsolatedSnapshotLoadsDenyFilter(t *testing.T) {
	s, _ := RunServerWithConfig(createConfFile(t, []byte(`
		listen: 127.0.0.1:-1
		leafnodes { listen: 127.0.0.1:-1, isolate_leafnode_interest: true }
	`)))
	defer s.Shutdown()
	acc := s.globalAccount()

	for _, deny := range []bool{true, false} {
		c := &client{srv: s, kind: LEAF, acc: acc, leaf: &leaf{}}
		c.setLeafIsolated(true)
		if deny {
			c.darray = []*subscription{{subject: []byte("$GR.>")}}
		}
		s.initLeafNodeSmapAndSendSubs(c)
		c.mu.Lock()
		loaded := c.mperms != nil
		c.mu.Unlock()
		require_Equal(t, loaded, deny)
	}
}

// A leaf that requests isolation in its CONNECT, on a hub that does not
// isolate by itself, leaves the shared-leaf set once it is isolated.
func TestLeafNodeRequestedIsolationLeavesSharedSet(t *testing.T) {
	conf := createConfFile(t, []byte(fmt.Sprintf(isolationHubTmpl, "H1",
		`{user: HA, password: pwd}`, "", false)))
	h1, o1 := RunServerWithConfig(conf)
	defer h1.Shutdown()

	spokeTmpl := `
		port: -1
		server_name: "%s"
		accounts { A { users: [{user: A, password: pwd}] } }
		leafnodes {
			remotes [{ url: "nats://HA:pwd@127.0.0.1:%d", local: "A", request_isolation: %v }]
		}
	`
	sp1, _ := RunServerWithConfig(createConfFile(t, []byte(fmt.Sprintf(spokeTmpl, "SP1", o1.LeafNode.Port, true))))
	defer sp1.Shutdown()
	sp2, _ := RunServerWithConfig(createConfFile(t, []byte(fmt.Sprintf(spokeTmpl, "SP2", o1.LeafNode.Port, false))))
	defer sp2.Shutdown()
	checkLeafNodeConnectedCount(t, h1, 2)

	l1, l2 := hubLeafFor(t, h1, "SP1"), hubLeafFor(t, h1, "SP2")
	acc, err := h1.LookupAccount("HA")
	require_NoError(t, err)
	checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
		acc.lmu.RLock()
		defer acc.lmu.RUnlock()
		_, has1 := acc.sharedLeafs[l1]
		_, has2 := acc.sharedLeafs[l2]
		if has1 || !has2 {
			return fmt.Errorf("shared set: SP1=%v (want false) SP2=%v (want true)", has1, has2)
		}
		return nil
	})

	// The normal leaf still gets interest from the isolated one; the isolated
	// one does not get interest from the normal one.
	n1 := natsConnect(t, sp1.ClientURL(), nats.UserInfo("A", "pwd"))
	defer n1.Close()
	n2 := natsConnect(t, sp2.ClientURL(), nats.UserInfo("A", "pwd"))
	defer n2.Close()
	natsSubSync(t, n1, "from.sp1")
	natsSubSync(t, n2, "from.sp2")
	natsFlush(t, n1)
	natsFlush(t, n2)
	checkSubInterest(t, h1, "HA", "from.sp1", 2*time.Second)
	checkSubInterest(t, h1, "HA", "from.sp2", 2*time.Second)
	checkSubInterest(t, sp2, "A", "from.sp1", 2*time.Second)
	time.Sleep(250 * time.Millisecond)
	checkSubNoInterest(t, sp1, "A", "from.sp2", 250*time.Millisecond)
}

// Cost of the snapshot for a new isolated hub-side leaf, with K leaf
// subscriptions already in the account, and a few local ones.
func BenchmarkLeafNodeIsolatedInitSmap(b *testing.B) {
	for _, k := range []int{15_000, 150_000, 900_000} {
		b.Run(fmt.Sprintf("leafSubs=%d", k), func(b *testing.B) {
			s, _ := RunServerWithConfig(createConfFile(b, []byte(`
				listen: 127.0.0.1:-1
				leafnodes { listen: 127.0.0.1:-1, isolate_leafnode_interest: true }
			`)))
			defer s.Shutdown()
			acc := s.globalAccount()
			const perLeaf = 15
			for i := 0; i < k/perLeaf; i++ {
				lc := &client{kind: LEAF, leaf: &leaf{}}
				for j := 0; j < perLeaf; j++ {
					subj := fmt.Sprintf("leaf.%d.s%d", i, j)
					if j < 3 {
						subj = fmt.Sprintf("shared.s%d", j)
					}
					acc.sl.Insert(&subscription{client: lc, subject: []byte(subj), sid: []byte(subj)})
				}
			}
			for j := 0; j < 20; j++ {
				acc.sl.Insert(&subscription{client: &client{kind: CLIENT}, subject: []byte(fmt.Sprintf("local.%d", j))})
			}
			// A bare hub-side leaf without a connection: queued protocol
			// stays in c.out and is dropped after each run.
			c := &client{srv: s, kind: LEAF, acc: acc, leaf: &leaf{}}
			c.setLeafIsolated(true)
			// The first snapshot fills the non-leaf set with one full walk.
			// Measure the steady state.
			s.initLeafNodeSmapAndSendSubs(c)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.initLeafNodeSmapAndSendSubs(c)
				c.mu.Lock()
				c.out.nb, c.out.pb = nil, 0
				c.mu.Unlock()
			}
		})
	}
}
