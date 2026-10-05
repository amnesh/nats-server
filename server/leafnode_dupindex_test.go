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
	"math/rand/v2"
	"net"
	"testing"
)

// upstreamDuplicateLeaf is the original duplicate check: all matches.
func upstreamDuplicateLeaf(s *Server, srvName, clusterName, accName, remoteAccName string) map[*client]struct{} {
	out := make(map[*client]struct{})
	for _, ol := range s.leafs {
		ol.mu.Lock()
		if !ol.isSolicitedLeafNode() && ol.leaf.remoteServer == srvName &&
			ol.leaf.remoteCluster == clusterName && ol.acc.Name == accName &&
			remoteAccName != _EMPTY_ && ol.leaf.remoteAccName == remoteAccName {
			out[ol] = struct{}{}
		}
		ol.mu.Unlock()
	}
	return out
}

// The indexed duplicate check finds a connection exactly when the original
// walk finds one, and only one of the connections the walk can find, after
// any mix of adds and removes, and in fallback mode.
func TestLeafNodeDuplicateIndexMatchesWalk(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	names := []string{"", "s1", "s2"}
	clusters := []string{"", "c1"}
	accs := []*Account{NewAccount("A"), NewAccount("B")}
	remoteAccs := []string{"", "RA", "RB"}

	for _, fallback := range []bool{false, true} {
		s := &Server{leafs: make(map[uint64]*client)}
		if fallback {
			s.leafDupDirty.Store(1)
		}
		var cid uint64
		pick := func(l []string) string { return l[rng.IntN(len(l))] }

		for i := 0; i < 3000; i++ {
			if rng.IntN(3) > 0 || len(s.leafs) == 0 {
				cid++
				c := &client{kind: LEAF, cid: cid, acc: accs[rng.IntN(len(accs))], leaf: &leaf{}}
				if rng.IntN(5) == 0 {
					c.leaf.remote = &leafNodeCfg{}
				}
				c.leaf.remoteServer, c.leaf.remoteCluster, c.leaf.remoteAccName = pick(names), pick(clusters), pick(remoteAccs)
				s.mu.Lock()
				s.leafs[cid] = c
				s.indexLeafLocked(c, leafDupKey{c.leaf.remoteServer, c.leaf.remoteCluster, c.acc.Name, c.leaf.remoteAccName}, c.leaf.remote != nil)
				s.mu.Unlock()
			} else {
				for id, c := range s.leafs {
					s.mu.Lock()
					delete(s.leafs, id)
					s.unindexLeafLocked(c)
					s.mu.Unlock()
					break
				}
			}
			srv, cl, acc, racc := pick(names), pick(clusters), accs[rng.IntN(len(accs))].Name, pick(remoteAccs)
			s.mu.Lock()
			want := upstreamDuplicateLeaf(s, srv, cl, acc, racc)
			got := s.findDuplicateLeafLocked(srv, cl, acc, racc)
			s.mu.Unlock()
			if got == nil {
				if len(want) != 0 {
					t.Fatalf("fallback=%v: index found nothing, walk found %d", fallback, len(want))
				}
			} else if _, ok := want[got]; !ok {
				t.Fatalf("fallback=%v: index found a connection the walk does not match", fallback)
			}
		}
		// Every index entry is a live connection.
		s.mu.Lock()
		n := 0
		for _, set := range s.leafDupIdx {
			for c := range set {
				if s.leafs[c.cid] != c {
					t.Fatalf("index holds a removed connection")
				}
				n++
			}
		}
		s.mu.Unlock()
		if n > len(s.leafs) {
			t.Fatalf("index has %d entries for %d connections", n, len(s.leafs))
		}
	}
}

// A key field change on an indexed connection switches to the full walk while
// that connection is open, so it is still found under its new identity. The
// walk ends when the connection is removed.
func TestLeafNodeDuplicateIndexFallbackOnIdentityChange(t *testing.T) {
	s, _ := RunServerWithConfig(createConfFile(t, []byte(`
		listen: 127.0.0.1:-1
		leafnodes { listen: 127.0.0.1:-1 }
	`)))
	defer s.Shutdown()
	acc := s.globalAccount()

	add := func(cid uint64, name string) *client {
		c := &client{srv: s, kind: LEAF, cid: cid, acc: acc, leaf: &leaf{}}
		c.leaf.remoteServer, c.leaf.remoteAccName = name, "RA"
		c.leaf.dupIndexed.Store(true)
		s.mu.Lock()
		s.leafs[cid] = c
		s.indexLeafLocked(c, leafDupKey{name, "", acc.Name, "RA"}, false)
		s.mu.Unlock()
		return c
	}
	remove := func(c *client) {
		s.mu.Lock()
		c.mu.Lock()
		c.leafDupRemovedLocked()
		c.mu.Unlock()
		delete(s.leafs, c.cid)
		s.unindexLeafLocked(c)
		s.mu.Unlock()
	}
	find := func(name string) *client {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.findDuplicateLeafLocked(name, "", acc.Name, "RA")
	}

	c := add(1, "s1")
	other := add(2, "s3")
	require_True(t, find("s1") == c)

	// An INFO from the remote changes its name.
	c.mu.Lock()
	c.leafDupKeyWillChange()
	c.leaf.remoteServer = "s2"
	c.mu.Unlock()
	require_Equal(t, s.leafDupDirty.Load(), int64(1))
	require_True(t, find("s2") == c)
	require_True(t, find("s1") == nil)
	require_True(t, find("s3") == other)

	// A second change does not count twice.
	c.mu.Lock()
	c.leafDupKeyWillChange()
	c.mu.Unlock()
	require_Equal(t, s.leafDupDirty.Load(), int64(1))

	// Removing the dirty connection ends the walk; a late change on the
	// removed connection does not start it again.
	remove(c)
	require_Equal(t, s.leafDupDirty.Load(), int64(0))
	c.mu.Lock()
	c.leafDupKeyWillChange()
	c.mu.Unlock()
	require_Equal(t, s.leafDupDirty.Load(), int64(0))
	require_True(t, find("s3") == other)
	require_True(t, find("s2") == nil)
	remove(other)
}

// A connection that moves to another account (a second CONNECT that
// authenticates elsewhere) is marked before its account changes.
func TestLeafNodeDuplicateIndexAccountChange(t *testing.T) {
	s, _ := RunServerWithConfig(createConfFile(t, []byte(`
		listen: 127.0.0.1:-1
		accounts { A {}, B {} }
		leafnodes { listen: 127.0.0.1:-1 }
	`)))
	defer s.Shutdown()
	a, err := s.LookupAccount("A")
	require_NoError(t, err)
	b, err := s.LookupAccount("B")
	require_NoError(t, err)

	newLeaf := func(cid uint64) *client {
		nc, other := net.Pipe()
		t.Cleanup(func() { nc.Close(); other.Close() })
		return &client{srv: s, kind: LEAF, cid: cid, nc: nc, leaf: &leaf{}}
	}
	c := newLeaf(1)
	require_NoError(t, c.registerWithAccount(a))
	c.leaf.remoteServer, c.leaf.remoteAccName = "s1", "RA"
	c.leaf.dupIndexed.Store(true)
	s.mu.Lock()
	s.leafs[1] = c
	s.indexLeafLocked(c, leafDupKey{"s1", "", "A", "RA"}, false)
	s.mu.Unlock()

	require_NoError(t, c.registerWithAccount(b))
	require_Equal(t, s.leafDupDirty.Load(), int64(1))
	s.mu.Lock()
	require_True(t, s.findDuplicateLeafLocked("s1", "", "B", "RA") == c)
	require_True(t, s.findDuplicateLeafLocked("s1", "", "A", "RA") == nil)
	s.mu.Unlock()

	// Registering again with the same account does not mark anything.
	c2 := newLeaf(2)
	require_NoError(t, c2.registerWithAccount(a))
	c2.leaf.dupIndexed.Store(true)
	require_NoError(t, c2.registerWithAccount(a))
	require_False(t, c2.leaf.dupDirty.Load())
}
