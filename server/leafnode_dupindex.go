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

// Index for the duplicate check in addLeafNodeConnection. Upstream finds a
// previous connection from the same remote server by walking all leafnode
// connections under the server lock, so each connect costs O(number of
// leafnodes) while it blocks the server. The index finds the same connections
// by key. Each candidate is still checked with the original condition, under
// its client lock.
//
// The key fields of a connection are set while it processes its CONNECT,
// before it is indexed. Only an abnormal remote can change them later: an INFO
// sent to the accept side, or a second CONNECT, possibly into another account.
// Such a connection is marked dirty before the change, under its client lock.
// While any dirty connection is open, the check uses the original walk, so the
// result is always the same as upstream.

// leafDupKey holds the fields that the duplicate check compares.
type leafDupKey struct {
	srv, cluster, acc, remoteAcc string
}

// leafDupKeyWillChange must be called with the client lock held, before a key
// field of the duplicate check is written.
func (c *client) leafDupKeyWillChange() {
	if c.leaf != nil && c.srv != nil && c.leaf.dupIndexed.Load() && !c.leaf.dupDirty.Load() {
		c.leaf.dupDirty.Store(true)
		c.srv.leafDupDirty.Add(1)
		c.Noticef("Leafnode changed its identity after connect, using the full duplicate check while it is connected")
	}
}

// leafDupRemovedLocked must be called with the client lock held when c is
// removed from the leafnode connections. After it, c is never marked dirty.
func (c *client) leafDupRemovedLocked() {
	if c.leaf == nil {
		return
	}
	c.leaf.dupIndexed.Store(false)
	if c.leaf.dupDirty.Load() {
		c.leaf.dupDirty.Store(false)
		c.srv.leafDupDirty.Add(-1)
	}
}

// findDuplicateLeafLocked returns a non-solicited leafnode connection from the
// same remote server, cluster, local account and remote account, or nil. It is
// the upstream duplicate check. Server lock must be held.
func (s *Server) findDuplicateLeafLocked(srvName, clusterName, accName, remoteAccName string) *client {
	match := func(ol *client) bool {
		ol.mu.Lock()
		defer ol.mu.Unlock()
		// We care here only about non solicited Leafnode. This function
		// is more about replacing stale connections than detecting loops.
		// We have code for the loop detection elsewhere, which also delays
		// attempt to reconnect.
		return !ol.isSolicitedLeafNode() && ol.leaf.remoteServer == srvName &&
			ol.leaf.remoteCluster == clusterName && ol.acc.Name == accName &&
			remoteAccName != _EMPTY_ && ol.leaf.remoteAccName == remoteAccName
	}
	walk := func() *client {
		for _, ol := range s.leafs {
			if match(ol) {
				return ol
			}
		}
		return nil
	}
	if s.leafDupDirty.Load() > 0 {
		return walk()
	}
	if remoteAccName == _EMPTY_ {
		return nil
	}
	for ol := range s.leafDupIdx[leafDupKey{srvName, clusterName, accName, remoteAccName}] {
		if match(ol) {
			return ol
		}
	}
	// A connection may have become dirty while we searched the index. It
	// marks itself before it changes, so checking again here is enough.
	if s.leafDupDirty.Load() > 0 {
		return walk()
	}
	return nil
}

// indexLeafLocked adds c, which was just stored in s.leafs, to the index. Only
// connections that the duplicate check can match are indexed. Server lock must
// be held.
func (s *Server) indexLeafLocked(c *client, key leafDupKey, solicited bool) {
	if solicited || key.remoteAcc == _EMPTY_ || c.leaf == nil {
		return
	}
	// A repeated add (second CONNECT) has marked c dirty, but keep the index
	// exact anyway.
	s.unindexLeafLocked(c)
	if s.leafDupIdx == nil {
		s.leafDupIdx = make(map[leafDupKey]map[*client]struct{})
	}
	set := s.leafDupIdx[key]
	if set == nil {
		set = make(map[*client]struct{})
		s.leafDupIdx[key] = set
	}
	set[c] = struct{}{}
	c.leaf.dupKey = &key
}

// unindexLeafLocked removes c from the index. Server lock must be held.
func (s *Server) unindexLeafLocked(c *client) {
	if c.leaf == nil || c.leaf.dupKey == nil {
		return
	}
	key := *c.leaf.dupKey
	c.leaf.dupKey = nil
	if set := s.leafDupIdx[key]; set != nil {
		delete(set, c)
		if len(set) == 0 {
			delete(s.leafDupIdx, key)
		}
	}
}
