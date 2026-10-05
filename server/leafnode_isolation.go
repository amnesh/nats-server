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

// Fast paths for isolated leafnode interest (leafnodes { isolate: true } or a
// remote that requests isolation). An isolated leaf never receives interest
// that comes from leafnodes. Upstream applies that rule per subscription, after
// it has collected and permission-checked the interest of every leaf in the
// account, so the cost of a connect and of each leaf subscription grows with
// the number of leaves. These helpers apply the same rule earlier, with the
// same result.

// isLeafInterest reports whether sub is interest that an isolated leaf must
// not receive: interest from a leafnode on this server, or interest routed from
// a leafnode on another server of the cluster. It is the same test that
// initLeafNodeSmapAndSendSubs and updateLeafNodesEx apply.
func isLeafInterest(sub *subscription) bool {
	return (sub.client != nil && sub.client.kind == LEAF) || sub.leaf
}

// nonLeafSubs collects all subscriptions in the sublist except leaf interest,
// for the snapshot that a hub sends to a new isolated leaf. The result is the
// same as All() followed by the isolated-leaf filter, but the cost depends only
// on the number of non-leaf subscriptions: on first use, the sublist walks its
// tree once and from then on keeps the set up to date in Insert and remove.
func (s *Sublist) nonLeafSubs(subs *[]*subscription) {
	s.RLock()
	if s.nonLeaf == nil {
		s.RUnlock()
		s.Lock()
		if s.nonLeaf == nil {
			m := make(map[*subscription]struct{})
			s.collectNonLeafSubs(s.root, m)
			s.nonLeaf = m
		}
		s.Unlock()
		s.RLock()
	}
	for sub := range s.nonLeaf {
		*subs = append(*subs, sub)
	}
	s.RUnlock()
}

// trackNonLeafInsert is called by Insert after sub was added. Lock held.
func (s *Sublist) trackNonLeafInsert(sub *subscription) {
	if s.nonLeaf != nil && !isLeafInterest(sub) {
		s.nonLeaf[sub] = struct{}{}
	}
}

// trackNonLeafRemove is called by remove after sub was removed. Lock held.
func (s *Sublist) trackNonLeafRemove(sub *subscription) {
	if s.nonLeaf != nil {
		delete(s.nonLeaf, sub)
	}
}

func addNonLeafNodeSubs(n *node, m map[*subscription]struct{}) {
	for sub := range n.psubs {
		if !isLeafInterest(sub) {
			m[sub] = struct{}{}
		}
	}
	for _, qr := range n.qsubs {
		for sub := range qr {
			if !isLeafInterest(sub) {
				m[sub] = struct{}{}
			}
		}
	}
}

// collectNonLeafSubs walks the tree like collectAllSubs. Lock held.
func (s *Sublist) collectNonLeafSubs(l *level, m map[*subscription]struct{}) {
	for _, n := range l.nodes {
		addNonLeafNodeSubs(n, m)
		s.collectNonLeafSubs(n.next, m)
	}
	if l.pwc != nil {
		addNonLeafNodeSubs(l.pwc, m)
		s.collectNonLeafSubs(l.pwc.next, m)
	}
	if l.fwc != nil {
		addNonLeafNodeSubs(l.fwc, m)
		s.collectNonLeafSubs(l.fwc.next, m)
	}
}

// setLeafIsolated sets the isolation mode of a leaf connection. Isolation can
// only be turned on, never off. Lock must be held.
func (c *client) setLeafIsolated(isolated bool) {
	if isolated {
		c.leaf.isolated = true
		c.leaf.isolatedHint.Store(true)
	}
}

// Each account keeps the set of its leaves (in lleafs) that are not isolated
// when they are added. updateLeafNodesEx skips leaf interest for isolated
// leaves, so when the set is empty, leaf interest has no receiver and the loop
// over all leaves can be skipped. A leaf that becomes isolated after it was
// added stays in the set until untrackIsolatedLeaf runs; being in the set only
// disables the shortcut, it never drops an update.

// trackSharedLeaf records c when it is added to lleafs. Account lmu must be
// held for writing.
func (a *Account) trackSharedLeaf(c *client) {
	if c.leaf != nil && c.leaf.isolatedHint.Load() {
		return
	}
	if a.sharedLeafs == nil {
		a.sharedLeafs = make(map[*client]struct{})
	}
	a.sharedLeafs[c] = struct{}{}
}

// untrackSharedLeaf forgets c when it is removed from lleafs. Account lmu must
// be held for writing.
func (a *Account) untrackSharedLeaf(c *client) {
	delete(a.sharedLeafs, c)
}

// untrackIsolatedLeaf forgets c if it has become isolated after it was added,
// for isolation that the remote requests in its CONNECT. An isolated leaf
// never receives leaf interest. Account lmu must not be held, nor the client
// lock (lock order is account lmu, then client).
func (a *Account) untrackIsolatedLeaf(c *client) {
	if c.leaf == nil || !c.leaf.isolatedHint.Load() {
		return
	}
	a.lmu.Lock()
	delete(a.sharedLeafs, c)
	a.lmu.Unlock()
}

// loadIsolatedLeafDenyFilter loads the delivery deny filter of an isolated
// hub-side leaf that has subscribe denies. Upstream runs canSubscribe on all
// leaf interest in the snapshot and drops it afterwards; as a side effect, a
// wildcard subject there can load this filter. Some subscriptions of the leaf
// itself ($GR., _GR_.) skip the permission check that would load it. Since the
// snapshot no longer collects leaf interest, load the filter here. The filter
// only blocks deliveries that the deny rules already block. Lock must be held.
func (c *client) loadIsolatedLeafDenyFilter() {
	if c.mperms == nil && len(c.darray) > 0 {
		c.loadMsgDenyFilter()
	}
}

// noLeafReceivesLeafInterest reports whether no leaf in lleafs can receive
// interest that comes from a leafnode. Account lmu must be held.
func (a *Account) noLeafReceivesLeafInterest() bool {
	return len(a.sharedLeafs) == 0
}
