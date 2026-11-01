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
	"cmp"
	"slices"
	"strings"
)

type grantLeafSourceKey struct {
	virtual bool
	key     string
}

type grantLeafSource struct {
	n    int64
	rows []string
}

func (c *client) projectsGrantLeafInterest() bool {
	return c.kind == LEAF && c.leaf != nil && c.authGrantMode.Load() && !c.isSolicitedLeafNode()
}

func intersectGrantLeafSubjects(a, b string) string {
	at, bt := strings.Split(a, tsep), strings.Split(b, tsep)
	row := make([]string, 0, max(len(at), len(bt)))
	for i := 0; i < len(at) && i < len(bt); i++ {
		switch {
		case at[i] == fwcs:
			return strings.Join(append(row, bt[i:]...), tsep)
		case bt[i] == fwcs:
			return strings.Join(append(row, at[i:]...), tsep)
		case at[i] == bt[i] || bt[i] == pwcs:
			row = append(row, at[i])
		case at[i] == pwcs:
			row = append(row, bt[i])
		default:
			return _EMPTY_
		}
	}
	if len(at) != len(bt) {
		return _EMPTY_
	}
	return strings.Join(row, tsep)
}

// The client lock protects the permission snapshot and delivery deny filters.
func (c *client) projectGrantLeafSource(key string) []string {
	subject, queue, hasQueue := strings.Cut(key, " ")
	var rows []string
	add := func(row string) {
		if row == _EMPTY_ {
			return
		}
		if c.opts.Export != nil {
			for _, deny := range c.opts.Export.Deny {
				if subjectIsSubsetMatch(row, deny) {
					return
				}
			}
		}
		c.loadMsgDenyFilterIfNeeded(row, hasQueue)
		if hasQueue {
			row += " " + queue
		}
		rows = append(rows, row)
	}
	allows := []string{fwcs}
	if c.opts.Export != nil && c.opts.Export.Allow != nil {
		allows = c.opts.Export.Allow
	}
	for _, allow := range allows {
		add(intersectGrantLeafSubjects(subject, allow))
	}
	if c.perms != nil {
		for _, rule := range c.perms.sub.prefix {
			wire := make([]string, len(rule))
			for i, token := range rule {
				wire[i] = token.value
				if token.prefix {
					wire[i] = pwcs
				}
			}
			row := intersectGrantLeafSubjects(subject, strings.Join(wire, tsep))
			if row == _EMPTY_ {
				continue
			}
			tokens := strings.Split(row, tsep)
			valid := true
			for i, token := range rule {
				if !token.prefix {
					continue
				}
				if i >= len(tokens) || (tokens[i] != pwcs &&
					(len(tokens[i]) <= len(token.value) || !strings.HasPrefix(tokens[i], token.value))) {
					valid = false
					break
				}
			}
			if valid {
				add(row)
			}
		}
	}
	slices.Sort(rows)
	return slices.Compact(rows)
}

func (c *client) applyGrantLeafRowDelta(key string, delta int64, notify bool) {
	if delta == 0 {
		return
	}
	old := c.leaf.smap[key]
	n := old + delta
	if n > 0 {
		c.leaf.smap[key] = n
	} else {
		delete(c.leaf.smap, key)
	}
	if notify && (strings.Contains(key, " ") || (old <= 0 && n > 0) || (old > 0 && n <= 0)) {
		c.sendLeafNodeSubUpdate(key, n)
	}
}

func (c *client) setGrantLeafSource(key grantLeafSourceKey, n int64, notify bool) {
	old, present := c.leaf.gsrc[key]
	if n <= 0 {
		n = 0
		delete(c.leaf.gsrc, key)
	} else {
		if !present {
			old.rows = c.projectGrantLeafSource(key.key)
		}
		c.leaf.gsrc[key] = grantLeafSource{n: n, rows: old.rows}
	}
	for _, row := range old.rows {
		c.applyGrantLeafRowDelta(row, n-old.n, notify)
	}
}

func (c *client) addGrantLeafSource(key string, virtual bool, delta int64, notify bool) {
	sk := grantLeafSourceKey{virtual: virtual, key: key}
	c.setGrantLeafSource(sk, c.leaf.gsrc[sk].n+delta, notify)
}

// Mapping notifications can arrive after a later mutation or the initial snapshot.
// Read the inventory under client -> account so every notification converges.
func (c *client) reconcileGrantLeafVirtualSource(subject string) {
	var n int64
	c.acc.mu.RLock()
	if len(c.acc.imports.services[subject]) > 0 {
		n++
	}
	for _, m := range c.acc.mappings {
		if m.src == subject {
			n++
			break
		}
	}
	c.acc.mu.RUnlock()
	c.setGrantLeafSource(grantLeafSourceKey{virtual: true, key: subject}, n, true)
}

func (c *client) reprojectGrantLeafInterest() {
	keys := make([]grantLeafSourceKey, 0, len(c.leaf.gsrc))
	for key := range c.leaf.gsrc {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b grantLeafSourceKey) int {
		if a.virtual != b.virtual {
			if a.virtual {
				return 1
			}
			return -1
		}
		return cmp.Compare(a.key, b.key)
	})
	deltas := make(map[string]int64)
	for _, key := range keys {
		source := c.leaf.gsrc[key]
		for _, row := range source.rows {
			deltas[row] -= source.n
		}
		source.rows = c.projectGrantLeafSource(key.key)
		for _, row := range source.rows {
			deltas[row] += source.n
		}
		c.leaf.gsrc[key] = source
	}
	rows := make([]string, 0, len(deltas))
	for row := range deltas {
		rows = append(rows, row)
	}
	slices.Sort(rows)
	for _, row := range rows {
		c.applyGrantLeafRowDelta(row, deltas[row], true)
	}
}
