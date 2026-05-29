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

// Package authverify holds the pure, server-independent logic for the
// authentication verification callout: narrowing a verified user's JWT claims by
// a service-supplied override such that the result can only ever be more
// restrictive than what the server already verified (it can never escalate).
//
// It deliberately depends only on github.com/nats-io/jwt/v2 (never on the server
// package) so it can be imported by the server without an import cycle. The
// subject subset-match below is a small vendored copy of the unexported helper in
// server/sublist.go for the same reason.
package authverify

import (
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
)

// NarrowPermissions returns a new permission set that restricts base by override
// such that any subject action allowed by the result is also allowed by base: the
// override can only narrow, never escalate. A nil override returns an independent
// clone of base.
func NarrowPermissions(base, override *jwt.Permissions) *jwt.Permissions {
	if base == nil {
		base = &jwt.Permissions{}
	}
	out := clonePermissions(base)
	if override == nil {
		return out
	}
	out.Pub = narrowPermission(base.Pub, override.Pub)
	out.Sub = narrowPermission(base.Sub, override.Sub)
	out.Resp = narrowResponse(base.Resp, override.Resp)
	return out
}

// narrowPermission restricts a single pub or sub permission: the allow set is
// intersected (never broadened) and the deny set is unioned (always narrows).
func narrowPermission(base, override jwt.Permission) jwt.Permission {
	out := clonePermission(base)
	// Allow: intersection. An empty override allow means "no allow restriction".
	if len(override.Allow) > 0 {
		if len(base.Allow) == 0 {
			// base allowed everything -> restrict to the override's set.
			out.Allow = cloneStrings(override.Allow)
		} else {
			kept := intersectAllow(base.Allow, override.Allow)
			// An empty intersection would serialize as an empty allow list, which
			// NATS interprets as "allow all" -- an escalation. When the override
			// does not intersect base at all, keep base's allow so the result can
			// never be broader than base.
			if len(kept) > 0 {
				out.Allow = kept
			}
		}
	}
	// Deny: union (adding denies always narrows), deduplicated.
	if len(override.Deny) > 0 {
		out.Deny = unionStrings(out.Deny, override.Deny)
	}
	return out
}

// intersectAllow returns the subjects allowed by BOTH base and override allow
// lists: every override entry within some base entry, plus every base entry
// within some override entry. The result is always a subset of base.
func intersectAllow(base, override jwt.StringList) jwt.StringList {
	var out jwt.StringList
	seen := make(map[string]struct{})
	add := func(s string) {
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, o := range override {
		for _, b := range base {
			if subjectIsSubsetMatch(o, b) {
				add(o)
				break
			}
		}
	}
	for _, b := range base {
		for _, o := range override {
			if subjectIsSubsetMatch(b, o) {
				add(b)
				break
			}
		}
	}
	return out
}

// unionStrings returns the deduplicated union of a and b.
func unionStrings(a, b jwt.StringList) jwt.StringList {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make(jwt.StringList, 0, len(a)+len(b))
	for _, s := range a {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	for _, s := range b {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// narrowResponse tightens a response permission. A response grant the verified
// user did not have cannot be added.
func narrowResponse(base, override *jwt.ResponsePermission) *jwt.ResponsePermission {
	if base == nil {
		return nil
	}
	out := &jwt.ResponsePermission{MaxMsgs: base.MaxMsgs, Expires: base.Expires}
	if override == nil {
		return out
	}
	out.MaxMsgs = int(NarrowCount(int64(base.MaxMsgs), int64(override.MaxMsgs)))
	out.Expires = time.Duration(NarrowExpiry(int64(base.Expires), int64(override.Expires)))
	return out
}

// NarrowExpiry returns the sooner of two expirations where 0 means "never". An
// override can only shorten the effective expiry, never extend it.
func NarrowExpiry(base, override int64) int64 {
	return narrowToward(base, override, 0)
}

// NarrowCount returns the more restrictive of two numeric limits where -1 means
// "unlimited" (the JWT no-limit sentinel). An override can lower a limit but never
// raise it.
func NarrowCount(base, override int64) int64 {
	return narrowToward(base, override, -1)
}

// narrowToward returns the more restrictive (smaller) of base and override, where
// the sentinel `unlimited` is treated as +infinity. The result is never larger
// than base, so an override can never raise a limit.
func narrowToward(base, override, unlimited int64) int64 {
	if override == unlimited {
		return base
	}
	if base == unlimited {
		return override
	}
	if override < base {
		return override
	}
	return base
}

func clonePermissions(p *jwt.Permissions) *jwt.Permissions {
	out := &jwt.Permissions{
		Pub: clonePermission(p.Pub),
		Sub: clonePermission(p.Sub),
	}
	if p.Resp != nil {
		out.Resp = &jwt.ResponsePermission{MaxMsgs: p.Resp.MaxMsgs, Expires: p.Resp.Expires}
	}
	return out
}

func clonePermission(p jwt.Permission) jwt.Permission {
	return jwt.Permission{Allow: cloneStrings(p.Allow), Deny: cloneStrings(p.Deny)}
}

func cloneStrings(s jwt.StringList) jwt.StringList {
	if s == nil {
		return nil
	}
	out := make(jwt.StringList, len(s))
	copy(out, s)
	return out
}

// --- vendored subject subset-match (copy of the unexported helpers in
// server/sublist.go; duplicated here to keep this package free of a server
// import). subjectIsSubsetMatch reports whether subject is a subset of test,
// e.g. "foo.*" is a subset of "foo.>" but not of "foo.bar".

const (
	pwc  = '*'
	fwc  = '>'
	tsep = '.'
)

func tokenizeSubjectIntoSlice(tts []string, subject string) []string {
	start := 0
	for i := 0; i < len(subject); i++ {
		if subject[i] == tsep {
			tts = append(tts, subject[start:i])
			start = i + 1
		}
	}
	tts = append(tts, subject[start:])
	return tts
}

func subjectIsSubsetMatch(subject, test string) bool {
	tsa := [32]string{}
	tts := tokenizeSubjectIntoSlice(tsa[:0], subject)
	return isSubsetMatch(tts, test)
}

func isSubsetMatch(tokens []string, test string) bool {
	tsa := [32]string{}
	tts := tokenizeSubjectIntoSlice(tsa[:0], test)
	return isSubsetMatchTokenized(tokens, tts)
}

func isSubsetMatchTokenized(tokens, test []string) bool {
	for i, t2 := range test {
		if i >= len(tokens) {
			return false
		}
		l := len(t2)
		if l == 0 {
			return false
		}
		if t2[0] == fwc && l == 1 {
			return true
		}
		t1 := tokens[i]

		l = len(t1)
		if l == 0 || t1[0] == fwc && l == 1 {
			return false
		}

		if t1[0] == pwc && len(t1) == 1 {
			m := t2[0] == pwc && len(t2) == 1
			if !m {
				return false
			}
			if i >= len(test) {
				return true
			}
			continue
		}
		if t2[0] != pwc && strings.Compare(t1, t2) != 0 {
			return false
		}
	}
	return len(tokens) == len(test)
}
