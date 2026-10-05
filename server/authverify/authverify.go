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
// package) so it can be imported by the server without an import cycle.
package authverify

import (
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
)

// NarrowPermissions returns a new permission set that restricts base by override
// such that any subject action allowed by the result is also allowed by base: the
// override can only narrow, never escalate. A nil override returns an independent
// clone of base. base must be the permissions in effect for the user (for example,
// the account default permissions when the user JWT has none).
func NarrowPermissions(base, override *jwt.Permissions) *jwt.Permissions {
	if base == nil {
		base = &jwt.Permissions{}
	}
	out := clonePermissions(base)
	if override == nil {
		return out
	}
	// With a response permission and no publish allow list, the server allows
	// only replies (see validateResponsePermissions). An empty allow list then
	// does not mean "allow all".
	pubAllowsAll := len(base.Pub.Allow) == 0 && base.Resp == nil
	out.Pub = narrowPermission(base.Pub, override.Pub, pubAllowsAll)
	out.Sub = narrowPermission(base.Sub, override.Sub, len(base.Sub.Allow) == 0)
	out.Resp = narrowResponse(base.Resp, override.Resp)
	return out
}

// narrowPermission restricts a single pub or sub permission: the allow set is
// intersected (never broadened) and the deny set is unioned (always narrows).
// allowsAll reports whether an empty base allow list means "allow all".
func narrowPermission(base, override jwt.Permission, allowsAll bool) jwt.Permission {
	out := clonePermission(base)
	// Allow: intersection. An empty override allow means "no allow restriction".
	if len(override.Allow) > 0 {
		if allowsAll {
			// base allowed everything -> restrict to the override's set.
			out.Allow = cloneStrings(override.Allow)
		} else if len(base.Allow) > 0 {
			kept := intersectAllow(base.Allow, override.Allow)
			if len(kept) > 0 {
				out.Allow = kept
			} else {
				// No subject is allowed by both. An empty allow list means
				// "allow all", so deny everything explicitly.
				out.Allow = nil
				out.Deny = unionStrings(out.Deny, jwt.StringList{">"})
			}
		}
		// Otherwise base allows nothing on its own allow list, and the
		// override cannot add to it.
	}
	// Deny: union (adding denies always narrows), deduplicated.
	if len(override.Deny) > 0 {
		out.Deny = unionStrings(out.Deny, override.Deny)
	}
	return out
}

// intersectAllow returns the exact intersection of two allow lists: for every
// pair of entries, the subjects (and queue) allowed by both. Each result entry is
// within some base entry, so the result is always a subset of base.
func intersectAllow(base, override jwt.StringList) jwt.StringList {
	var out jwt.StringList
	seen := make(map[string]struct{})
	for _, o := range override {
		for _, b := range base {
			e, ok := intersectEntry(b, o)
			if !ok {
				continue
			}
			if _, dup := seen[e]; dup {
				continue
			}
			seen[e] = struct{}{}
			out = append(out, e)
		}
	}
	return out
}

// intersectEntry intersects two permission entries of the form "subject" or
// "subject queue". An entry without a queue allows any queue. Entries with
// different queues do not intersect.
func intersectEntry(a, b string) (string, bool) {
	as, aq, ok := splitEntry(a)
	if !ok {
		return "", false
	}
	bs, bq, ok := splitEntry(b)
	if !ok {
		return "", false
	}
	q := aq
	if q == "" {
		q = bq
	} else if bq != "" && bq != aq {
		return "", false
	}
	s, ok := intersectSubject(as, bs)
	if !ok {
		return "", false
	}
	if q != "" {
		s += " " + q
	}
	return s, true
}

// splitEntry splits a permission entry into subject and optional queue.
func splitEntry(e string) (string, string, bool) {
	f := strings.Fields(e)
	switch len(f) {
	case 1:
		return f[0], "", true
	case 2:
		return f[0], f[1], true
	}
	return "", "", false
}

// intersectSubject returns a subject that matches exactly the subjects matched
// by both a and b, or false if no subject matches both. Only a token that is
// exactly "*" or ">" is a wildcard; a token such as "*bar" is a literal.
func intersectSubject(a, b string) (string, bool) {
	ta := strings.Split(a, ".")
	tb := strings.Split(b, ".")
	out := make([]string, 0, max(len(ta), len(tb)))
	for i := 0; ; i++ {
		if i == len(ta) || i == len(tb) {
			if len(ta) != len(tb) {
				return "", false
			}
			return strings.Join(out, "."), true
		}
		x, y := ta[i], tb[i]
		// Empty tokens and a ">" before the last token make an invalid
		// subject, which the server never matches.
		if x == "" || y == "" || (x == ">" && i != len(ta)-1) || (y == ">" && i != len(tb)-1) {
			return "", false
		}
		switch {
		case x == ">":
			// ">" matches one or more tokens: the rest of b (never empty here).
			return strings.Join(append(out, tb[i:]...), "."), true
		case y == ">":
			return strings.Join(append(out, ta[i:]...), "."), true
		case x == "*":
			out = append(out, y)
		case y == "*":
			out = append(out, x)
		case x == y:
			out = append(out, x)
		default:
			return "", false
		}
	}
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
	out.MaxMsgs = int(narrowRespLimit(int64(base.MaxMsgs), int64(override.MaxMsgs)))
	out.Expires = time.Duration(narrowRespLimit(int64(base.Expires), int64(override.Expires)))
	return out
}

// narrowRespLimit returns the more restrictive of two response-permission limits
// (MaxMsgs or Expires) in the server's enforcement domain. There, a limit is
// only applied when it is strictly positive: a negative value means "unlimited"
// and 0 selects the server default (a small finite value). An override can
// therefore only tighten the verified base: it may lower a positive base, and it
// may replace an unlimited (negative) base with a concrete positive limit, but it
// can never relax base. A 0 base is left untouched so the server default applies
// and an override cannot raise it. This differs from NarrowCount/NarrowExpiry,
// whose single-sentinel domains do not match these per-field "<= 0 == no limit"
// semantics and would let a non-positive override escalate.
func narrowRespLimit(base, override int64) int64 {
	// A non-positive override imposes no concrete limit, so it can never tighten
	// base: keep base.
	if override <= 0 {
		return base
	}
	// override is a concrete positive limit. It tightens an unlimited (negative)
	// base or a larger positive base; a 0 base keeps the (smaller) default.
	if base < 0 {
		return override
	}
	if base > 0 && override < base {
		return override
	}
	return base
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
