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

package authverify

import (
	"sort"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
)

func equalSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func pub(allow string, deny ...string) jwt.Permission {
	p := jwt.Permission{Allow: jwt.StringList{allow}}
	if len(deny) > 0 {
		p.Deny = jwt.StringList(deny)
	}
	return p
}

// The headline guarantee: an override allow broader than base cannot escalate.
func TestAuthVerifyNarrowAllowDropsEscalation(t *testing.T) {
	base := &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"foo.>"}}}
	override := &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"foo.bar", "baz.>"}}}

	got := NarrowPermissions(base, override)

	if !equalSet(got.Pub.Allow, []string{"foo.bar"}) {
		t.Fatalf("expected pub allow [foo.bar], got %v", got.Pub.Allow)
	}
}

// Override deny is unioned with base deny (deduped); adding a deny always narrows.
func TestAuthVerifyNarrowDenyUnion(t *testing.T) {
	base := &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{">"}, Deny: jwt.StringList{"secret.>"}}}
	override := &jwt.Permissions{Pub: jwt.Permission{Deny: jwt.StringList{"admin.>", "secret.>"}}}

	got := NarrowPermissions(base, override)

	if !equalSet(got.Pub.Deny, []string{"secret.>", "admin.>"}) {
		t.Fatalf("expected pub deny [secret.> admin.>], got %v", got.Pub.Deny)
	}
}

// Response permission can only be tightened.
func TestAuthVerifyNarrowResponsePermission(t *testing.T) {
	base := &jwt.Permissions{Resp: &jwt.ResponsePermission{MaxMsgs: 10, Expires: 5 * time.Second}}
	override := &jwt.Permissions{Resp: &jwt.ResponsePermission{MaxMsgs: 100, Expires: 2 * time.Second}}

	got := NarrowPermissions(base, override)

	if got.Resp == nil || got.Resp.MaxMsgs != 10 || got.Resp.Expires != 2*time.Second {
		t.Fatalf("expected response {10, 2s}, got %+v", got.Resp)
	}
}

// A negative override response limit means "unlimited" at enforcement
// (server enforces only when the limit is > 0), so it must not relax the
// verified user's concrete limit. Regression: a negative override survived
// narrowing and silently disabled the cap (an escalation).
func TestAuthVerifyNarrowResponseNegativeNoEscalation(t *testing.T) {
	base := &jwt.Permissions{Resp: &jwt.ResponsePermission{MaxMsgs: 5, Expires: 30 * time.Second}}
	override := &jwt.Permissions{Resp: &jwt.ResponsePermission{MaxMsgs: -2, Expires: -1}}

	got := NarrowPermissions(base, override)

	if got.Resp == nil || got.Resp.MaxMsgs != 5 || got.Resp.Expires != 30*time.Second {
		t.Fatalf("expected response {5, 30s} (negative override must not relax), got %+v", got.Resp)
	}
}

// A base response limit of 0 selects the server default (a small finite value),
// not "unlimited"; an override must not be able to raise it. Regression: base 0
// was treated as the unlimited sentinel so a larger override escalated the
// effective limit.
func TestAuthVerifyNarrowResponseZeroBaseNoEscalation(t *testing.T) {
	base := &jwt.Permissions{Resp: &jwt.ResponsePermission{MaxMsgs: 0, Expires: 0}}
	override := &jwt.Permissions{Resp: &jwt.ResponsePermission{MaxMsgs: 100, Expires: time.Hour}}

	got := NarrowPermissions(base, override)

	if got.Resp == nil || got.Resp.MaxMsgs != 0 || got.Resp.Expires != 0 {
		t.Fatalf("expected response {0, 0} (default preserved, override cannot raise), got %+v", got.Resp)
	}
}

// A response grant the verified user never had cannot be added.
func TestAuthVerifyNarrowResponsePermissionNotAdded(t *testing.T) {
	base := &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{">"}}}
	override := &jwt.Permissions{Resp: &jwt.ResponsePermission{MaxMsgs: 5, Expires: time.Second}}

	got := NarrowPermissions(base, override)

	if got.Resp != nil {
		t.Fatalf("expected no response permission granted, got %+v", got.Resp)
	}
}

// Expiry (unix seconds, 0 == never) can only be brought sooner.
func TestAuthVerifyNarrowExpiry(t *testing.T) {
	if got := NarrowExpiry(1000, 0); got != 1000 {
		t.Fatalf("override unset: expected 1000, got %d", got)
	}
	if got := NarrowExpiry(0, 500); got != 500 {
		t.Fatalf("base never: expected 500, got %d", got)
	}
	if got := NarrowExpiry(1000, 500); got != 500 {
		t.Fatalf("both set: expected 500, got %d", got)
	}
	if got := NarrowExpiry(1000, 5000); got != 1000 {
		t.Fatalf("later override: expected 1000 (clamped), got %d", got)
	}
}

// Numeric limits (-1 == unlimited): an override can lower but never raise.
func TestAuthVerifyNarrowCount(t *testing.T) {
	if got := NarrowCount(100, 10); got != 10 {
		t.Fatalf("lower: expected 10, got %d", got)
	}
	if got := NarrowCount(100, 1000); got != 100 {
		t.Fatalf("raise attempt: expected 100 (clamped), got %d", got)
	}
	if got := NarrowCount(100, -1); got != 100 {
		t.Fatalf("override unlimited: expected 100, got %d", got)
	}
	if got := NarrowCount(-1, 50); got != 50 {
		t.Fatalf("base unlimited: expected 50, got %d", got)
	}
}

// When the override allow is broader than base, the narrower base entry is kept
// (not dropped, which would leave an empty allow == allow-all).
func TestAuthVerifyNarrowAllowBaseNarrowerThanOverride(t *testing.T) {
	base := &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"app.foo"}}}
	override := &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"app.>"}}}

	got := NarrowPermissions(base, override)

	if !equalSet(got.Pub.Allow, []string{"app.foo"}) {
		t.Fatalf("expected pub allow [app.foo], got %v", got.Pub.Allow)
	}
}

// A disjoint override allow must not collapse to an empty (== allow-all) list,
// and must not keep base either: the service asked for subjects the user does
// not have, so nothing is allowed.
func TestAuthVerifyNarrowAllowDisjointDeniesAll(t *testing.T) {
	base := &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"app.>"}}}
	override := &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"other.>"}}}

	got := NarrowPermissions(base, override)

	if len(got.Pub.Allow) != 0 || !equalSet(got.Pub.Deny, []string{">"}) {
		t.Fatalf("expected deny-all (allow [], deny [>]), got allow %v deny %v", got.Pub.Allow, got.Pub.Deny)
	}
}

// Overlapping wildcards with no subset relation narrow to their exact
// intersection, not to all of base.
func TestAuthVerifyNarrowAllowOverlapIntersects(t *testing.T) {
	base := &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"foo.*.bar", "a.>"}}}
	override := &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"foo.baz.*", "a.b.*"}}}

	got := NarrowPermissions(base, override)

	if !equalSet(got.Pub.Allow, []string{"foo.baz.bar", "a.b.*"}) {
		t.Fatalf("expected pub allow [foo.baz.bar a.b.*], got %v", got.Pub.Allow)
	}
}

// A literal token that starts with '*' (e.g. "*bar") is not a wildcard.
func TestAuthVerifyNarrowStarPrefixedLiteralIsNotWildcard(t *testing.T) {
	base := &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"foo.*bar"}}}
	override := &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"foo.secret"}}}

	got := NarrowPermissions(base, override)

	if len(got.Pub.Allow) != 0 || !equalSet(got.Pub.Deny, []string{">"}) {
		t.Fatalf("literal *bar escalated: allow %v deny %v", got.Pub.Allow, got.Pub.Deny)
	}

	// The same literal still intersects with itself and with a real wildcard.
	override = &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"foo.*"}}}
	got = NarrowPermissions(base, override)
	if !equalSet(got.Pub.Allow, []string{"foo.*bar"}) {
		t.Fatalf("expected pub allow [foo.*bar], got %v", got.Pub.Allow)
	}
}

// An invalid base entry grants nothing on the server, so it must not grant
// anything through the intersection either.
func TestAuthVerifyNarrowInvalidBaseEntryGrantsNothing(t *testing.T) {
	base := &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"a.>.b", "c..d"}}}
	override := &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"a.x.y", "c.*.d"}}}

	got := NarrowPermissions(base, override)

	if len(got.Pub.Allow) != 0 || !equalSet(got.Pub.Deny, []string{">"}) {
		t.Fatalf("invalid base entry escalated: allow %v deny %v", got.Pub.Allow, got.Pub.Deny)
	}
}

// Queue subscribe permissions ("subject queue") keep the queue restriction.
func TestAuthVerifyNarrowQueuePermissions(t *testing.T) {
	base := &jwt.Permissions{Sub: jwt.Permission{Allow: jwt.StringList{"foo.> q1"}}}
	override := &jwt.Permissions{Sub: jwt.Permission{Allow: jwt.StringList{"foo.bar q2", "foo.baz"}}}

	got := NarrowPermissions(base, override)

	if !equalSet(got.Sub.Allow, []string{"foo.baz q1"}) {
		t.Fatalf("expected sub allow [foo.baz q1], got %v", got.Sub.Allow)
	}

	base = &jwt.Permissions{Sub: jwt.Permission{Allow: jwt.StringList{"foo.>"}}}
	override = &jwt.Permissions{Sub: jwt.Permission{Allow: jwt.StringList{"foo.bar q2"}}}
	got = NarrowPermissions(base, override)
	if !equalSet(got.Sub.Allow, []string{"foo.bar q2"}) {
		t.Fatalf("expected sub allow [foo.bar q2], got %v", got.Sub.Allow)
	}
}

// With response permissions and no publish allow list, the server allows only
// replies. An override must not turn that into an allow list.
func TestAuthVerifyNarrowResponseOnlyPublishNotWidened(t *testing.T) {
	base := &jwt.Permissions{Resp: &jwt.ResponsePermission{MaxMsgs: 1, Expires: time.Second}}
	override := &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"app.>"}}}

	got := NarrowPermissions(base, override)

	if len(got.Pub.Allow) != 0 {
		t.Fatalf("response-only publish widened to %v", got.Pub.Allow)
	}
	if got.Resp == nil {
		t.Fatalf("response permission lost")
	}
}

// Capstone: an override that tries to escalate on every dimension widens nothing.
func TestAuthVerifyNarrowEscalationFullyNeutralized(t *testing.T) {
	base := &jwt.Permissions{
		Pub:  pub("app.>", "app.secret.>"),
		Sub:  pub("app.>"),
		Resp: &jwt.ResponsePermission{MaxMsgs: 5, Expires: time.Second},
	}
	override := &jwt.Permissions{
		Pub:  pub(">"),       // try to allow everything
		Sub:  pub("other.>"), // try an unrelated tree
		Resp: &jwt.ResponsePermission{MaxMsgs: 1000, Expires: time.Hour},
	}

	got := NarrowPermissions(base, override)

	if !equalSet(got.Pub.Allow, []string{"app.>"}) {
		t.Fatalf("pub allow escalated: %v", got.Pub.Allow)
	}
	if !equalSet(got.Pub.Deny, []string{"app.secret.>"}) {
		t.Fatalf("pub deny lost: %v", got.Pub.Deny)
	}
	if len(got.Sub.Allow) != 0 || !equalSet(got.Sub.Deny, []string{">"}) {
		t.Fatalf("disjoint sub override not denied: allow %v deny %v", got.Sub.Allow, got.Sub.Deny)
	}
	if got.Resp.MaxMsgs != 5 || got.Resp.Expires != time.Second {
		t.Fatalf("response escalated: %+v", got.Resp)
	}
}

// NarrowPermissions must not mutate base.
func TestAuthVerifyNarrowDoesNotMutateBase(t *testing.T) {
	base := &jwt.Permissions{Pub: pub("app.>", "app.secret.>")}
	override := &jwt.Permissions{Pub: pub("app.foo", "app.other.>")}

	_ = NarrowPermissions(base, override)

	if !equalSet(base.Pub.Allow, []string{"app.>"}) {
		t.Fatalf("base allow mutated: %v", base.Pub.Allow)
	}
	if !equalSet(base.Pub.Deny, []string{"app.secret.>"}) {
		t.Fatalf("base deny mutated: %v", base.Pub.Deny)
	}
}

// A nil override yields an equivalent but independent copy.
func TestAuthVerifyNarrowNilOverrideClonesBase(t *testing.T) {
	base := &jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"app.>"}}}

	got := NarrowPermissions(base, nil)

	if got == base {
		t.Fatalf("expected a distinct copy")
	}
	if !equalSet(got.Pub.Allow, []string{"app.>"}) {
		t.Fatalf("expected pub allow [app.>], got %v", got.Pub.Allow)
	}
	got.Pub.Allow[0] = "mutated"
	if base.Pub.Allow[0] != "app.>" {
		t.Fatalf("clone shares backing array with base")
	}
}

// Publish and Subscribe narrow independently.
func TestAuthVerifyNarrowPublishSubscribeIndependent(t *testing.T) {
	base := &jwt.Permissions{Pub: pub("app.>"), Sub: pub("app.>")}
	override := &jwt.Permissions{Pub: pub("app.foo")} // only publish

	got := NarrowPermissions(base, override)

	if !equalSet(got.Pub.Allow, []string{"app.foo"}) {
		t.Fatalf("expected pub allow [app.foo], got %v", got.Pub.Allow)
	}
	if !equalSet(got.Sub.Allow, []string{"app.>"}) {
		t.Fatalf("expected sub allow [app.>] unchanged, got %v", got.Sub.Allow)
	}
}
