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
	"strings"
	"testing"
)

func TestAuthGrantPrefixCompile(t *testing.T) {
	for _, subject := range []string{
		"", ".foo*", "foo*.", "foo*..bar", "foo bar*", "foo*.bar baz",
		"foo*.bar\t", "foo*.bar\n", "foo*.bar\r", "foo*.bar\f",
		"foo", "foo.*", "foo.>", "*", ">", "foo*bar", "foo**", "**",
		"*foo", "fo>o*", "foo>*", "foo*.bar**", "foo*.>.bar", "foo*.>.>",
	} {
		t.Run(subject, func(t *testing.T) {
			rules, err := compileGrantPrefixRules([]string{subject})
			if err == nil || rules != nil {
				t.Fatalf("Expected invalid rule %q to reject, got %v, %v", subject, rules, err)
			}
		})
	}
	for _, subjects := range [][]string{nil, {}, {"foo*"}, {"*.foo*.>"}, {"foo*.bar*.baz"}, {"é*.尾*"}, {"foo*.foo*bar"}, {"foo*.foo>bar"}} {
		if _, err := compileGrantPrefixRules(subjects); err != nil {
			t.Fatalf("Valid rules %q rejected: %v", subjects, err)
		}
	}
	rules, err := compileGrantPrefixRules([]string{"foo*", "invalid"})
	if err == nil || rules != nil {
		t.Fatal("Expected the entire list to reject when one rule is invalid")
	}
	subjects := make([]string, maxGrantPrefixRules+1)
	for i := range subjects {
		subjects[i] = "foo*"
	}
	if _, err := compileGrantPrefixRules(subjects[:maxGrantPrefixRules]); err != nil {
		t.Fatalf("Budget boundary rejected: %v", err)
	}
	if _, err := compileGrantPrefixRules(subjects); err == nil {
		t.Fatal("Budget overflow accepted")
	}
}

func TestAuthGrantPrefixMatch(t *testing.T) {
	for _, test := range []struct {
		rule    string
		subject string
		allowed bool
	}{
		{"$JS.API.STREAM.INFO.KV_device-config-*", "$JS.API.STREAM.INFO.KV_device-config-d501", true},
		{"$JS.API.STREAM.INFO.KV_device-config-*", "$JS.API.STREAM.INFO.KV_other", false},
		{"$JS.API.STREAM.INFO.KV_device-config-*", "$JS.API.STREAM.INFO.KV_device-config-", false},
		{"foo*", "foobar", true},
		{"foo*", "foo", false},
		{"foo*", "FooBar", false},
		{"foo*", "barfoo", false},
		{"foo*", "foobar.baz", false},
		{"foo*", "*", false},
		{"foo*", ">", false},
		{"foo*.>", "foobar", false},
		{"foo*.>", "foobar.baz", true},
		{"foo*.>", "foobar.>", true},
		{"foo*.>", "foobar.*", true},
		{"foo*.>", "foobar.*.>", true},
		{"foo*.>", "*.>", false},
		{"foo*.>", ">", false},
		{"*.foo*", "*.foobar", true},
		{"*.foo*", ">", false},
		{"*.foo*", "a.>", false},
		{"foo*.bar", "foobar.*", false},
		{"foo*.*", "foobar.*", true},
		{"foo*.*", "foobar.>", false},
		{"foo*.*.>", "foobar.*.>", true},
		{"foo*.*.>", "foobar.>", false},
		{"foo*.*.>", "foobar.bar", false},
		{"foo*.*.>", "foobar.bar.baz", true},
		{"$KV.device-config-*.>", "$KV.device-config-d1.>", true},
		{"$KV.device-config-*.>", "$KV.*.>", false},
		{"$KV.device-config-*.>", "$KV.>", false},
		{"foo*.bar*", "food.barn", true},
		{"foo*.bar*", "food.bar", false},
		{"foo*.bar*", "food.*", false},
		{"foo*.foo*bar", "food.foo*bar", true},
		{"foo*.foo*bar", "food.fooxbar", false},
		{"foo*.foo>bar", "food.foo>bar", true},
		{"foo*.foo>bar", "food.fooxbar", false},
		{"foo*.bar>", "food.bar>", true},
		{"é*.尾*", "élan.尾部", true},
		{"é*.尾*", "é.尾部", false},
		{strings.Repeat("x.", 40) + "foo*", strings.Repeat("x.", 40) + "foobar", true},
	} {
		t.Run(test.rule+"/"+test.subject, func(t *testing.T) {
			rules, err := compileGrantPrefixRules([]string{test.rule})
			require_NoError(t, err)
			if got := rules.allows(test.subject); got != test.allowed {
				t.Fatalf("Rule %q allows %q: got %v, want %v", test.rule, test.subject, got, test.allowed)
			}
		})
	}
	var empty grantPrefixRules
	require_False(t, empty.allows("foo"))
	rules, err := compileGrantPrefixRules([]string{"foo*", "bar*"})
	require_NoError(t, err)
	require_True(t, rules.allows("barbaz"))
}

func TestAuthGrantPrefixPermissions(t *testing.T) {
	for _, kind := range []int{CLIENT, LEAF} {
		for _, standardAllow := range []bool{false, true} {
			c := &client{kind: kind}
			perms := &Permissions{
				Publish:   &SubjectPermission{Deny: []string{"pub-denied"}},
				Subscribe: &SubjectPermission{Deny: []string{"sub-denied", "sub-queue workers"}},
			}
			if standardAllow {
				perms.Publish.Allow = []string{"standard.pub"}
				perms.Subscribe.Allow = []string{"standard.sub"}
			}
			c.setPermissions(perms)
			var err error
			c.perms.pub.prefix, err = compileGrantPrefixRules([]string{"pub-*"})
			require_NoError(t, err)
			c.perms.sub.prefix, err = compileGrantPrefixRules([]string{"sub-*", "sub-*.>"})
			require_NoError(t, err)
			for _, test := range []struct {
				subject string
				allowed bool
			}{
				{"pub-yes", true}, {"pub-", false}, {"pub-denied", false},
				{"other", false}, {"standard.pub", standardAllow},
			} {
				for repeat := 0; repeat < 2; repeat++ {
					if got := c.pubAllowed(test.subject); got != test.allowed {
						t.Fatalf("kind=%d standard=%v publish %q got %v, want %v", kind, standardAllow, test.subject, got, test.allowed)
					}
				}
			}
			for _, test := range []struct {
				subject, queue string
				allowed        bool
			}{
				{"sub-yes", "", true}, {"sub-yes", "any-queue", true},
				{"sub-", "", false}, {"sub-denied", "", false},
				{"other", "", false}, {"standard.sub", "", standardAllow},
				{"sub-yes.>", "", true}, {"*.>", "", kind == LEAF && standardAllow}, {">", "", kind == LEAF && standardAllow},
				{"sub-queue", "workers", false}, {"sub-queue", "other", true},
			} {
				if got := c.canSubscribeInternal(test.subject, test.queue); got != test.allowed {
					t.Fatalf("kind=%d standard=%v subscribe %q queue %q got %v, want %v", kind, standardAllow, test.subject, test.queue, got, test.allowed)
				}
			}
		}
	}
}

func TestAuthGrantPrefixLeafSwap(t *testing.T) {
	s, err := NewServer(DefaultOptions())
	require_NoError(t, err)
	defer s.Shutdown()
	c := &client{kind: LEAF, srv: s, leaf: &leaf{}, acc: s.globalAccount(), opts: defaultOpts}
	c.initClient()
	defer c.closeConnection(ClientClosed)
	c.setPermissions(&Permissions{
		Publish:   &SubjectPermission{Allow: []string{"standard.pub"}},
		Subscribe: &SubjectPermission{Allow: []string{"standard.sub"}},
	})
	c.perms.pub.prefix, err = compileGrantPrefixRules([]string{"pub-*"})
	require_NoError(t, err)
	c.perms.sub.prefix, err = compileGrantPrefixRules([]string{"sub-*"})
	require_NoError(t, err)
	require_NoError(t, c.processLeafNodeConnect(s, []byte(`{"name":"grant-prefix-leaf"}`), ""))
	for _, subject := range []string{"sub-yes", "standard.sub"} {
		require_True(t, c.pubAllowed(subject))
		require_False(t, c.canSubscribeInternal(subject))
	}
	for _, subject := range []string{"pub-yes", "standard.pub"} {
		require_True(t, c.canSubscribeInternal(subject))
		require_False(t, c.pubAllowed(subject))
	}
}
