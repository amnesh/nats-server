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
	"strings"
)

const maxGrantPrefixRules = 4096

type grantPrefixToken struct {
	value  string
	prefix bool
}

type grantPrefixRules [][]grantPrefixToken

func compileGrantPrefixRules(subjects []string) (grantPrefixRules, error) {
	if len(subjects) > maxGrantPrefixRules {
		return nil, fmt.Errorf("grant prefix rules exceed limit of %d", maxGrantPrefixRules)
	}
	var rules grantPrefixRules
	for _, subject := range subjects {
		if !IsValidSubject(subject) {
			return nil, fmt.Errorf("invalid grant prefix rule %q", subject)
		}
		tokens := strings.Split(subject, tsep)
		rule := make([]grantPrefixToken, 0, len(tokens))
		hasPrefix := false
		for _, token := range tokens {
			ct := grantPrefixToken{value: token}
			switch {
			case token == "*", token == ">":
			case strings.HasSuffix(token, "*"):
				if strings.ContainsAny(token[:len(token)-1], "*>") {
					return nil, fmt.Errorf("invalid grant prefix rule %q", subject)
				}
				ct.value = token[:len(token)-1]
				ct.prefix = true
				hasPrefix = true
			}
			rule = append(rule, ct)
		}
		if !hasPrefix {
			return nil, fmt.Errorf("grant prefix rule %q has no token prefix", subject)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (rules grantPrefixRules) allows(subject string) bool {
	if len(rules) == 0 {
		return false
	}
	var buf [32]string
	tokens := tokenizeSubjectIntoSlice(buf[:0], subject)
	for _, rule := range rules {
		if grantPrefixRuleMatches(tokens, rule) {
			return true
		}
	}
	return false
}

func grantPrefixRuleMatches(tokens []string, rule []grantPrefixToken) bool {
	for i, token := range rule {
		if i >= len(tokens) {
			return false
		}
		if token.value == ">" && !token.prefix {
			return true
		}
		subjectToken := tokens[i]
		if subjectToken == ">" {
			return false
		}
		if token.prefix {
			if subjectToken == "*" || len(subjectToken) <= len(token.value) || !strings.HasPrefix(subjectToken, token.value) {
				return false
			}
		} else if token.value != "*" && subjectToken != token.value {
			return false
		}
	}
	return len(tokens) == len(rule)
}

func (rules grantPrefixRules) intersects(subject string) bool {
	var buf [32]string
	tokens := tokenizeSubjectIntoSlice(buf[:0], subject)
	for _, rule := range rules {
		match := true
		for i, token := range rule {
			if i >= len(tokens) {
				match = false
				break
			}
			if token.value == ">" && !token.prefix || tokens[i] == ">" {
				return true
			}
			if token.prefix {
				if tokens[i] != "*" && (len(tokens[i]) <= len(token.value) || !strings.HasPrefix(tokens[i], token.value)) {
					match = false
					break
				}
			} else if token.value != "*" && tokens[i] != "*" && token.value != tokens[i] {
				match = false
				break
			}
		}
		if match && len(tokens) == len(rule) {
			return true
		}
	}
	return false
}
