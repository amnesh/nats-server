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

	"github.com/nats-io/jwt/v2"
)

// Permission template macros (fork feature).
//
// A scoped signing key template entry that is exactly one macro token, for
// example {{kvrw(tag(kv))}}, expands into the full set of subjects a client
// needs to use one JetStream KV bucket or Object Store bucket. The macro
// argument is a value-producing template operation (tag(x), account-tag(x),
// name(), subject(), account-name(), account-subject()) or a literal bucket
// name. One subject set is emitted per resolved value.
//
// Macros are expanded by expandPermissionMacros, which runs inside
// processUserPermissionsTemplate before the upstream template pass. Entries
// that are not macros pass through untouched, so templates without macros
// behave exactly as upstream.
//
// The subjects emitted depend on the list the macro appears in:
//
//   - In a publish list (allow or deny) the macro emits the JetStream API
//     subjects for the bucket's backing stream. Read/write macros add the
//     bucket's data subject and the stream purge API.
//   - In a subscribe list the macro emits only the bucket's data subject.
//
// Inbox subjects (for JetStream API replies) and bucket create/delete APIs
// are deliberately not part of any macro.

type permMacro struct {
	streamPrefix  string // Prefix of the backing stream name, e.g. "KV_".
	subjectPrefix string // Prefix of the data subjects, e.g. "$KV".
	write         bool   // Whether the macro grants writes.
}

var permMacros = map[string]permMacro{
	"kvro":  {streamPrefix: "KV_", subjectPrefix: "$KV", write: false},
	"kvrw":  {streamPrefix: "KV_", subjectPrefix: "$KV", write: true},
	"objro": {streamPrefix: "OBJ_", subjectPrefix: "$O", write: false},
	"objrw": {streamPrefix: "OBJ_", subjectPrefix: "$O", write: true},
}

// Publish subjects a client needs to read a bucket. The verb is the backing
// stream name. The set covers the nats.go legacy and new JetStream APIs:
// stream info, message get (direct and non-direct), ordered consumers
// (push and pull), and both flow control reply formats.
var permMacroReadPubSubjects = []string{
	"$JS.API.STREAM.INFO.%s",
	"$JS.API.STREAM.MSG.GET.%s",
	"$JS.API.DIRECT.GET.%s",
	"$JS.API.DIRECT.GET.%s.>",
	"$JS.API.CONSUMER.CREATE.%s",
	"$JS.API.CONSUMER.CREATE.%s.>",
	"$JS.API.CONSUMER.INFO.%s.>",
	"$JS.API.CONSUMER.DELETE.%s.>",
	"$JS.API.CONSUMER.MSG.NEXT.%s.>",
	"$JS.FC.%s.>",
	"$JS.FC.*.*.%s.>",
}

// Additional publish subjects a client needs to write a bucket, besides the
// data subject itself. Purge is used by KV PurgeDeletes and Object Store
// Put/Delete. The verb is the backing stream name.
var permMacroWritePubSubjects = []string{
	"$JS.API.STREAM.PURGE.%s",
}

// subjects returns the subjects the macro emits for one bucket.
func (m permMacro) subjects(bucket string, isSub bool) []string {
	data := m.subjectPrefix + "." + bucket + ".>"
	if isSub {
		return []string{data}
	}
	stream := m.streamPrefix + bucket
	out := make([]string, 0, len(permMacroReadPubSubjects)+len(permMacroWritePubSubjects)+1)
	for _, t := range permMacroReadPubSubjects {
		out = append(out, fmt.Sprintf(t, stream))
	}
	if m.write {
		out = append(out, data)
		for _, t := range permMacroWritePubSubjects {
			out = append(out, fmt.Sprintf(t, stream))
		}
	}
	return out
}

// parsePermMacro checks whether op, the trimmed content of one {{...}}
// token, is a macro call and returns the macro and its raw argument.
func parsePermMacro(op string) (permMacro, string, bool) {
	i := strings.IndexByte(op, '(')
	if i <= 0 || !strings.HasSuffix(op, ")") {
		return permMacro{}, _EMPTY_, false
	}
	m, ok := permMacros[strings.ToLower(strings.TrimSpace(op[:i]))]
	if !ok {
		return permMacro{}, _EMPTY_, false
	}
	return m, strings.TrimSpace(op[i+1 : len(op)-1]), true
}

// permMacroTagKey returns the key of a tag(key) or account-tag(key) style
// argument when arg has the given call prefix.
func permMacroTagKey(arg, call string) (string, bool) {
	if len(arg) <= len(call) || !strings.EqualFold(arg[:len(call)], call) || !strings.HasSuffix(arg, ")") {
		return _EMPTY_, false
	}
	return strings.TrimSpace(arg[len(call) : len(arg)-1]), true
}

// permMacroArgValues resolves a macro argument to the list of bucket names.
// The second result is false when the argument is not a known operation.
func permMacroArgValues(arg string, ujwt *jwt.UserClaims, acc *Account) ([]string, bool) {
	switch {
	case strings.EqualFold(arg, "name()"):
		return []string{ujwt.Name}, true
	case strings.EqualFold(arg, "subject()"):
		return []string{ujwt.Subject}, true
	case strings.EqualFold(arg, "account-name()"):
		acc.mu.RLock()
		name := acc.nameTag
		acc.mu.RUnlock()
		return []string{name}, true
	case strings.EqualFold(arg, "account-subject()"):
		return []string{ujwt.IssuerAccount}, true
	}
	var tags jwt.TagList
	var key string
	if k, ok := permMacroTagKey(arg, "account-tag("); ok {
		acc.mu.RLock()
		tags = acc.tags
		acc.mu.RUnlock()
		key = k
	} else if k, ok := permMacroTagKey(arg, "tag("); ok {
		tags = ujwt.Tags
		key = k
	} else if arg == _EMPTY_ || strings.ContainsAny(arg, "()") {
		return nil, false
	} else {
		// A literal bucket name.
		return []string{arg}, true
	}
	if key == _EMPTY_ {
		return nil, false
	}
	prefix := strings.ToLower(key) + ":"
	var values []string
	for _, tag := range tags {
		if v, ok := strings.CutPrefix(tag, prefix); ok {
			values = append(values, v)
		}
	}
	return values, true
}

// isValidPermMacroBucket reports whether a resolved macro value is a bucket
// name a macro may expand. The rule is the one the official clients enforce
// when they create a bucket: one or more of [A-Za-z0-9_-]. It is stricter than
// the server's stream name rule on purpose: the emitted subjects go through
// the upstream template pass afterwards, so a value must not be able to carry
// a template token ({{...}}), a wildcard, or a subject separator.
func isValidPermMacroBucket(name string) bool {
	if name == _EMPTY_ {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// expandPermMacroList replaces macro entries in one permission list by the
// subjects they expand to. Other entries are kept as they are. When
// failOnBadSubject is set (deny lists), an argument that resolves to no
// value or to an invalid bucket name is an error; otherwise such values are
// skipped, which mirrors how upstream treats unresolved tags.
func expandPermMacroList(list jwt.StringList, isSub, failOnBadSubject bool, ujwt *jwt.UserClaims, acc *Account) (jwt.StringList, error) {
	trimOp := func(tk string) string {
		return strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(tk, "{{"), "}}"))
	}
	hasMacro := false
	for _, entry := range list {
		if !strings.Contains(entry, "{{") {
			continue
		}
		for _, tk := range mustacheRE.FindAllString(entry, -1) {
			if _, _, ok := parsePermMacro(trimOp(tk)); ok {
				hasMacro = true
				break
			}
		}
		if hasMacro {
			break
		}
	}
	if !hasMacro {
		return list, nil
	}
	out := make(jwt.StringList, 0, len(list))
	for _, entry := range list {
		tokens := mustacheRE.FindAllString(entry, -1)
		macroTokens := 0
		for _, tk := range tokens {
			if _, _, ok := parsePermMacro(trimOp(tk)); ok {
				macroTokens++
			}
		}
		if macroTokens == 0 {
			out = append(out, entry)
			continue
		}
		if macroTokens > 1 || len(tokens) > 1 || strings.TrimSpace(entry) != tokens[0] {
			return nil, fmt.Errorf("template macro in %q must be the whole entry", entry)
		}
		op := trimOp(tokens[0])
		m, arg, _ := parsePermMacro(op)
		values, ok := permMacroArgValues(arg, ujwt, acc)
		if !ok {
			return nil, fmt.Errorf("template operation in %q: %q is not defined", entry, op)
		}
		if len(values) == 0 && failOnBadSubject {
			return nil, fmt.Errorf("generated invalid subject %q: %q is not defined", entry, arg)
		}
		for _, v := range values {
			if !isValidPermMacroBucket(v) {
				if failOnBadSubject {
					return nil, fmt.Errorf("generated invalid subject %q: %q is not a valid bucket name", entry, v)
				}
				continue
			}
			subjects := m.subjects(v, isSub)
			if len(out) > maxPermTemplateSubjectExpansions-len(subjects) {
				return nil, fmt.Errorf("%w: %d", errPermTemplateExpansionLimit, maxPermTemplateSubjectExpansions)
			}
			out = append(out, subjects...)
		}
	}
	return out, nil
}

// expandPermissionMacros expands permission macros in all four permission
// lists. It is called from processUserPermissionsTemplate after the
// fail-closed bookkeeping and before the upstream template pass, so a macro
// that resolves to nothing in an allow list still results in a "deny >".
func expandPermissionMacros(lim jwt.UserPermissionLimits, ujwt *jwt.UserClaims, acc *Account) (jwt.UserPermissionLimits, error) {
	var err error
	if lim.Permissions.Sub.Allow, err = expandPermMacroList(lim.Permissions.Sub.Allow, true, false, ujwt, acc); err != nil {
		return jwt.UserPermissionLimits{}, err
	} else if lim.Permissions.Sub.Deny, err = expandPermMacroList(lim.Permissions.Sub.Deny, true, true, ujwt, acc); err != nil {
		return jwt.UserPermissionLimits{}, err
	} else if lim.Permissions.Pub.Allow, err = expandPermMacroList(lim.Permissions.Pub.Allow, false, false, ujwt, acc); err != nil {
		return jwt.UserPermissionLimits{}, err
	} else if lim.Permissions.Pub.Deny, err = expandPermMacroList(lim.Permissions.Pub.Deny, false, true, ujwt, acc); err != nil {
		return jwt.UserPermissionLimits{}, err
	}
	return lim, nil
}
