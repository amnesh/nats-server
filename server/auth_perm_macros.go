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
// needs for one JetStream resource: a KV bucket, an Object Store bucket, a
// plain stream, or one consumer of a stream. Each macro argument is a
// value-producing template operation (tag(x), account-tag(x), name(),
// subject(), account-name(), account-subject()) or a literal name.
//
// Arguments are positional and separated by commas at parenthesis depth zero,
// for example {{jsconsumer(orders, tag(worker))}}. Every argument resolves to
// a list of values, and the macro emits one subject set per element of the
// cartesian product of those lists, first argument first. {{jsinfo()}} takes
// no argument.
//
// Every macro also accepts one trailing named argument, domain=VALUE, for a
// remote JetStream domain the client reaches through a leaf node, for example
// {{kvrw(tag(kv), domain=hub)}}. The value resolves like a positional
// argument and is the innermost loop of the cartesian product. Without it the
// macro covers the server's own JetStream, which is what a local client needs.
//
// Macros are expanded by expandPermissionMacros, which runs inside
// processUserPermissionsTemplate before the upstream template pass. Entries
// that are not macros pass through untouched, so templates without macros
// behave exactly as upstream.
//
// The subjects emitted depend on the list the macro appears in:
//
//   - In a publish list (allow or deny) a macro emits the JetStream API
//     subjects for the resource's stream. Levels are cumulative: read,
//     read+write, read+write+admin.
//   - In a subscribe list a bucket macro emits only the bucket's data
//     subject. Stream macros, consumer macros and jsinfo are errors there,
//     because a stream has no derivable data subject.
//
// Inbox subjects (for JetStream API replies) are deliberately not part of
// any macro. The design is documented in
// docs/superpowers/specs/2026-09-17-permission-template-macros-v2-design.md.

type permMacro struct {
	streamPrefix  string // Prefix of the backing stream name, e.g. "KV_"; empty for plain streams.
	subjectPrefix string // Prefix of the data subjects, e.g. "$KV"; empty when there is no data subject.
	dataViaAPI    bool   // The data publish subject of a remote domain goes through that domain's API prefix.
	args          int    // Number of positional arguments the macro takes.
	write         bool   // Grants writes: purge and, for buckets, the data subject.
	admin         bool   // Grants stream management.
	info          bool   // Account-level JetStream discovery, no resource.
	consumer      bool   // Grants the use of one named consumer of the stream.
	consumerAdmin bool   // Grants the management of that one consumer.
}

var permMacros = map[string]permMacro{
	"kvro":            {streamPrefix: "KV_", subjectPrefix: "$KV", dataViaAPI: true, args: 1},
	"kvrw":            {streamPrefix: "KV_", subjectPrefix: "$KV", dataViaAPI: true, args: 1, write: true},
	"kvadmin":         {streamPrefix: "KV_", subjectPrefix: "$KV", dataViaAPI: true, args: 1, write: true, admin: true},
	"objro":           {streamPrefix: "OBJ_", subjectPrefix: "$O", args: 1},
	"objrw":           {streamPrefix: "OBJ_", subjectPrefix: "$O", args: 1, write: true},
	"objadmin":        {streamPrefix: "OBJ_", subjectPrefix: "$O", args: 1, write: true, admin: true},
	"jsread":          {args: 1},
	"jsadmin":         {args: 1, write: true, admin: true},
	"jsinfo":          {args: 0, info: true},
	"jsconsumer":      {args: 2, consumer: true},
	"jsconsumeradmin": {args: 2, consumer: true, consumerAdmin: true},
}

// Placeholders of the subject templates below. {stream} and {consumer} are
// replaced by the resolved resource names, {api} by the JetStream API prefix
// and {dom} by the domain token of the v2 ack and flow control formats.
const (
	permMacroStream   = "{stream}"
	permMacroConsumer = "{consumer}"
	permMacroAPI      = "{api}"
	permMacroDom      = "{dom}"
)

// permMacroLocalAPI is the JetStream API prefix of the server's own domain,
// which is what {api} becomes when the macro carries no domain argument.
const permMacroLocalAPI = "$JS.API"

// permMacroDomainArg is the only named argument the grammar defines.
const permMacroDomainArg = "domain"

// Publish subjects a client needs to consume a stream. The set covers the
// nats.go legacy and new JetStream APIs: stream info, message get (direct
// and non-direct), consumer management on that stream, pull requests, and
// the v1 and v2 ack and flow control reply formats.
//
// The ack and flow control patterns use exact token counts on purpose. The
// v1 ack subject has 9 tokens with the stream name third, the v2 ack subject
// has 11 or more tokens with the stream name fifth. A pattern with a trailing
// ">" for one format could match the other format for another stream (for
// example when a stream name is numeric and equals a v1 delivered count).
var permMacroReadPubSubjects = []string{
	"{api}.STREAM.INFO.{stream}",
	"{api}.STREAM.MSG.GET.{stream}",
	"{api}.DIRECT.GET.{stream}",
	"{api}.DIRECT.GET.{stream}.>",
	"{api}.CONSUMER.CREATE.{stream}",
	"{api}.CONSUMER.CREATE.{stream}.>",
	"{api}.CONSUMER.DURABLE.CREATE.{stream}.>",
	"{api}.CONSUMER.INFO.{stream}.>",
	"{api}.CONSUMER.NAMES.{stream}",
	"{api}.CONSUMER.LIST.{stream}",
	"{api}.CONSUMER.DELETE.{stream}.>",
	"{api}.CONSUMER.MSG.NEXT.{stream}.>",
	"$JS.ACK.{stream}.*.*.*.*.*.*",
	"$JS.ACK.{dom}.*.{stream}.*.*.*.*.*.>",
	"$JS.FC.{stream}.*.*",
	"$JS.FC.{dom}.*.{stream}.*.*",
}

// Additional publish subjects a client needs to write to a stream, besides
// the data subjects. Purge is used by KV PurgeDeletes and Object Store
// Put/Delete.
var permMacroWritePubSubjects = []string{
	"{api}.STREAM.PURGE.{stream}",
}

// Additional publish subjects a client needs to manage a stream. Account
// info is included because clients call it before they create a bucket.
var permMacroAdminPubSubjects = []string{
	"{api}.STREAM.CREATE.{stream}",
	"{api}.STREAM.UPDATE.{stream}",
	"{api}.STREAM.DELETE.{stream}",
	"{api}.STREAM.MSG.DELETE.{stream}",
	"{api}.STREAM.SNAPSHOT.{stream}",
	"{api}.STREAM.RESTORE.{stream}",
	"{api}.INFO",
}

// Publish subjects for account-level JetStream discovery.
var permMacroInfoPubSubjects = []string{
	"{api}.INFO",
	"{api}.STREAM.NAMES",
	"{api}.STREAM.LIST",
}

// Publish subjects a client needs to bind to one named consumer of a stream
// and to consume from it. The client cannot create, change or delete that
// consumer, so a filter the administrator set holds.
//
// The ack and flow control patterns use exact token counts, for the reason
// given above permMacroReadPubSubjects. They pin both the stream token and
// the consumer token.
var permMacroConsumerPubSubjects = []string{
	"{api}.STREAM.INFO.{stream}",
	"{api}.CONSUMER.INFO.{stream}.{consumer}",
	"{api}.CONSUMER.MSG.NEXT.{stream}.{consumer}",
	"$JS.ACK.{stream}.{consumer}.*.*.*.*.*",
	"$JS.ACK.{dom}.*.{stream}.{consumer}.*.*.*.*.>",
	"$JS.FC.{stream}.{consumer}.*",
	"$JS.FC.{dom}.*.{stream}.{consumer}.*",
}

// Additional publish subjects a client needs to own one named consumer of a
// stream: create it with a filter of its choice, pause it, unpin it, reset it
// and delete it.
var permMacroConsumerAdminPubSubjects = []string{
	"{api}.CONSUMER.CREATE.{stream}.{consumer}",
	"{api}.CONSUMER.CREATE.{stream}.{consumer}.>",
	"{api}.CONSUMER.DURABLE.CREATE.{stream}.{consumer}",
	"{api}.CONSUMER.DELETE.{stream}.{consumer}",
	"{api}.CONSUMER.PAUSE.{stream}.{consumer}",
	"{api}.CONSUMER.UNPIN.{stream}.{consumer}",
	"{api}.CONSUMER.RESET.{stream}.{consumer}",
}

// subjects returns the subjects the macro emits for one tuple of resolved
// positional argument values and one resolved domain, which is empty when the
// macro names no domain. The caller has checked that the macro is valid for a
// subscribe list and that the tuple has m.args values.
func (m permMacro) subjects(values []string, domain string, isSub bool) []string {
	name := _EMPTY_
	if len(values) > 0 {
		name = values[0]
	}
	// A subscribe list names the bucket's own data subject. That subject is
	// account local, so a remote domain does not change it.
	data := _EMPTY_
	if m.subjectPrefix != _EMPTY_ {
		data = m.subjectPrefix + "." + name + ".>"
	}
	if isSub {
		return []string{data}
	}
	// Without a domain the client talks to the JetStream of its own server,
	// and the domain token of the v2 ack and flow control formats is unknown,
	// so it stays a wildcard.
	api, dom := permMacroLocalAPI, pwcs
	if domain != _EMPTY_ {
		api, dom = "$JS."+domain+".API", domain
		// A remote KV write is published through the domain API prefix, which
		// the remote maps back to $KV.<b>.>. An Object Store write is not:
		// clients do not prefix it and there is no $O domain mapping.
		if m.dataViaAPI && data != _EMPTY_ {
			data = api + "." + data
		}
	}
	stream := m.streamPrefix + name
	out := make([]string, 0, len(permMacroReadPubSubjects)+len(permMacroWritePubSubjects)+len(permMacroAdminPubSubjects)+1)
	add := func(templates []string) {
		for _, t := range templates {
			t = strings.ReplaceAll(t, permMacroAPI, api)
			t = strings.ReplaceAll(t, permMacroDom, dom)
			t = strings.ReplaceAll(t, permMacroStream, stream)
			if len(values) > 1 {
				t = strings.ReplaceAll(t, permMacroConsumer, values[1])
			}
			out = append(out, t)
		}
	}
	if m.info {
		add(permMacroInfoPubSubjects)
		return out
	}
	if m.consumer {
		add(permMacroConsumerPubSubjects)
		if m.consumerAdmin {
			add(permMacroConsumerAdminPubSubjects)
		}
		return out
	}
	add(permMacroReadPubSubjects)
	if m.write {
		add(permMacroWritePubSubjects)
		if data != _EMPTY_ {
			out = append(out, data)
		}
	}
	if m.admin {
		add(permMacroAdminPubSubjects)
	}
	return out
}

// validInSubscribeList reports whether the macro has a meaning in a
// subscribe list, which requires a data subject.
func (m permMacro) validInSubscribeList() bool {
	return m.subjectPrefix != _EMPTY_
}

// permMacroCall is one parsed macro token.
type permMacroCall struct {
	macro   permMacro
	args    []string // Raw positional arguments, in the order they were written.
	domain  string   // Value of the named "domain" argument, empty when absent.
	badArgs bool     // The argument list does not follow the grammar.
}

// splitPermMacroArgs splits an argument list on commas at parenthesis depth
// zero and trims every part. An unbalanced list is not an error here: the
// parts are returned as they are and the caller rejects them.
func splitPermMacroArgs(list string) []string {
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(list); i++ {
		switch list[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(list[start:i]))
				start = i + 1
			}
		}
	}
	return append(parts, strings.TrimSpace(list[start:]))
}

// permMacroNamedArg splits a "key=value" argument. A "=" that comes after a
// "(" belongs to a value operation, not to a named argument.
func permMacroNamedArg(part string) (string, string, bool) {
	for i := 0; i < len(part); i++ {
		switch part[i] {
		case '=':
			return strings.TrimSpace(part[:i]), strings.TrimSpace(part[i+1:]), true
		case '(':
			return _EMPTY_, _EMPTY_, false
		}
	}
	return _EMPTY_, _EMPTY_, false
}

// parsePermMacro checks whether op, the trimmed content of one {{...}}
// token, is a macro call and returns the parsed call. The second result
// reports whether op names a macro at all; a call whose argument list is
// malformed is still a macro call, and the caller reports it.
func parsePermMacro(op string) (permMacroCall, bool) {
	i := strings.IndexByte(op, '(')
	if i <= 0 || !strings.HasSuffix(op, ")") {
		return permMacroCall{}, false
	}
	m, ok := permMacros[strings.ToLower(strings.TrimSpace(op[:i]))]
	if !ok {
		return permMacroCall{}, false
	}
	call := permMacroCall{macro: m}
	list := strings.TrimSpace(op[i+1 : len(op)-1])
	if list == _EMPTY_ {
		return call, true
	}
	for _, part := range splitPermMacroArgs(list) {
		key, value, named := permMacroNamedArg(part)
		if !named {
			// Positional arguments come before the named argument.
			if call.domain != _EMPTY_ {
				call.badArgs = true
			}
			call.args = append(call.args, part)
			continue
		}
		if !strings.EqualFold(key, permMacroDomainArg) || value == _EMPTY_ || call.domain != _EMPTY_ {
			call.badArgs = true
			continue
		}
		call.domain = value
	}
	return call, true
}

// permMacroTagKey returns the key of a tag(key) or account-tag(key) style
// argument when arg has the given call prefix.
func permMacroTagKey(arg, call string) (string, bool) {
	if len(arg) <= len(call) || !strings.EqualFold(arg[:len(call)], call) || !strings.HasSuffix(arg, ")") {
		return _EMPTY_, false
	}
	return strings.TrimSpace(arg[len(call) : len(arg)-1]), true
}

// permMacroArgValues resolves a macro argument to the list of resource
// names. The second result is false when the argument is not a known
// operation.
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
		// A literal resource name.
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

// isValidPermMacroName reports whether a resolved macro value is a resource
// name a macro may expand. The rule is the one the official clients enforce
// when they create a bucket: one or more of [A-Za-z0-9_-]. It is stricter than
// the server's stream name rule on purpose: the emitted subjects go through
// the upstream template pass afterwards, so a value must not be able to carry
// a template token ({{...}}), a wildcard, or a subject separator.
func isValidPermMacroName(name string) bool {
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
// value or to an invalid resource name is an error; otherwise such values
// are skipped, which mirrors how upstream treats unresolved tags.
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
			if _, ok := parsePermMacro(trimOp(tk)); ok {
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
			if _, ok := parsePermMacro(trimOp(tk)); ok {
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
		call, _ := parsePermMacro(op)
		m := call.macro
		if isSub && !m.validInSubscribeList() {
			return nil, fmt.Errorf("template macro in %q is not valid in a subscribe list", entry)
		}
		if call.badArgs || len(call.args) != m.args {
			return nil, fmt.Errorf("template operation in %q: %q is not defined", entry, op)
		}
		// Resolve every argument to its list of valid values. The domain is
		// resolved like a positional argument and comes last, so it is the
		// innermost loop of the cartesian product below. A domain value is
		// held to the same name rule as a resource name, which also keeps the
		// wildcard out: a macro may name one domain, never all of them, so a
		// literal "*" argument must stay a positional-only exception.
		args := call.args
		if call.domain != _EMPTY_ {
			args = append(append(make([]string, 0, len(call.args)+1), call.args...), call.domain)
		}
		lists := make([][]string, 0, len(args))
		for _, arg := range args {
			values, ok := permMacroArgValues(arg, ujwt, acc)
			if !ok {
				return nil, fmt.Errorf("template operation in %q: %q is not defined", entry, op)
			}
			if len(values) == 0 && failOnBadSubject {
				return nil, fmt.Errorf("generated invalid subject %q: %q is not defined", entry, arg)
			}
			valid := make([]string, 0, len(values))
			for _, v := range values {
				if !isValidPermMacroName(v) {
					if failOnBadSubject {
						return nil, fmt.Errorf("generated invalid subject %q: %q is not a valid name", entry, v)
					}
					continue
				}
				valid = append(valid, v)
			}
			lists = append(lists, valid)
		}
		// Emit one subject set per element of the cartesian product, with the
		// first positional argument as the outer loop and the domain as the
		// innermost one.
		tuple := make([]string, len(lists))
		var emit func(int) error
		emit = func(i int) error {
			if i == len(lists) {
				values, domain := tuple, _EMPTY_
				if call.domain != _EMPTY_ {
					values, domain = tuple[:len(tuple)-1], tuple[len(tuple)-1]
				}
				subjects := m.subjects(values, domain, isSub)
				if len(out) > maxPermTemplateSubjectExpansions-len(subjects) {
					return fmt.Errorf("%w: %d", errPermTemplateExpansionLimit, maxPermTemplateSubjectExpansions)
				}
				out = append(out, subjects...)
				return nil
			}
			for _, v := range lists[i] {
				tuple[i] = v
				if err := emit(i + 1); err != nil {
					return err
				}
			}
			return nil
		}
		if err := emit(0); err != nil {
			return nil, err
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
