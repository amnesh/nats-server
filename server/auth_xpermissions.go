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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/nats-io/jwt/v2"
)

type xBucketPermission struct {
	Op     string
	Bucket string
	Domain string
}

type xStreamPermission struct {
	Op     string
	Stream string
	Domain string
}

type xConsumerPermission struct {
	Op       string
	Stream   string
	Consumer string
	Domain   string
}

type xPermissions struct {
	KV       []xBucketPermission
	Obj      []xBucketPermission
	Stream   []xStreamPermission
	Consumer []xConsumerPermission
	JSInfo   *bool
}

type accountXPermissions map[string]*xPermissions

var legacyXPermissionOperations = map[string]struct{}{
	"kvro": {}, "kvrw": {}, "kvadmin": {},
	"objro": {}, "objrw": {}, "objadmin": {},
	"jsread": {}, "jsadmin": {}, "jsinfo": {},
	"jsconsumer": {}, "jsconsumeradmin": {},
}

func rejectDuplicateJSONMembers(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var readValue func() error
	readValue = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("invalid JSON object member")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON object member %q", key)
				}
				seen[key] = struct{}{}
				if err := readValue(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := readValue(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delim)
		}
	}
	if err := readValue(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func jwtPayload(claimJWT string) ([]byte, error) {
	parts := strings.Split(claimJWT, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT payload: %w", err)
	}
	return payload, nil
}

func decodeAccountXPermissions(claimJWT string, ac *jwt.AccountClaims) (accountXPermissions, error) {
	payload, err := jwtPayload(claimJWT)
	if err != nil {
		return nil, err
	}
	if err := rejectDuplicateJSONMembers(payload); err != nil {
		return nil, fmt.Errorf("invalid account xpermissions: %w", err)
	}
	var raw struct {
		Nats struct {
			SigningKeys []json.RawMessage `json:"signing_keys"`
		} `json:"nats"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("invalid account JWT payload: %w", err)
	}

	result := make(accountXPermissions)
	seen := make(map[string]struct{}, len(raw.Nats.SigningKeys))
	for _, rawSigner := range raw.Nats.SigningKeys {
		trimmed := bytes.TrimSpace(rawSigner)
		if len(trimmed) == 0 {
			return nil, fmt.Errorf("invalid empty signing key")
		}
		if trimmed[0] == '"' {
			var key string
			if err := json.Unmarshal(trimmed, &key); err != nil {
				return nil, fmt.Errorf("invalid signing key: %w", err)
			}
			if err := correlateRawSigningKey(ac, seen, key, false); err != nil {
				return nil, err
			}
			continue
		}
		if trimmed[0] != '{' {
			return nil, fmt.Errorf("invalid signing key entry")
		}
		var signer map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &signer); err != nil {
			return nil, fmt.Errorf("invalid scoped signing key: %w", err)
		}
		kind, err := requiredRawString(signer, "kind")
		if err != nil {
			return nil, err
		}
		key, err := requiredRawString(signer, "key")
		if err != nil {
			return nil, err
		}
		if kind != jwt.UserScopeType.String() {
			return nil, fmt.Errorf("unsupported signing key kind %q", kind)
		}
		if err := correlateRawSigningKey(ac, seen, key, true); err != nil {
			return nil, err
		}
		templateRaw, ok := signer["template"]
		if !ok {
			return nil, fmt.Errorf("user scope %q has no template", key)
		}
		var template map[string]json.RawMessage
		if err := json.Unmarshal(templateRaw, &template); err != nil {
			return nil, fmt.Errorf("invalid user scope template for %q: %w", key, err)
		}
		extensionRaw, ok := template["xpermissions"]
		if !ok {
			continue
		}
		xp, err := parseXPermissions(extensionRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid xpermissions for signer %q: %w", key, err)
		}
		result[key] = xp
	}
	if len(seen) != len(ac.SigningKeys) {
		return nil, fmt.Errorf("raw and typed signing keys do not match")
	}
	for key := range ac.SigningKeys {
		if _, ok := seen[key]; !ok {
			return nil, fmt.Errorf("typed signing key %q is absent from raw claim", key)
		}
	}
	return result, nil
}

func correlateRawSigningKey(ac *jwt.AccountClaims, seen map[string]struct{}, key string, scoped bool) error {
	if key == _EMPTY_ {
		return fmt.Errorf("empty signing key")
	}
	if _, duplicate := seen[key]; duplicate {
		return fmt.Errorf("duplicate signing key %q", key)
	}
	seen[key] = struct{}{}
	scope, ok := ac.SigningKeys[key]
	if !ok {
		return fmt.Errorf("raw signing key %q is absent from typed claim", key)
	}
	_, isUserScope := scope.(*jwt.UserScope)
	if scoped != isUserScope || scoped != (scope != nil) {
		return fmt.Errorf("raw and typed signing key kind differ for %q", key)
	}
	return nil
}

func requiredRawString(object map[string]json.RawMessage, field string) (string, error) {
	raw, ok := object[field]
	if !ok {
		return _EMPTY_, fmt.Errorf("missing %q", field)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == _EMPTY_ {
		return _EMPTY_, fmt.Errorf("%q must be a nonempty string", field)
	}
	return value, nil
}

func parseXPermissions(raw json.RawMessage) (*xPermissions, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, fmt.Errorf("extension must be an object")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, fmt.Errorf("extension must be an object: %w", err)
	}
	if len(object) == 0 {
		return nil, fmt.Errorf("extension must not be empty")
	}
	xp := &xPermissions{}
	for field, value := range object {
		switch field {
		case "kv":
			entries, err := parseXBucketPermissions(value, "kv")
			if err != nil {
				return nil, err
			}
			xp.KV = entries
		case "obj":
			entries, err := parseXBucketPermissions(value, "obj")
			if err != nil {
				return nil, err
			}
			xp.Obj = entries
		case "stream":
			entries, err := parseXStreamPermissions(value)
			if err != nil {
				return nil, err
			}
			xp.Stream = entries
		case "consumer":
			entries, err := parseXConsumerPermissions(value)
			if err != nil {
				return nil, err
			}
			xp.Consumer = entries
		case "jsinfo":
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return nil, fmt.Errorf("jsinfo must be a boolean")
			}
			var enabled bool
			if err := json.Unmarshal(value, &enabled); err != nil {
				return nil, fmt.Errorf("jsinfo must be a boolean")
			}
			xp.JSInfo = &enabled
		default:
			return nil, fmt.Errorf("unknown xpermissions field %q", field)
		}
	}
	return xp, nil
}

func parseXBucketPermissions(raw json.RawMessage, group string) ([]xBucketPermission, error) {
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || entries == nil {
		return nil, fmt.Errorf("%s must be an array", group)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s must not be empty", group)
	}
	result := make([]xBucketPermission, 0, len(entries))
	for index, rawEntry := range entries {
		entry, err := parseXPermissionEntry(rawEntry, group, []string{"op", "bucket", "domain"}, []string{"op", "bucket"})
		if err != nil {
			return nil, fmt.Errorf("group %s entry %d%s: %w", group, index, xPermissionEntryOpContext(rawEntry), err)
		}
		op, bucket := entry["op"], entry["bucket"]
		if op != "ro" && op != "rw" && op != "admin" {
			return nil, fmt.Errorf("group %s entry %d field op: unknown operation %q", group, index, op)
		}
		if err := validateXPermissionSelector(bucket, true); err != nil {
			return nil, fmt.Errorf("group %s entry %d op %q field bucket: %w", group, index, op, err)
		}
		if err := validateXPermissionDomain(entry["domain"]); err != nil {
			return nil, fmt.Errorf("group %s entry %d op %q field domain: %w", group, index, op, err)
		}
		result = append(result, xBucketPermission{Op: op, Bucket: bucket, Domain: entry["domain"]})
	}
	return result, nil
}

func parseXStreamPermissions(raw json.RawMessage) ([]xStreamPermission, error) {
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || entries == nil {
		return nil, fmt.Errorf("stream must be an array")
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("stream must not be empty")
	}
	result := make([]xStreamPermission, 0, len(entries))
	for index, rawEntry := range entries {
		entry, err := parseXPermissionEntry(rawEntry, "stream", []string{"op", "stream", "domain"}, []string{"op", "stream"})
		if err != nil {
			return nil, fmt.Errorf("group stream entry %d%s: %w", index, xPermissionEntryOpContext(rawEntry), err)
		}
		op, stream := entry["op"], entry["stream"]
		if op != "ro" && op != "admin" {
			return nil, fmt.Errorf("group stream entry %d field op: unknown operation %q", index, op)
		}
		if err := validateXPermissionSelector(stream, true); err != nil {
			return nil, fmt.Errorf("group stream entry %d op %q field stream: %w", index, op, err)
		}
		if err := validateXPermissionDomain(entry["domain"]); err != nil {
			return nil, fmt.Errorf("group stream entry %d op %q field domain: %w", index, op, err)
		}
		result = append(result, xStreamPermission{Op: op, Stream: stream, Domain: entry["domain"]})
	}
	return result, nil
}

func parseXConsumerPermissions(raw json.RawMessage) ([]xConsumerPermission, error) {
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || entries == nil {
		return nil, fmt.Errorf("consumer must be an array")
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("consumer must not be empty")
	}
	result := make([]xConsumerPermission, 0, len(entries))
	for index, rawEntry := range entries {
		entry, err := parseXPermissionEntry(rawEntry, "consumer", []string{"op", "stream", "consumer", "domain"}, []string{"op", "stream", "consumer"})
		if err != nil {
			return nil, fmt.Errorf("group consumer entry %d%s: %w", index, xPermissionEntryOpContext(rawEntry), err)
		}
		op := entry["op"]
		if op != "ro" && op != "admin" {
			return nil, fmt.Errorf("group consumer entry %d field op: unknown operation %q", index, op)
		}
		if err := validateXPermissionSelector(entry["stream"], true); err != nil {
			return nil, fmt.Errorf("group consumer entry %d op %q field stream: %w", index, op, err)
		}
		if err := validateXPermissionSelector(entry["consumer"], true); err != nil {
			return nil, fmt.Errorf("group consumer entry %d op %q field consumer: %w", index, op, err)
		}
		if err := validateXPermissionDomain(entry["domain"]); err != nil {
			return nil, fmt.Errorf("group consumer entry %d op %q field domain: %w", index, op, err)
		}
		result = append(result, xConsumerPermission{Op: op, Stream: entry["stream"], Consumer: entry["consumer"], Domain: entry["domain"]})
	}
	return result, nil
}

func xPermissionEntryOpContext(raw json.RawMessage) string {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return _EMPTY_
	}
	var op string
	if json.Unmarshal(object["op"], &op) != nil || op == _EMPTY_ {
		return _EMPTY_
	}
	return fmt.Sprintf(" op %q", op)
}

func parseXPermissionEntry(raw json.RawMessage, group string, allowed, required []string) (map[string]string, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, fmt.Errorf("%s entry must be an object", group)
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, field := range allowed {
		allowedSet[field] = struct{}{}
	}
	for field := range object {
		if _, ok := allowedSet[field]; !ok {
			return nil, fmt.Errorf("unknown %s entry field %q", group, field)
		}
	}
	result := make(map[string]string, len(object))
	for field, rawValue := range object {
		if field == "domain" && bytes.Equal(bytes.TrimSpace(rawValue), []byte("null")) {
			return nil, fmt.Errorf("field domain must be a nonempty string")
		}
		var value string
		if err := json.Unmarshal(rawValue, &value); err != nil {
			return nil, fmt.Errorf("%s entry field %q must be a string", group, field)
		}
		if field == "domain" && value == _EMPTY_ {
			return nil, fmt.Errorf("field domain must be a nonempty string")
		}
		result[field] = value
	}
	for _, field := range required {
		if result[field] == _EMPTY_ {
			return nil, fmt.Errorf("%s entry field %q is required", group, field)
		}
	}
	return result, nil
}

func validateXPermissionDomain(domain string) error {
	if domain == _EMPTY_ {
		return nil
	}
	if err := validateXPermissionSelector(domain, false); err != nil {
		return fmt.Errorf("invalid domain selector: %w", err)
	}
	return nil
}

func validateXPermissionSelector(selector string, allowLiteralWildcard bool) error {
	if selector == _EMPTY_ {
		return fmt.Errorf("selector must not be empty")
	}
	if selector == pwcs {
		if allowLiteralWildcard {
			return nil
		}
		return fmt.Errorf("wildcard is not allowed")
	}
	tokens := mustacheRE.FindAllString(selector, -1)
	if len(tokens) == 0 {
		if !isValidXPermissionName(selector) {
			return fmt.Errorf("%q is not a valid name", selector)
		}
		return nil
	}
	static := selector
	for _, token := range tokens {
		static = strings.Replace(static, token, _EMPTY_, 1)
		op := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(token, "{{"), "}}"))
		if !isXPermissionValueOperation(op) {
			return fmt.Errorf("template operation %q is not defined", op)
		}
	}
	if strings.ContainsAny(static, "{}()*>") {
		return fmt.Errorf("%q is not a valid selector", selector)
	}
	for i := 0; i < len(static); i++ {
		if !isXPermissionNameByte(static[i]) {
			return fmt.Errorf("%q is not a valid selector", selector)
		}
	}
	return nil
}

func isXPermissionValueOperation(op string) bool {
	if strings.EqualFold(op, "name()") || strings.EqualFold(op, "subject()") ||
		strings.EqualFold(op, "account-name()") || strings.EqualFold(op, "account-subject()") {
		return true
	}
	for _, prefix := range []string{"tag(", "account-tag("} {
		if len(op) > len(prefix) && strings.EqualFold(op[:len(prefix)], prefix) && strings.HasSuffix(op, ")") {
			key := strings.TrimSpace(op[len(prefix) : len(op)-1])
			return key != _EMPTY_ && !strings.ContainsAny(key, "(){}")
		}
	}
	return false
}

func isXPermissionNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func isValidXPermissionName(name string) bool {
	if name == _EMPTY_ {
		return false
	}
	for i := 0; i < len(name); i++ {
		if !isXPermissionNameByte(name[i]) {
			return false
		}
	}
	return true
}

func validateNoLegacyPermissionMacros(ac *jwt.AccountClaims) error {
	for key, scope := range ac.SigningKeys {
		userScope, ok := scope.(*jwt.UserScope)
		if !ok {
			continue
		}
		lists := []jwt.StringList{
			userScope.Template.Pub.Allow,
			userScope.Template.Pub.Deny,
			userScope.Template.Sub.Allow,
			userScope.Template.Sub.Deny,
		}
		for _, list := range lists {
			for _, entry := range list {
				for _, token := range mustacheRE.FindAllString(entry, -1) {
					op := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(token, "{{"), "}}")))
					name := op
					if i := strings.IndexByte(name, '('); i >= 0 {
						name = strings.TrimSpace(name[:i])
					}
					if _, legacy := legacyXPermissionOperations[name]; legacy {
						return fmt.Errorf("legacy resource permission operation %q in scope %q is not supported", name, key)
					}
				}
			}
		}
	}
	return nil
}
