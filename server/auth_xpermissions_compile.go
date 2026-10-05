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

const (
	xPermissionStream   = "{stream}"
	xPermissionConsumer = "{consumer}"
	xPermissionAPI      = "{api}"
	xPermissionDomain   = "{domain}"
	xPermissionLocalAPI = "$JS.API"
)

var xPermissionReadSubjects = []string{
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
	"$JS.ACK.{domain}.*.{stream}.*.*.*.*.*.>",
	"$JS.FC.{stream}.*.*",
	"$JS.FC.{domain}.*.{stream}.*.*",
}

var xPermissionWriteSubjects = []string{
	"{api}.STREAM.PURGE.{stream}",
}

var xPermissionAdminSubjects = []string{
	"{api}.STREAM.CREATE.{stream}",
	"{api}.STREAM.UPDATE.{stream}",
	"{api}.STREAM.DELETE.{stream}",
	"{api}.STREAM.MSG.DELETE.{stream}",
	"{api}.STREAM.SNAPSHOT.{stream}",
	"{api}.STREAM.RESTORE.{stream}",
	"{api}.INFO",
}

var xPermissionInfoSubjects = []string{
	"{api}.INFO",
	"{api}.STREAM.NAMES",
	"{api}.STREAM.LIST",
}

var xPermissionConsumerSubjects = []string{
	"{api}.STREAM.INFO.{stream}",
	"{api}.CONSUMER.INFO.{stream}.{consumer}",
	"{api}.CONSUMER.MSG.NEXT.{stream}.{consumer}",
	"$JS.ACK.{stream}.{consumer}.*.*.*.*.*",
	"$JS.ACK.{domain}.*.{stream}.{consumer}.*.*.*.*.>",
	"$JS.FC.{stream}.{consumer}.*",
	"$JS.FC.{domain}.*.{stream}.{consumer}.*",
}

var xPermissionConsumerAdminSubjects = []string{
	"{api}.CONSUMER.CREATE.{stream}.{consumer}",
	"{api}.CONSUMER.CREATE.{stream}.{consumer}.>",
	"{api}.CONSUMER.DURABLE.CREATE.{stream}.{consumer}",
	"{api}.CONSUMER.DELETE.{stream}.{consumer}",
	"{api}.CONSUMER.PAUSE.{stream}.{consumer}",
	"{api}.CONSUMER.UNPIN.{stream}.{consumer}",
	"{api}.CONSUMER.RESET.{stream}.{consumer}",
}

type xPermissionSubjects struct {
	pub []string
	sub []string
}

func appendXPermissions(lim jwt.UserPermissionLimits, xp *xPermissions, ujwt *jwt.UserClaims, acc *Account, pubCandidates, subCandidates int) (jwt.UserPermissionLimits, error) {
	if xp == nil {
		return lim, nil
	}
	appendSubjects := func(subjects xPermissionSubjects) error {
		if len(subjects.pub) > maxPermTemplateSubjectExpansions-pubCandidates ||
			len(subjects.sub) > maxPermTemplateSubjectExpansions-subCandidates {
			return fmt.Errorf("%w: %d", errPermTemplateExpansionLimit, maxPermTemplateSubjectExpansions)
		}
		pubCandidates += len(subjects.pub)
		subCandidates += len(subjects.sub)
		lim.Permissions.Pub.Allow = append(lim.Permissions.Pub.Allow, subjects.pub...)
		lim.Permissions.Sub.Allow = append(lim.Permissions.Sub.Allow, subjects.sub...)
		return nil
	}
	for index, entry := range xp.KV {
		err := forEachXPermissionTuple([]string{entry.Bucket, entry.Domain}, []string{"bucket", "domain"}, []bool{true, false}, ujwt, acc, func(tuple []string) error {
			return appendSubjects(bucketXPermissionSubjects("KV_", "$KV", true, entry.Op, tuple[0], tuple[1]))
		})
		if err != nil {
			return jwt.UserPermissionLimits{}, fmt.Errorf("group kv entry %d op %q: %w", index, entry.Op, err)
		}
	}
	for index, entry := range xp.Obj {
		err := forEachXPermissionTuple([]string{entry.Bucket, entry.Domain}, []string{"bucket", "domain"}, []bool{true, false}, ujwt, acc, func(tuple []string) error {
			return appendSubjects(bucketXPermissionSubjects("OBJ_", "$O", false, entry.Op, tuple[0], tuple[1]))
		})
		if err != nil {
			return jwt.UserPermissionLimits{}, fmt.Errorf("group obj entry %d op %q: %w", index, entry.Op, err)
		}
	}
	for index, entry := range xp.Stream {
		err := forEachXPermissionTuple([]string{entry.Stream, entry.Domain}, []string{"stream", "domain"}, []bool{true, false}, ujwt, acc, func(tuple []string) error {
			return appendSubjects(streamXPermissionSubjects(entry.Op, tuple[0], tuple[1]))
		})
		if err != nil {
			return jwt.UserPermissionLimits{}, fmt.Errorf("group stream entry %d op %q: %w", index, entry.Op, err)
		}
	}
	for index, entry := range xp.Consumer {
		err := forEachXPermissionTuple([]string{entry.Stream, entry.Consumer, entry.Domain}, []string{"stream", "consumer", "domain"}, []bool{true, true, false}, ujwt, acc, func(tuple []string) error {
			return appendSubjects(consumerXPermissionSubjects(entry.Op, tuple[0], tuple[1], tuple[2]))
		})
		if err != nil {
			return jwt.UserPermissionLimits{}, fmt.Errorf("group consumer entry %d op %q: %w", index, entry.Op, err)
		}
	}
	if xp.JSInfo != nil && *xp.JSInfo {
		if err := appendSubjects(xPermissionSubjects{pub: renderXPermissionSubjects(xPermissionInfoSubjects, _EMPTY_, _EMPTY_, _EMPTY_)}); err != nil {
			return jwt.UserPermissionLimits{}, fmt.Errorf("field jsinfo: %w", err)
		}
	}
	lim.Permissions.Pub.Allow = stableUniqueSubjects(lim.Permissions.Pub.Allow)
	lim.Permissions.Sub.Allow = stableUniqueSubjects(lim.Permissions.Sub.Allow)
	return lim, nil
}

func bucketXPermissionSubjects(streamPrefix, dataPrefix string, dataViaAPI bool, op, bucket, domain string) xPermissionSubjects {
	stream := streamPrefix + bucket
	if bucket == pwcs {
		stream = pwcs
	}
	result := streamXPermissionSubjects("ro", stream, domain)
	if op == "rw" || op == "admin" {
		result.pub = append(result.pub, renderXPermissionSubjects(xPermissionWriteSubjects, stream, _EMPTY_, domain)...)
		data := dataPrefix + "." + bucket + ".>"
		if domain != _EMPTY_ && dataViaAPI {
			data = "$JS." + domain + ".API." + data
		}
		result.pub = append(result.pub, data)
	}
	if op == "admin" {
		result.pub = append(result.pub, renderXPermissionSubjects(xPermissionAdminSubjects, stream, _EMPTY_, domain)...)
	}
	result.sub = []string{dataPrefix + "." + bucket + ".>"}
	return result
}

func streamXPermissionSubjects(op, stream, domain string) xPermissionSubjects {
	result := xPermissionSubjects{pub: renderXPermissionSubjects(xPermissionReadSubjects, stream, _EMPTY_, domain)}
	if op == "admin" {
		result.pub = append(result.pub, renderXPermissionSubjects(xPermissionWriteSubjects, stream, _EMPTY_, domain)...)
		result.pub = append(result.pub, renderXPermissionSubjects(xPermissionAdminSubjects, stream, _EMPTY_, domain)...)
	}
	return result
}

func consumerXPermissionSubjects(op, stream, consumer, domain string) xPermissionSubjects {
	result := xPermissionSubjects{pub: renderXPermissionSubjects(xPermissionConsumerSubjects, stream, consumer, domain)}
	if op == "admin" {
		result.pub = append(result.pub, renderXPermissionSubjects(xPermissionConsumerAdminSubjects, stream, consumer, domain)...)
	}
	return result
}

func renderXPermissionSubjects(templates []string, stream, consumer, domain string) []string {
	api, domainToken := xPermissionLocalAPI, pwcs
	if domain != _EMPTY_ {
		api, domainToken = "$JS."+domain+".API", domain
	}
	result := make([]string, 0, len(templates))
	for _, template := range templates {
		subject := strings.ReplaceAll(template, xPermissionAPI, api)
		subject = strings.ReplaceAll(subject, xPermissionDomain, domainToken)
		subject = strings.ReplaceAll(subject, xPermissionStream, stream)
		subject = strings.ReplaceAll(subject, xPermissionConsumer, consumer)
		result = append(result, subject)
	}
	return result
}

func forEachXPermissionTuple(selectors, fields []string, allowWildcard []bool, ujwt *jwt.UserClaims, acc *Account, fn func([]string) error) error {
	expanded := make([][]string, len(selectors))
	total := 1
	for i, selector := range selectors {
		if selector == _EMPTY_ {
			expanded[i] = []string{_EMPTY_}
			continue
		}
		values, err := resolveXPermissionSelector(selector, allowWildcard[i], ujwt, acc)
		if err != nil {
			return fmt.Errorf("field %s: %w", fields[i], err)
		}
		if len(values) == 0 || total > maxPermTemplateSubjectExpansions/len(values) {
			return fmt.Errorf("field %s: %w: %d", fields[i], errPermTemplateExpansionLimit, maxPermTemplateSubjectExpansions)
		}
		total *= len(values)
		expanded[i] = values
	}
	tuple := make([]string, len(expanded))
	var visit func(int) error
	visit = func(index int) error {
		if index == len(expanded) {
			return fn(tuple)
		}
		for _, value := range expanded[index] {
			tuple[index] = value
			if err := visit(index + 1); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(0)
}

func resolveXPermissionSelector(selector string, allowLiteralWildcard bool, ujwt *jwt.UserClaims, acc *Account) ([]string, error) {
	if selector == pwcs && allowLiteralWildcard {
		return []string{pwcs}, nil
	}
	tokens := mustacheRE.FindAllString(selector, -1)
	if len(tokens) == 0 {
		if !isValidXPermissionName(selector) {
			return nil, fmt.Errorf("generated invalid subject: %q is not a valid name", selector)
		}
		return []string{selector}, nil
	}
	lists := make([][]string, len(tokens))
	total := 1
	for i, token := range tokens {
		op := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(token, "{{"), "}}"))
		values, ok := xPermissionOperationValues(op, ujwt, acc)
		if !ok {
			return nil, fmt.Errorf("template operation in %q: %q is not defined", selector, op)
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("generated invalid subject %q: %q is not defined", selector, op)
		}
		for _, value := range values {
			if !isValidXPermissionName(value) {
				return nil, fmt.Errorf("generated invalid subject %q: %q is not a valid name", selector, value)
			}
		}
		if total > maxPermTemplateSubjectExpansions/len(values) {
			return nil, fmt.Errorf("%w: %d", errPermTemplateExpansionLimit, maxPermTemplateSubjectExpansions)
		}
		total *= len(values)
		lists[i] = values
	}
	result := make([]string, 0, total)
	choice := make([]string, len(tokens))
	var emit func(int) error
	emit = func(index int) error {
		if index == len(lists) {
			value := selector
			for i, token := range tokens {
				value = strings.Replace(value, token, choice[i], 1)
			}
			if !isValidXPermissionName(value) {
				return fmt.Errorf("generated invalid subject %q: %q is not a valid name", selector, value)
			}
			result = append(result, value)
			return nil
		}
		for _, value := range lists[index] {
			choice[index] = value
			if err := emit(index + 1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := emit(0); err != nil {
		return nil, err
	}
	return result, nil
}

func xPermissionOperationValues(op string, ujwt *jwt.UserClaims, acc *Account) ([]string, bool) {
	switch {
	case strings.EqualFold(op, "name()"):
		return []string{ujwt.Name}, true
	case strings.EqualFold(op, "subject()"):
		return []string{ujwt.Subject}, true
	case strings.EqualFold(op, "account-name()"):
		acc.mu.RLock()
		name := acc.nameTag
		acc.mu.RUnlock()
		return []string{name}, true
	case strings.EqualFold(op, "account-subject()"):
		return []string{ujwt.IssuerAccount}, true
	}
	prefix, key := _EMPTY_, _EMPTY_
	for _, candidate := range []string{"tag(", "account-tag("} {
		if len(op) > len(candidate) && strings.EqualFold(op[:len(candidate)], candidate) && strings.HasSuffix(op, ")") {
			prefix = candidate
			key = strings.TrimSpace(op[len(candidate) : len(op)-1])
			break
		}
	}
	if prefix == _EMPTY_ || key == _EMPTY_ || strings.ContainsAny(key, "(){}") {
		return nil, false
	}
	var tags jwt.TagList
	if strings.EqualFold(prefix, "account-tag(") {
		acc.mu.RLock()
		tags = append(jwt.TagList(nil), acc.tags...)
		acc.mu.RUnlock()
	} else {
		tags = ujwt.Tags
	}
	tagPrefix := strings.ToLower(key) + ":"
	var result []string
	for _, tag := range tags {
		if value, ok := strings.CutPrefix(tag, tagPrefix); ok {
			result = append(result, value)
		}
	}
	return result, true
}

func stableUniqueSubjects(subjects jwt.StringList) jwt.StringList {
	if len(subjects) < 2 {
		return subjects
	}
	seen := make(map[string]struct{}, len(subjects))
	result := make(jwt.StringList, 0, len(subjects))
	for _, subject := range subjects {
		if _, ok := seen[subject]; ok {
			continue
		}
		seen[subject] = struct{}{}
		result = append(result, subject)
	}
	return result
}
