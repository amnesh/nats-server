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
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
)

type grantLeafExport struct {
	Allow       []string `json:"allow"`
	Deny        []string `json:"deny,omitempty"`
	AllowPrefix []string `json:"allow_prefix,omitempty"`
}

// leafExportPermission returns what the remote leaf may publish into this
// server. For a grant leaf it is the copy that installAuthGrant keeps, because
// a CONNECT can replace c.opts.Export before re-authentication installs the
// grant again. The client lock is held.
func (c *client) leafExportPermission() *SubjectPermission {
	if c.leaf != nil && c.leaf.grantPub != nil {
		return c.leaf.grantPub
	}
	return c.opts.Export
}

func (c *client) grantLeafExportJSON() json.RawMessage {
	grant := grantLeafExport{Allow: []string{fwcs}}
	if export := c.leafExportPermission(); export != nil {
		if export.Allow != nil {
			grant.Allow = append([]string{}, export.Allow...)
		}
		grant.Deny = slices.Clone(export.Deny)
	}
	for _, rule := range c.perms.sub.prefix {
		tokens := make([]string, len(rule))
		for i, token := range rule {
			tokens[i] = token.value
			if token.prefix {
				tokens[i] += pwcs
			}
		}
		grant.AllowPrefix = append(grant.AllowPrefix, strings.Join(tokens, tsep))
	}
	data, _ := json.Marshal(grant)
	return data
}

func decodeGrantLeafExport(data json.RawMessage) (*SubjectPermission, grantPrefixRules, error) {
	invalid := errors.New("invalid leaf export grant")
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return nil, nil, invalid
	}
	var grant grantLeafExport
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&grant); err != nil {
		return nil, nil, invalid
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, nil, invalid
	}
	for _, list := range [][]string{grant.Allow, grant.Deny} {
		if len(list) > maxPermTemplateSubjectExpansions {
			return nil, nil, invalid
		}
		for _, subject := range list {
			if !IsValidSubject(subject) {
				return nil, nil, invalid
			}
		}
	}
	rules, err := compileGrantPrefixRules(grant.AllowPrefix)
	if err != nil {
		return nil, nil, invalid
	}
	return &SubjectPermission{Allow: append([]string{}, grant.Allow...), Deny: grant.Deny}, rules, nil
}

// The client lock is held. Only solicited leaves consume INFO permissions.
func (c *client) setLeafInfoPermissions(info *Info) error {
	perms := &Permissions{Publish: info.Export, Subscribe: info.Import}
	var rules grantPrefixRules
	exact := len(info.ExportGrant) > 0
	if exact {
		var err error
		perms.Publish, rules, err = decodeGrantLeafExport(info.ExportGrant)
		if err != nil {
			return err
		}
	}
	if remote := c.leaf.remote; remote != nil {
		if len(remote.DenyExports) > 0 {
			if perms.Publish == nil {
				perms.Publish = &SubjectPermission{}
			}
			perms.Publish.Deny = append(perms.Publish.Deny, remote.DenyExports...)
		}
		if len(remote.DenyImports) > 0 {
			if perms.Subscribe == nil {
				perms.Subscribe = &SubjectPermission{}
			}
			perms.Subscribe.Deny = append(perms.Subscribe.Deny, remote.DenyImports...)
		}
	}
	c.setPermissions(perms)
	c.perms.pub.prefix = rules
	c.leaf.exportGrant = exact
	if exact {
		c.restoreGrantLeafDenies()
	}
	return nil
}

// This async INFO precedes changed interest without taking Server under client.
func (c *client) refreshGrantLeafInfo() {
	if c.srv == nil || c.acc == nil {
		return
	}
	info := &Info{CID: c.cid, Import: c.opts.Import, Export: c.opts.Export, RemoteAccount: c.acc.Name}
	c.setGrantLeafInfoPermissions(info)
	c.enqueueProto(generateInfoJSON(info))
}

func (c *client) grantLeafLiteralInterestAllowed(wireSubject, aclSubject []byte) bool {
	if !c.isSolicitedLeafNode() || !c.leaf.exportGrant {
		return false
	}
	key := string(wireSubject)
	if strings.HasPrefix(key, leafNodeLoopDetectionSubjectPrefix) || !subjectIsLiteral(key) {
		return false
	}
	sub := c.subs[key]
	if sub == nil || sub.queue != nil || sub.isClosed() || string(sub.subject) != key {
		return false
	}
	if c.perms.pub.deny != nil {
		if n, _ := c.perms.pub.deny.NumInterest(key); n > 0 {
			return false
		}
		if n, _ := c.perms.pub.deny.NumInterest(string(aclSubject)); n > 0 {
			return false
		}
	}
	return true
}

// Retain CONNECT and JetStream restrictions independently of replaceable grants.
func (c *client) rememberGrantLeafDenies(what denyType, subjects []string) {
	if !c.projectsGrantLeafInterest() && !(c.isSolicitedLeafNode() && c.leaf.exportGrant) {
		return
	}
	remember := func(dst *[]string) {
		for _, subject := range subjects {
			if !slices.Contains(*dst, subject) {
				*dst = append(*dst, subject)
			}
		}
		slices.Sort(*dst)
	}
	if what == pub || what == both {
		remember(&c.leaf.grantDenyPub)
	}
	if what == sub || what == both {
		remember(&c.leaf.grantDenySub)
	}
}

func (c *client) restoreGrantLeafDenies() {
	c.mergeDenyPermissions(pub, c.leaf.grantDenyPub)
	c.mergeDenyPermissions(sub, c.leaf.grantDenySub)
	for _, subscription := range c.subs {
		c.loadMsgDenyFilterIfNeeded(string(subscription.subject), subscription.queue != nil)
	}
}
