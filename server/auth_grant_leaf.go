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
	"slices"
)

func (c *client) setGrantLeafInfoPermissions(info *Info) {
	if !c.authGrantMode.Load() || c.perms == nil {
		return
	}
	if c.projectsGrantLeafInterest() {
		info.ExportGrant = c.grantLeafExportJSON()
	}
	info.Import = grantLeafWirePermission(info.Import, c.perms.pub.prefix)
	info.Export = grantLeafWirePermission(info.Export, c.perms.sub.prefix)
	if c.perms.resp != nil {
		export := &SubjectPermission{Allow: []string{">"}}
		if info.Export != nil {
			export.Deny = slices.Clone(info.Export.Deny)
		}
		info.Export = export
	}
}

func (c *client) advertiseGrantLeafReply(reply []byte) {
	if c.kind != LEAF || c.replies == nil || len(reply) == 0 {
		return
	}
	subject := string(reply)
	if c.replies[subject] != nil || c.leafSendAllowed(reply) || c.canAdvertiseLeafInterestInternal(subject) {
		return
	}
	// The request already discloses this reply subject. Advertise it before
	// the request so a fast response cannot race interest propagation.
	c.sendGrantLeafReplyInterest(subject, 1)
}

func (c *client) removeGrantLeafReplyInterest(subject string) {
	if !c.authGrantMode.Load() || c.kind != LEAF || c.canAdvertiseLeafInterestInternal(subject) {
		return
	}
	c.sendGrantLeafReplyInterest(subject, 0)
}

// A delivered request authorizes its response interest even in spoke role.
func (c *client) sendGrantLeafReplyInterest(subject string, delta int64) {
	var b bytes.Buffer
	c.writeLeafSub(&b, subject, delta)
	c.enqueueProto(b.Bytes())
}
