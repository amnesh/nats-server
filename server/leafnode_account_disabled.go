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
	"time"
)

// leafAccountDisabledDelay is the connect delay of a leaf remote after the
// remote server rejected or closed it with the account disabled code. The
// host can admit the account again at any time, so the remote keeps trying,
// but not at each reconnect interval. The test-only LeafNode.connDelay option
// replaces it.
const leafAccountDisabledDelay = 30 * time.Second

// leafProcessAccountDisabledErr sets the connect delay of a soliciting leaf
// when the remote server reports that the account is disabled, at CONNECT or
// as a planned close.
func (c *client) leafProcessAccountDisabledErr(errStr string) {
	if !strings.Contains(errStr, authRejectAccountDisabledText) {
		return
	}
	_, delay := c.setLeafConnectDelayIfSoliciting(leafAccountDisabledDelay)
	c.Warnf("Leafnode connection rejected because the account is disabled, next attempt in %v", delay)
}
