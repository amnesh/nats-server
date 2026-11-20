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

import "github.com/nats-io/jwt/v2"

// On the JWT path, the server registers the user and the account of a
// connection before the verdict of auth verification or of the grant hook
// arrives. Connz then lists the connection with its account and user. The
// marker ConnInfo.VerificationPending tells a host that reads Connz that the
// server can still reject the connection.

// markVerificationPending sets the marker before the server registers the user
// and the account of a JWT connection that gets a verdict. A connection that a
// verdict admitted keeps no marker when a config reload authenticates it
// again, because the reload uses the cached verdict.
func (s *Server) markVerificationPending(c *client, juc *jwt.UserClaims, acc *Account, opts *Options, grantMode bool) {
	if !grantMode && !s.authVerificationApplies(c, juc, acc, opts) {
		return
	}
	c.mu.Lock()
	if c.authGrant == nil && (c.authVerify == nil || !c.authVerify.done) {
		c.verificationPending = true
	}
	c.mu.Unlock()
}

// clearVerificationPending removes the marker when a verdict admits the
// connection. A rejected connection keeps it until it closes.
func (c *client) clearVerificationPending() {
	c.mu.Lock()
	c.verificationPending = false
	c.mu.Unlock()
}
