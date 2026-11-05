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
	"crypto/sha256"
	"errors"
	"strings"
)

// A leaf remote does not send CONNECT again with a user JWT that the remote
// server reported revoked. The unit of revocation is the credential, not the
// user key: a new JWT for the same key connects. The remote keeps only a
// SHA-256 digest of the last revoked JWT, in memory. The JWT and the digest
// never reach a log.

// leafRevokedCheckDelay is the delay before the next check of a remote whose
// JWT is revoked.
const leafRevokedCheckDelay = leafNodeReconnectAfterPermViolation

var errLeafCredentialRevoked = errors.New("leafnode remote credential revoked")

// leafJWTDigest is the digest of a user JWT. The zero value is no JWT.
type leafJWTDigest struct {
	sum [sha256.Size]byte
	set bool
}

func newLeafJWTDigest(token string) leafJWTDigest {
	if token == _EMPTY_ {
		return leafJWTDigest{}
	}
	return leafJWTDigest{sum: sha256.Sum256([]byte(token)), set: true}
}

// leafCheckRevokedJWTLocked records the JWT that this connection sends and
// reports if the remote server revoked it. On a match it sets the connect
// delay of the remote. The client lock must be held.
func (c *client) leafCheckRevokedJWTLocked(token string) error {
	digest := newLeafJWTDigest(token)
	c.leaf.connectJWT = digest
	remote := c.leaf.remote
	if !digest.set || remote == nil {
		return nil
	}
	remote.RLock()
	revoked := remote.revokedJWT == digest
	remote.RUnlock()
	if !revoked {
		return nil
	}
	delay := leafRevokedCheckDelay
	if s := c.srv; s != nil {
		if testDelay := s.getOpts().LeafNode.connDelay; testDelay != 0 {
			delay = testDelay
		}
	}
	remote.setConnectDelay(delay)
	c.Warnf("Leafnode remote credential was revoked by the remote server, will not connect until it changes, next check in %v", delay)
	return errLeafCredentialRevoked
}

// leafProcessRevokedErr records the JWT of this connection as revoked when
// the remote server reports it revoked, at CONNECT or as a planned close.
func (c *client) leafProcessRevokedErr(errStr string) {
	if !strings.Contains(errStr, authRejectRevokedText) {
		return
	}
	c.mu.Lock()
	var remote *leafNodeCfg
	var digest leafJWTDigest
	if c.isSolicitedLeafNode() {
		remote, digest = c.leaf.remote, c.leaf.connectJWT
	}
	c.mu.Unlock()
	if remote == nil || !digest.set {
		return
	}
	remote.Lock()
	remote.revokedJWT = digest
	remote.Unlock()
	c.Warnf("Leafnode remote credential revoked by the remote server")
}

// leafConnectErrClosedState returns the close state for an error of
// sendLeafConnect.
func leafConnectErrClosedState(err error) ClosedState {
	if err == errLeafCredentialRevoked {
		return Revocation
	}
	return WriteError
}
