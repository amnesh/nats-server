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

package authverify

import "github.com/nats-io/jwt/v2"

// RejectCode classifies a rejection or a planned close. The values are part of
// the static callout wire format (AuthVerifyResponse.Code), so new codes are
// only appended. The server treats an unknown code as CodeDenied.
type RejectCode int

const (
	// CodeDenied rejects with "Authorization Violation".
	CodeDenied RejectCode = iota
	// CodeResourceLimit sends the client to another server.
	CodeResourceLimit
	// CodeRetry is a temporary rejection. The client tries again later.
	CodeRetry
	// CodeQuarantined is a temporary rejection of a quarantined account.
	CodeQuarantined
	// CodeRevoked rejects a revoked credential.
	CodeRevoked
)

// GrantRequest describes a verified connection in a grant-mode account.
type GrantRequest struct {
	Server    jwt.ServerID
	UserNkey  string
	Account   string
	Client    jwt.ClientInformation
	Connect   jwt.ConnectOptions
	TLS       *jwt.ClientTLS
	Issuer    string
	ScopeRole string
}

// Grant is the complete permission set supplied by the embedding host.
type Grant struct {
	Pub, Sub SubjectGrant
	Resp     *jwt.ResponsePermission
}

type SubjectGrant struct {
	Allow       []string
	AllowPrefix []string
	Deny        []string
}

type GrantVerdict struct {
	Reject     bool
	Code       RejectCode
	Reason     string
	Generation uint64
	Expires    int64
	Grant      Grant
	// Done runs exactly once for an admit verdict, after the admission decision.
	Done func(applied bool)
}

type GrantUpdate struct {
	ClientID   uint64
	Account    string
	UserNkey   string
	Generation uint64
	Expires    int64
	Grant      Grant
}

// GrantHook runs in process. Methods must not block or perform I/O.
// Closed is called only after Done(true), with no server or client lock held.
type GrantHook interface {
	Verify(req *GrantRequest) *GrantVerdict
	Closed(serverID string, clientID uint64)
}
