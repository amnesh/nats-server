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
	"errors"

	"github.com/nats-io/nats-server/v2/server/authverify"
)

// Wire texts of the reject codes. nats.go treats a text that starts with
// "authorization violation", "user authentication revoked", or one of the
// expired texts as an authentication error and stops reconnecting after the
// same error twice on one server. It only retries for the retry and
// quarantine texts.
const (
	authRejectDeniedText      = "Authorization Violation"
	authRejectRetryText       = "Authorization Temporarily Unavailable"
	authRejectQuarantinedText = "Account Quarantined"
	authRejectRevokedText     = "User Authentication Revoked"
)

var (
	errAuthGrantRetry       = errors.New("auth grant retry")
	errAuthGrantQuarantined = errors.New("auth grant quarantined")
	errAuthGrantRevoked     = errors.New("auth grant revoked")
)

// authRejectCodeError returns the authentication error of a reject code from
// the grant hook or the static callout. CodeDenied and an unknown code return
// nil, which keeps the default authentication violation.
func authRejectCodeError(code authverify.RejectCode) error {
	switch code {
	case authverify.CodeResourceLimit:
		return errAuthGrantResourceLimit
	case authverify.CodeRetry:
		return errAuthGrantRetry
	case authverify.CodeQuarantined:
		return errAuthGrantQuarantined
	case authverify.CodeRevoked:
		return errAuthGrantRevoked
	default:
		return nil
	}
}

// authRejectClosedState returns the close state of a reject code error.
func authRejectClosedState(err error) (ClosedState, bool) {
	switch err {
	case errAuthGrantResourceLimit:
		return ResourceLimit, true
	case errAuthGrantRetry:
		return AuthorizationUnavailable, true
	case errAuthGrantQuarantined:
		return AccountQuarantined, true
	case errAuthGrantRevoked:
		return Revocation, true
	default:
		return 0, false
	}
}

// authRejectWireText returns the -ERR text that a connect rejection with the
// close state reason sends.
func authRejectWireText(reason ClosedState) string {
	switch reason {
	case ResourceLimit:
		return ErrTooManyConnections.Error()
	case AuthorizationUnavailable:
		return authRejectRetryText
	case AccountQuarantined:
		return authRejectQuarantinedText
	case Revocation:
		return authRejectRevokedText
	default:
		return authRejectDeniedText
	}
}

// authRejectDisconnect returns the close state and the -ERR text of a planned
// disconnect with code. An empty text sends no -ERR: while connected, nats.go
// closes for good on an error text that it does not know, but reconnects
// after a close without -ERR.
func authRejectDisconnect(code authverify.RejectCode) (ClosedState, string) {
	switch code {
	case authverify.CodeResourceLimit:
		return ResourceLimit, ErrTooManyConnections.Error()
	case authverify.CodeRetry:
		return AuthorizationUnavailable, _EMPTY_
	case authverify.CodeQuarantined:
		return AccountQuarantined, _EMPTY_
	case authverify.CodeRevoked:
		return Revocation, authRejectRevokedText
	default:
		return GrantRejected, authRejectDeniedText
	}
}
