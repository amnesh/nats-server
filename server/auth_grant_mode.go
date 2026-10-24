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
	"encoding/json"
	"fmt"

	"github.com/nats-io/jwt/v2"
)

type authMode uint8

const (
	authModeStatic authMode = iota
	authModeGrant
)

type accountClaimExtensions struct {
	xpermissions accountXPermissions
	authMode     authMode
}

func decodeAuthModeJWT(raw string, user bool) (authMode, bool, error) {
	payload, err := jwtPayload(raw)
	if err != nil {
		return authModeStatic, false, err
	}
	if err := rejectDuplicateJSONMembers(payload); err != nil {
		return authModeStatic, false, fmt.Errorf("invalid authverify mode: %w", err)
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil || claims == nil {
		return authModeStatic, false, fmt.Errorf("invalid JWT payload")
	}
	var nats map[string]json.RawMessage
	if err := json.Unmarshal(claims["nats"], &nats); err != nil || nats == nil {
		return authModeStatic, false, fmt.Errorf("invalid JWT nats block")
	}
	extension, present := nats["authverify"]
	if !present {
		return authModeStatic, false, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(extension, &fields); err != nil || fields == nil {
		return authModeStatic, true, fmt.Errorf("authverify must be an object")
	}
	if len(fields) != 1 {
		return authModeStatic, true, fmt.Errorf("authverify must contain only mode")
	}
	mode, err := requiredRawString(fields, "mode")
	if err != nil {
		return authModeStatic, true, fmt.Errorf("invalid authverify mode: %w", err)
	}
	switch mode {
	case "static":
		return authModeStatic, true, nil
	case "grant":
		if !user {
			return authModeGrant, true, nil
		}
	}
	return authModeStatic, true, fmt.Errorf("unsupported authverify mode %q", mode)
}

func accountClaimsWithGrantMode(claims *jwt.AccountClaims, xp accountXPermissions, raw string) (*jwt.AccountClaims, accountClaimExtensions, string, error) {
	mode, _, err := decodeAuthModeJWT(raw, false)
	if err != nil {
		return nil, accountClaimExtensions{}, _EMPTY_, err
	}
	if mode == authModeGrant && claims.HasExternalAuthorization() {
		return nil, accountClaimExtensions{}, _EMPTY_, ErrAccountValidation
	}
	return claims, accountClaimExtensions{xpermissions: xp, authMode: mode}, raw, nil
}
