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

import "maps"

// SetJetStreamLimits records JetStream limits on an account that is given to
// the server in Options.Accounts, the same as `jetstream` in an account block
// of a config file. Use it before the account is registered (server start) or
// before it is passed to ReloadOptions. It does not enable JetStream on a
// running account: the server reads the limits at start and at each reload,
// and only when server-wide JetStream is enabled.
//
// At a reload, an account without limits has JetStream disabled. Accounts
// built for ReloadOptions must have the limits set again, except accounts
// copied with Options.Clone, which keeps them.
//
// A nil map means no JetStream for the account. An empty map means the
// default (dynamic) limits. The map is copied.
func (a *Account) SetJetStreamLimits(limits map[string]JetStreamAccountLimits) {
	switch {
	case limits == nil:
	case len(limits) == 0:
		limits = defaultJSAccountTiers
	default:
		limits = maps.Clone(limits)
	}
	a.assignJetStreamLimits(limits)
}
