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

//go:build !skip_js_tests

package server

import (
	"reflect"
	"testing"

	"github.com/nats-io/nats.go"
)

// Accounts built in code get JetStream limits with SetJetStreamLimits, keep
// JetStream across ReloadOptions, and a memory stream keeps its messages.
func TestJetStreamAccountSetJetStreamLimitsReload(t *testing.T) {
	storeDir := t.TempDir()
	limits := map[string]JetStreamAccountLimits{_EMPTY_: {
		MaxMemory: 1024 * 1024, MaxStore: -1, MaxStreams: -1, MaxConsumers: -1,
	}}
	build := func(port int, limits map[string]JetStreamAccountLimits) *Options {
		o := DefaultTestOptions
		o.Port = port
		o.JetStream = true
		o.StoreDir = storeDir
		acc := NewAccount("A")
		acc.SetJetStreamLimits(limits)
		o.Accounts = []*Account{acc}
		o.Users = []*User{{Username: "a", Password: "pwd", Account: acc}}
		return &o
	}

	s := RunServer(build(-1, limits))
	defer s.Shutdown()
	port := s.getOpts().Port

	nc, js := jsClientConnect(t, s, nats.UserInfo("a", "pwd"))
	defer nc.Close()
	_, err := js.AddStream(&nats.StreamConfig{Name: "S", Subjects: []string{"s"}, Storage: nats.MemoryStorage})
	require_NoError(t, err)
	for range 10 {
		_, err = js.Publish("s", []byte("x"))
		require_NoError(t, err)
	}

	// New account objects with the limits set again.
	require_NoError(t, s.ReloadOptions(build(port, limits)))
	acc, err := s.LookupAccount("A")
	require_NoError(t, err)
	require_True(t, acc.JetStreamEnabled())
	si, err := js.StreamInfo("S")
	require_NoError(t, err)
	require_Equal(t, si.State.Msgs, 10)

	// A clone of the running options keeps the limits.
	require_NoError(t, s.ReloadOptions(s.getOpts().Clone()))
	require_True(t, acc.JetStreamEnabled())
	si, err = js.StreamInfo("S")
	require_NoError(t, err)
	require_Equal(t, si.State.Msgs, 10)

	// Without limits, the reload disables JetStream for the account.
	require_NoError(t, s.ReloadOptions(build(port, nil)))
	require_False(t, acc.JetStreamEnabled())
}

func TestJetStreamAccountSetJetStreamLimitsValues(t *testing.T) {
	acc := NewAccount("A")
	jsLimits := func() map[string]JetStreamAccountLimits {
		acc.mu.RLock()
		defer acc.mu.RUnlock()
		return acc.jsLimits
	}

	acc.SetJetStreamLimits(nil)
	require_True(t, jsLimits() == nil)

	acc.SetJetStreamLimits(map[string]JetStreamAccountLimits{})
	require_True(t, reflect.DeepEqual(jsLimits(), defaultJSAccountTiers))

	// The account keeps its own copy.
	in := map[string]JetStreamAccountLimits{_EMPTY_: {MaxMemory: 1}}
	acc.SetJetStreamLimits(in)
	in[_EMPTY_] = JetStreamAccountLimits{MaxMemory: 2}
	require_Equal(t, jsLimits()[_EMPTY_].MaxMemory, 1)
}
