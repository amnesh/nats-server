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

// RefreshClientTraceLevel makes each open connection use the present trace
// setting of the server. A connection keeps the trace flag that it read when
// it connected, and only a config reload sets it again. A host that changes
// the flags with SetLogger or SetLoggerV2 calls this method after the change.
// It also applies when Options.NoLog is set. It sets the same connections as
// a config reload: clients, routes, gateways, leaf nodes, and the system
// client (from the TraceVerbose flag). It locks the server and each
// connection, so do not call it from a logger method or another server
// callback.
func (s *Server) RefreshClientTraceLevel() {
	s.setClientsTraceLevel()
}
