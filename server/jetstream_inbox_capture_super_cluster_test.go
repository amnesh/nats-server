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

//go:build !skip_js_tests && !skip_js_cluster_tests && !skip_js_cluster_tests_2 && !skip_js_super_cluster_tests

package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestJetStreamSuperClusterInboxCaptureOriginTransit(t *testing.T) {
	// Use the established one-server-per-cluster gateway fixture. Every
	// advertised meta peer starts JetStream before the metagroup bootstraps.
	// The common supercluster helper selects $SYS as its system account.
	accounts := strings.Replace(inboxCaptureOriginAccounts, "system_account: SYS", "", 1)
	accounts = strings.Replace(accounts, "SYS {", "$SYS {", 1)
	tmpl := `
        listen: 127.0.0.1:-1
        server_name: %s
        jetstream {store_dir: '%s'}
        cluster {name: %s, listen: 127.0.0.1:%d, routes: [%s]}
    ` + accounts
	sc := createJetStreamSuperClusterWithTemplate(t, tmpl, 1, 2)
	defer sc.shutdown()
	leader := sc.leader()
	var source *Server
	for _, cluster := range sc.clusters {
		if cluster.name != leader.ClusterName() {
			source = cluster.randomServer()
			break
		}
	}
	if source == nil {
		t.Fatal("missing requester outside the meta leader's cluster")
	}
	require_True(t, source.ClusterName() != leader.ClusterName())
	host := inboxCaptureOriginConnect(t, source, "host", true)
	_, err := jsStreamCreate(t, host, &StreamConfig{
		Name: "GATEWAY_TRUSTED", Subjects: []string{"_INBOX.>"}, NoAck: true, Storage: MemoryStorage,
		Placement: &Placement{Cluster: leader.ClusterName()},
	})
	require_NoError(t, err)
	js, err := host.JetStream()
	require_NoError(t, err)
	info, err := js.StreamInfo("GATEWAY_TRUSTED")
	require_NoError(t, err)
	require_NotNil(t, info.Cluster)
	require_Equal(t, info.Cluster.Name, leader.ClusterName())
	require_NoError(t, js.DeleteStream("GATEWAY_TRUSTED"))
	for _, origin := range []struct {
		user  string
		iproc bool
	}{{"host", false}, {"bounded", true}} {
		nc := inboxCaptureOriginConnect(t, source, origin.user, origin.iproc)
		payload, err := json.Marshal(&StreamConfig{Name: "GATEWAY_REJECTED", Subjects: []string{"_INBOX.>"}, NoAck: true, Storage: MemoryStorage})
		require_NoError(t, err)
		request := nats.NewMsg(fmt.Sprintf(JSApiStreamCreateT, "GATEWAY_REJECTED"))
		request.Data = payload
		request.Header.Set(ClientInfoHdr, `{"acc":"APP","iproc_unrestricted":true}`)
		response, err := nc.RequestMsg(request, 5*time.Second)
		require_NoError(t, err)
		var result ApiResponse
		require_NoError(t, json.Unmarshal(response.Data, &result))
		requireInboxCaptureError(t, result.Error)
		_, err = js.StreamInfo("GATEWAY_REJECTED")
		require_Error(t, err)
	}
}
