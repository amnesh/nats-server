package test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// stamp_request_info must be reloadable via SIGHUP: toggling it on causes
// subsequent requests to carry the header, toggling it back off removes it.
func TestStampRequestInfoReload(t *testing.T) {
	const tmpl = `
		listen: 127.0.0.1:-1
		stamp_request_info: %s

		accounts: {
			A: {
				users: [
					{user: req, password: pwd}
					{user: svc, password: pwd}
				]
			}
		}
	`
	conf := createConfFile(t, []byte(fmt.Sprintf(tmpl, "false")))
	defer os.Remove(conf)

	srv, opts := RunServerWithConfig(conf)
	defer srv.Shutdown()

	svcNC, err := nats.Connect(fmt.Sprintf("nats://svc:pwd@%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error connecting service: %v", err)
	}
	defer svcNC.Close()

	var lastHdr atomic.Value
	lastHdr.Store("")
	if _, err := svcNC.Subscribe("svc.echo", func(msg *nats.Msg) {
		lastHdr.Store(msg.Header.Get(server.ClientInfoHdr))
		_ = msg.Respond([]byte("ok"))
	}); err != nil {
		t.Fatalf("Error subscribing: %v", err)
	}
	svcNC.Flush()

	reqNC, err := nats.Connect(fmt.Sprintf("nats://req:pwd@%s:%d", opts.Host, opts.Port), nats.Name("requestor"))
	if err != nil {
		t.Fatalf("Error connecting requester: %v", err)
	}
	defer reqNC.Close()

	doRequest := func() {
		t.Helper()
		if _, err := reqNC.Request("svc.echo", []byte("hello"), time.Second); err != nil {
			t.Fatalf("Unexpected request error: %v", err)
		}
	}

	// Initially disabled: no header.
	doRequest()
	if h := lastHdr.Load().(string); h != "" {
		t.Fatalf("Expected no CI header before reload, got %q", h)
	}

	// Reload with the option enabled.
	if err := os.WriteFile(conf, []byte(fmt.Sprintf(tmpl, "true")), 0666); err != nil {
		t.Fatalf("Error rewriting conf: %v", err)
	}
	if err := srv.Reload(); err != nil {
		t.Fatalf("Reload to enabled failed: %v", err)
	}
	doRequest()
	hdr := lastHdr.Load().(string)
	if hdr == "" {
		t.Fatal("Expected CI header after enabling reload, got none")
	}
	var ci server.ClientInfo
	if err := json.Unmarshal([]byte(hdr), &ci); err != nil {
		t.Fatalf("Error unmarshaling CI: %v", err)
	}
	if ci.User != "req" || ci.Name != "requestor" || ci.Account != "A" {
		t.Fatalf("Unexpected CI after enable: %+v", ci)
	}

	// Reload again with the option disabled — header must stop appearing.
	if err := os.WriteFile(conf, []byte(fmt.Sprintf(tmpl, "false")), 0666); err != nil {
		t.Fatalf("Error rewriting conf: %v", err)
	}
	if err := srv.Reload(); err != nil {
		t.Fatalf("Reload to disabled failed: %v", err)
	}
	lastHdr.Store("")
	doRequest()
	if h := lastHdr.Load().(string); h != "" {
		t.Fatalf("Expected no CI header after disabling reload, got %q", h)
	}
}

// When stamp_request_info is not enabled, the server must not attach the
// ClientInfoHdr on same-account direct requests.
func TestDirectServiceRequestStampRequestInfoDisabledByDefault(t *testing.T) {
	conf := createConfFile(t, []byte(`
		listen: 127.0.0.1:-1

		accounts: {
			A: {
				users: [
					{user: req, password: pwd}
					{user: svc, password: pwd}
				]
			}
		}
	`))
	defer os.Remove(conf)

	srv, opts := RunServerWithConfig(conf)
	defer srv.Shutdown()

	svcNC, err := nats.Connect(fmt.Sprintf("nats://svc:pwd@%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer svcNC.Close()

	hdrCh := make(chan string, 1)
	if _, err := svcNC.Subscribe("svc.echo", func(msg *nats.Msg) {
		hdrCh <- msg.Header.Get(server.ClientInfoHdr)
		_ = msg.Respond([]byte("ok"))
	}); err != nil {
		t.Fatalf("Error subscribing service: %v", err)
	}
	svcNC.Flush()

	reqNC, err := nats.Connect(fmt.Sprintf("nats://req:pwd@%s:%d", opts.Host, opts.Port), nats.Name("requestor"))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer reqNC.Close()

	if _, err := reqNC.Request("svc.echo", []byte("hello"), time.Second); err != nil {
		t.Fatalf("Unexpected request error: %v", err)
	}

	select {
	case hdr := <-hdrCh:
		if hdr != "" {
			t.Fatalf("Expected no ClientInfoHdr when stamp_request_info is disabled, got %q", hdr)
		}
	case <-time.After(time.Second):
		t.Fatal("Did not receive service request")
	}
}

func TestDirectServiceRequestSharesRequestUserInfo(t *testing.T) {
	conf := createConfFile(t, []byte(`
		listen: 127.0.0.1:-1
		stamp_request_info: true

		accounts: {
			A: {
				users: [
					{user: req, password: pwd}
					{user: svc, password: pwd}
				]
			}
		}
	`))
	defer os.Remove(conf)

	srv, opts := RunServerWithConfig(conf)
	defer srv.Shutdown()

	svcNC, err := nats.Connect(fmt.Sprintf("nats://svc:pwd@%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer svcNC.Close()

	ciCh := make(chan *server.ClientInfo, 1)
	if _, err := svcNC.Subscribe("svc.echo", func(msg *nats.Msg) {
		var ci server.ClientInfo
		if hdr := msg.Header.Get(server.ClientInfoHdr); hdr != "" {
			if err := json.Unmarshal([]byte(hdr), &ci); err != nil {
				t.Errorf("Error unmarshaling client info header: %v", err)
			}
		}
		ciCh <- &ci
		if err := msg.Respond([]byte("ok")); err != nil {
			t.Errorf("Error responding: %v", err)
		}
	}); err != nil {
		t.Fatalf("Error subscribing service: %v", err)
	}
	svcNC.Flush()

	reqNC, err := nats.Connect(fmt.Sprintf("nats://req:pwd@%s:%d", opts.Host, opts.Port), nats.Name("requestor"))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer reqNC.Close()

	resp, err := reqNC.Request("svc.echo", []byte("hello"), time.Second)
	if err != nil {
		t.Fatalf("Unexpected request error: %v", err)
	}
	if string(resp.Data) != "ok" {
		t.Fatalf("Unexpected response: %q", resp.Data)
	}

	select {
	case ci := <-ciCh:
		if ci == nil {
			t.Fatal("Expected client info")
		}
		if ci.Account != "A" {
			t.Fatalf("Expected account A, got %q", ci.Account)
		}
		if ci.User != "req" {
			t.Fatalf("Expected user req, got %q", ci.User)
		}
		if ci.Name != "requestor" {
			t.Fatalf("Expected client name requestor, got %q", ci.Name)
		}
		// stamp uses getClientInfoForRequest: trimmed shape — Jwt/IssuerKey/Tags/Start/ID/Version should not be set.
		if ci.Jwt != "" || ci.IssuerKey != "" || len(ci.Tags) != 0 || ci.Start != nil || ci.ID != 0 || ci.Version != "" {
			t.Fatalf("Unexpected detailed fields present in trimmed CI: %+v", ci)
		}
	case <-time.After(time.Second):
		t.Fatal("Did not receive service request")
	}
}

// Asserts the originator's CI survives a route hop unchanged: requester on srvA,
// responder on srvB, single shared account, single cluster.
func TestRoutedRequestSharesRequestUserInfo(t *testing.T) {
	confA := createConfFile(t, []byte(`
		server_name: A
		listen: 127.0.0.1:-1
		stamp_request_info: true
		cluster { name: C, listen: 127.0.0.1:-1 }
		accounts: { A: { users: [{user: req, password: pwd}, {user: svc, password: pwd}] } }
	`))
	defer os.Remove(confA)
	srvA, optsA := RunServerWithConfig(confA)
	defer srvA.Shutdown()

	confB := createConfFile(t, []byte(fmt.Sprintf(`
		server_name: B
		listen: 127.0.0.1:-1
		stamp_request_info: true
		cluster { name: C, listen: 127.0.0.1:-1, routes: [nats-route://%s:%d] }
		accounts: { A: { users: [{user: req, password: pwd}, {user: svc, password: pwd}] } }
	`, optsA.Cluster.Host, optsA.Cluster.Port)))
	defer os.Remove(confB)
	srvB, optsB := RunServerWithConfig(confB)
	defer srvB.Shutdown()

	checkClusterFormed(t, srvA, srvB)

	svcNC, err := nats.Connect(fmt.Sprintf("nats://svc:pwd@%s:%d", optsB.Host, optsB.Port))
	if err != nil {
		t.Fatalf("Error connecting service client: %v", err)
	}
	defer svcNC.Close()

	ciCh := make(chan *server.ClientInfo, 1)
	if _, err := svcNC.Subscribe("svc.echo", func(msg *nats.Msg) {
		var ci server.ClientInfo
		if hdr := msg.Header.Get(server.ClientInfoHdr); hdr != "" {
			if err := json.Unmarshal([]byte(hdr), &ci); err != nil {
				t.Errorf("Error unmarshaling client info header: %v", err)
			}
		}
		ciCh <- &ci
		if err := msg.Respond([]byte("ok")); err != nil {
			t.Errorf("Error responding: %v", err)
		}
	}); err != nil {
		t.Fatalf("Error subscribing service: %v", err)
	}
	svcNC.Flush()

	reqNC, err := nats.Connect(fmt.Sprintf("nats://req:pwd@%s:%d", optsA.Host, optsA.Port), nats.Name("requestor"))
	if err != nil {
		t.Fatalf("Error connecting requester: %v", err)
	}
	defer reqNC.Close()

	checkFor(t, 2*time.Second, 50*time.Millisecond, func() error {
		resp, err := reqNC.Request("svc.echo", []byte("hello"), 250*time.Millisecond)
		if err != nil {
			return err
		}
		if string(resp.Data) != "ok" {
			return fmt.Errorf("unexpected response: %q", resp.Data)
		}
		return nil
	})

	select {
	case ci := <-ciCh:
		if ci == nil {
			t.Fatal("Expected client info")
		}
		if ci.Account != "A" {
			t.Fatalf("Expected account A, got %q", ci.Account)
		}
		if ci.User != "req" {
			t.Fatalf("Expected user req (originator preserved across route), got %q", ci.User)
		}
		if ci.Name != "requestor" {
			t.Fatalf("Expected client name requestor, got %q", ci.Name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Did not receive service request")
	}
}

// Asserts the originator's CI survives a gateway hop unchanged: requester on
// cluster CA, responder on cluster CB, single shared account.
func TestGatewayRequestSharesRequestUserInfo(t *testing.T) {
	server.GatewayDoNotForceInterestOnlyMode(true)
	defer server.GatewayDoNotForceInterestOnlyMode(false)

	// Cluster B (responder).
	oB := testDefaultOptionsForGateway("B")
	oB.StampRequestInfo = true
	oB.Accounts = []*server.Account{server.NewAccount("A")}
	oB.Users = []*server.User{{Username: "req", Password: "pwd", Account: oB.Accounts[0]}, {Username: "svc", Password: "pwd", Account: oB.Accounts[0]}}
	srvB := runGatewayServer(oB)
	defer srvB.Shutdown()

	// Cluster A (requester) with a gateway pointing at B.
	oA := testDefaultOptionsForGateway("A")
	oA.StampRequestInfo = true
	oA.Accounts = []*server.Account{server.NewAccount("A")}
	oA.Users = []*server.User{{Username: "req", Password: "pwd", Account: oA.Accounts[0]}, {Username: "svc", Password: "pwd", Account: oA.Accounts[0]}}
	rurl, _ := url.Parse(fmt.Sprintf("nats://%s:%d", oB.Gateway.Host, oB.Gateway.Port))
	oA.Gateway.Gateways = []*server.RemoteGatewayOpts{{Name: "B", URLs: []*url.URL{rurl}}}
	srvA := runGatewayServer(oA)
	defer srvA.Shutdown()

	waitForOutboundGateways(t, srvA, 1, 10*time.Second)
	waitForOutboundGateways(t, srvB, 1, 10*time.Second)

	svcNC, err := nats.Connect(fmt.Sprintf("nats://svc:pwd@%s:%d", oB.Host, oB.Port))
	if err != nil {
		t.Fatalf("Error connecting service client: %v", err)
	}
	defer svcNC.Close()

	ciCh := make(chan *server.ClientInfo, 1)
	if _, err := svcNC.Subscribe("svc.echo", func(msg *nats.Msg) {
		var ci server.ClientInfo
		if hdr := msg.Header.Get(server.ClientInfoHdr); hdr != "" {
			if err := json.Unmarshal([]byte(hdr), &ci); err != nil {
				t.Errorf("Error unmarshaling client info header: %v", err)
			}
		}
		ciCh <- &ci
		if err := msg.Respond([]byte("ok")); err != nil {
			t.Errorf("Error responding: %v", err)
		}
	}); err != nil {
		t.Fatalf("Error subscribing service: %v", err)
	}
	svcNC.Flush()

	reqNC, err := nats.Connect(fmt.Sprintf("nats://req:pwd@%s:%d", oA.Host, oA.Port), nats.Name("requestor"))
	if err != nil {
		t.Fatalf("Error connecting requester: %v", err)
	}
	defer reqNC.Close()

	checkFor(t, 2*time.Second, 50*time.Millisecond, func() error {
		resp, err := reqNC.Request("svc.echo", []byte("hello"), 250*time.Millisecond)
		if err != nil {
			return err
		}
		if string(resp.Data) != "ok" {
			return fmt.Errorf("unexpected response: %q", resp.Data)
		}
		return nil
	})

	select {
	case ci := <-ciCh:
		if ci == nil {
			t.Fatal("Expected client info")
		}
		if ci.Account != "A" {
			t.Fatalf("Expected account A, got %q", ci.Account)
		}
		if ci.User != "req" {
			t.Fatalf("Expected user req (originator preserved across gateway), got %q", ci.User)
		}
		if ci.Name != "requestor" {
			t.Fatalf("Expected client name requestor, got %q", ci.Name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Did not receive service request")
	}
}

func TestLeafNodeDirectServiceRequestSharesRequestUserInfo(t *testing.T) {
	hubAcc := server.NewAccount("A")
	hubOpts := testDefaultOptionsForLeafNodes()
	hubOpts.StampRequestInfo = true
	hubOpts.Accounts = []*server.Account{hubAcc}
	hubOpts.Users = []*server.User{{Username: "svc", Password: "pwd", Account: hubAcc}}
	hubOpts.LeafNode.Users = []*server.User{{Username: "leaf", Password: "pwd", Account: hubAcc}}
	hub := RunServer(hubOpts)
	defer hub.Shutdown()

	leafAcc := server.NewAccount("A")
	leafOpts := testDefaultOptionsForLeafNodes()
	leafOpts.StampRequestInfo = true
	leafOpts.Accounts = []*server.Account{leafAcc}
	leafOpts.Users = []*server.User{{Username: "req", Password: "pwd", Account: leafAcc}}
	rurl, err := url.Parse(fmt.Sprintf("nats-leaf://leaf:pwd@%s:%d", hubOpts.LeafNode.Host, hubOpts.LeafNode.Port))
	if err != nil {
		t.Fatalf("Error parsing leaf URL: %v", err)
	}
	leafOpts.LeafNode.Remotes = []*server.RemoteLeafOpts{{URLs: []*url.URL{rurl}, LocalAccount: "A"}}
	leaf := RunServer(leafOpts)
	defer leaf.Shutdown()

	checkLeafNodeConnected(t, hub)

	svcNC, err := nats.Connect(fmt.Sprintf("nats://svc:pwd@%s:%d", hubOpts.Host, hubOpts.Port))
	if err != nil {
		t.Fatalf("Error connecting service client: %v", err)
	}
	defer svcNC.Close()

	ciCh := make(chan *server.ClientInfo, 1)
	if _, err := svcNC.Subscribe("svc.echo", func(msg *nats.Msg) {
		var ci server.ClientInfo
		if hdr := msg.Header.Get(server.ClientInfoHdr); hdr != "" {
			if err := json.Unmarshal([]byte(hdr), &ci); err != nil {
				t.Errorf("Error unmarshaling client info header: %v", err)
			}
		}
		ciCh <- &ci
		if err := msg.Respond([]byte("ok")); err != nil {
			t.Errorf("Error responding: %v", err)
		}
	}); err != nil {
		t.Fatalf("Error subscribing service: %v", err)
	}
	svcNC.Flush()

	reqNC, err := nats.Connect(fmt.Sprintf("nats://req:pwd@%s:%d", leafOpts.Host, leafOpts.Port), nats.Name("leaf-requestor"))
	if err != nil {
		t.Fatalf("Error connecting requester client: %v", err)
	}
	defer reqNC.Close()

	checkFor(t, 2*time.Second, 50*time.Millisecond, func() error {
		resp, err := reqNC.Request("svc.echo", []byte("hello"), 250*time.Millisecond)
		if err != nil {
			return err
		}
		if string(resp.Data) != "ok" {
			return fmt.Errorf("unexpected response: %q", resp.Data)
		}
		return nil
	})

	select {
	case ci := <-ciCh:
		if ci == nil {
			t.Fatal("Expected client info")
		}
		if ci.Account != "A" {
			t.Fatalf("Expected account A, got %q", ci.Account)
		}
		if ci.User != "leaf" {
			t.Fatalf("Expected user leaf, got %q", ci.User)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Did not receive service request")
	}
}
