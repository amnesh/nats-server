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

// runStampReqInfoServer starts a single server with stamp_request_info enabled
// and an account A holding a "req" (requestor) and "svc" (service) user.
func runStampReqInfoServer(t *testing.T) (*server.Server, *server.Options) {
	t.Helper()
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
	t.Cleanup(func() { os.Remove(conf) })
	srv, opts := RunServerWithConfig(conf)
	t.Cleanup(srv.Shutdown)
	return srv, opts
}

// A plain publish (no reply subject) is not a request, so even with the option
// enabled the server must not stamp it.
func TestStampRequestInfoNotStampedWithoutReply(t *testing.T) {
	_, opts := runStampReqInfoServer(t)

	svcNC, err := nats.Connect(fmt.Sprintf("nats://svc:pwd@%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error connecting service: %v", err)
	}
	defer svcNC.Close()

	hdrCh := make(chan string, 1)
	if _, err := svcNC.Subscribe("svc.event", func(msg *nats.Msg) {
		hdrCh <- msg.Header.Get(server.ClientInfoHdr)
	}); err != nil {
		t.Fatalf("Error subscribing: %v", err)
	}
	svcNC.Flush()

	reqNC, err := nats.Connect(fmt.Sprintf("nats://req:pwd@%s:%d", opts.Host, opts.Port), nats.Name("requestor"))
	if err != nil {
		t.Fatalf("Error connecting requester: %v", err)
	}
	defer reqNC.Close()

	// Fire-and-forget: no reply subject.
	if err := reqNC.Publish("svc.event", []byte("ping")); err != nil {
		t.Fatalf("Error publishing: %v", err)
	}
	reqNC.Flush()

	select {
	case hdr := <-hdrCh:
		if hdr != "" {
			t.Fatalf("Expected no CI header on a non-request publish, got %q", hdr)
		}
	case <-time.After(time.Second):
		t.Fatal("Did not receive published message")
	}
}

// Requests on the internal subject spaces ($JS./$KV./$O./$MQTT./$NRG.) must not
// be stamped, while a request on any other $-prefixed subject is stamped.
func TestStampRequestInfoSkippedSubjects(t *testing.T) {
	_, opts := runStampReqInfoServer(t)

	svcNC, err := nats.Connect(fmt.Sprintf("nats://svc:pwd@%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error connecting service: %v", err)
	}
	defer svcNC.Close()

	reqNC, err := nats.Connect(fmt.Sprintf("nats://req:pwd@%s:%d", opts.Host, opts.Port), nats.Name("requestor"))
	if err != nil {
		t.Fatalf("Error connecting requester: %v", err)
	}
	defer reqNC.Close()

	check := func(t *testing.T, subject string, wantStamped bool) {
		t.Helper()
		hdrCh := make(chan string, 1)
		sub, err := svcNC.Subscribe(subject, func(msg *nats.Msg) {
			hdrCh <- msg.Header.Get(server.ClientInfoHdr)
			_ = msg.Respond([]byte("ok"))
		})
		if err != nil {
			t.Fatalf("Error subscribing to %q: %v", subject, err)
		}
		defer sub.Unsubscribe()
		svcNC.Flush()

		if _, err := reqNC.Request(subject, []byte("hello"), time.Second); err != nil {
			t.Fatalf("Request to %q failed: %v", subject, err)
		}
		select {
		case hdr := <-hdrCh:
			if wantStamped && hdr == "" {
				t.Fatalf("Subject %q: expected a CI header, got none", subject)
			}
			if !wantStamped && hdr != "" {
				t.Fatalf("Subject %q: expected no CI header, got %q", subject, hdr)
			}
		case <-time.After(time.Second):
			t.Fatalf("Subject %q: did not receive request", subject)
		}
	}

	// Note: $NRG.* is also skipped, but a normal client is blocked from
	// publishing there (pubPermissionViolation) before stamping is reached, so
	// it cannot be exercised over the wire. It is covered by the unit tests
	// TestSkipRequestInfoStamp and TestStampRequestInfoHeaderIfNeeded instead.
	for _, subject := range []string{
		"$JS.API.STREAM.INFO.foo",
		"$KV.bucket.key",
		"$O.obj.chunk",
		"$MQTT.msgs.foo",
	} {
		t.Run("skipped/"+subject, func(t *testing.T) { check(t, subject, false) })
	}

	// A $-prefixed subject that is not one of the skipped spaces is stamped.
	t.Run("stamped/$XYZ.req", func(t *testing.T) { check(t, "$XYZ.req", true) })
}

// A client must not be able to spoof the request info: a ClientInfoHdr supplied
// by the requestor is overwritten with the server's authoritative value.
func TestStampRequestInfoClientCannotSpoofHeader(t *testing.T) {
	_, opts := runStampReqInfoServer(t)

	svcNC, err := nats.Connect(fmt.Sprintf("nats://svc:pwd@%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error connecting service: %v", err)
	}
	defer svcNC.Close()

	ciCh := make(chan string, 1)
	if _, err := svcNC.Subscribe("svc.echo", func(msg *nats.Msg) {
		ciCh <- msg.Header.Get(server.ClientInfoHdr)
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

	msg := nats.NewMsg("svc.echo")
	msg.Data = []byte("hello")
	// Attempt to impersonate the admin account/user.
	msg.Header.Set(server.ClientInfoHdr, `{"acc":"SYS","user":"admin"}`)
	if _, err := reqNC.RequestMsg(msg, time.Second); err != nil {
		t.Fatalf("Unexpected request error: %v", err)
	}

	select {
	case hdr := <-ciCh:
		if hdr == "" {
			t.Fatal("Expected server-stamped CI header")
		}
		var ci server.ClientInfo
		if err := json.Unmarshal([]byte(hdr), &ci); err != nil {
			t.Fatalf("Error unmarshaling CI %q: %v", hdr, err)
		}
		if ci.Account != "A" || ci.User != "req" {
			t.Fatalf("Spoofed values not overwritten, got acc=%q user=%q", ci.Account, ci.User)
		}
	case <-time.After(time.Second):
		t.Fatal("Did not receive service request")
	}
}

// Stamping must preserve any other headers the requestor set on the message.
func TestStampRequestInfoPreservesExistingHeaders(t *testing.T) {
	_, opts := runStampReqInfoServer(t)

	svcNC, err := nats.Connect(fmt.Sprintf("nats://svc:pwd@%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error connecting service: %v", err)
	}
	defer svcNC.Close()

	type capture struct {
		trace string
		ci    string
	}
	ch := make(chan capture, 1)
	if _, err := svcNC.Subscribe("svc.echo", func(msg *nats.Msg) {
		ch <- capture{trace: msg.Header.Get("X-Trace-Id"), ci: msg.Header.Get(server.ClientInfoHdr)}
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

	msg := nats.NewMsg("svc.echo")
	msg.Data = []byte("hello")
	msg.Header.Set("X-Trace-Id", "abc123")
	if _, err := reqNC.RequestMsg(msg, time.Second); err != nil {
		t.Fatalf("Unexpected request error: %v", err)
	}

	select {
	case c := <-ch:
		if c.trace != "abc123" {
			t.Fatalf("Existing header lost, X-Trace-Id=%q", c.trace)
		}
		if c.ci == "" {
			t.Fatal("Expected CI header alongside existing headers")
		}
		var ci server.ClientInfo
		if err := json.Unmarshal([]byte(c.ci), &ci); err != nil {
			t.Fatalf("Error unmarshaling CI %q: %v", c.ci, err)
		}
		if ci.User != "req" {
			t.Fatalf("Unexpected CI user %q", ci.User)
		}
	case <-time.After(time.Second):
		t.Fatal("Did not receive service request")
	}
}

// The trimmed CI carries the requestor's connection metadata: kind, client
// type, language and host.
func TestStampRequestInfoFullClientInfoFields(t *testing.T) {
	_, opts := runStampReqInfoServer(t)

	svcNC, err := nats.Connect(fmt.Sprintf("nats://svc:pwd@%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error connecting service: %v", err)
	}
	defer svcNC.Close()

	ciCh := make(chan *server.ClientInfo, 1)
	if _, err := svcNC.Subscribe("svc.echo", func(msg *nats.Msg) {
		var ci server.ClientInfo
		if hdr := msg.Header.Get(server.ClientInfoHdr); hdr != "" {
			if err := json.Unmarshal([]byte(hdr), &ci); err != nil {
				t.Errorf("Error unmarshaling CI: %v", err)
			}
		}
		ciCh <- &ci
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

	if _, err := reqNC.Request("svc.echo", []byte("hello"), time.Second); err != nil {
		t.Fatalf("Unexpected request error: %v", err)
	}

	select {
	case ci := <-ciCh:
		if ci.Kind != "Client" {
			t.Fatalf("Expected kind Client, got %q", ci.Kind)
		}
		if ci.ClientType != "nats" {
			t.Fatalf("Expected client type nats, got %q", ci.ClientType)
		}
		if ci.Lang != "go" {
			t.Fatalf("Expected lang go, got %q", ci.Lang)
		}
		if ci.Host == "" {
			t.Fatal("Expected non-empty host")
		}
	case <-time.After(time.Second):
		t.Fatal("Did not receive service request")
	}
}

// Token-based auth must never leak the token: the stamped CI user is redacted.
func TestStampRequestInfoTokenAuthUserRedacted(t *testing.T) {
	conf := createConfFile(t, []byte(`
		listen: 127.0.0.1:-1
		stamp_request_info: true
		authorization { token: s3cr3t }
	`))
	defer os.Remove(conf)
	srv, opts := RunServerWithConfig(conf)
	defer srv.Shutdown()

	svcNC, err := nats.Connect(fmt.Sprintf("nats://s3cr3t@%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error connecting service: %v", err)
	}
	defer svcNC.Close()

	ciCh := make(chan *server.ClientInfo, 1)
	if _, err := svcNC.Subscribe("svc.echo", func(msg *nats.Msg) {
		var ci server.ClientInfo
		if hdr := msg.Header.Get(server.ClientInfoHdr); hdr != "" {
			if err := json.Unmarshal([]byte(hdr), &ci); err != nil {
				t.Errorf("Error unmarshaling CI: %v", err)
			}
		}
		ciCh <- &ci
		_ = msg.Respond([]byte("ok"))
	}); err != nil {
		t.Fatalf("Error subscribing: %v", err)
	}
	svcNC.Flush()

	reqNC, err := nats.Connect(fmt.Sprintf("nats://s3cr3t@%s:%d", opts.Host, opts.Port), nats.Name("requestor"))
	if err != nil {
		t.Fatalf("Error connecting requester: %v", err)
	}
	defer reqNC.Close()

	if _, err := reqNC.Request("svc.echo", []byte("hello"), time.Second); err != nil {
		t.Fatalf("Unexpected request error: %v", err)
	}

	select {
	case ci := <-ciCh:
		if ci.User != "[REDACTED]" {
			t.Fatalf("Expected redacted token user, got %q", ci.User)
		}
	case <-time.After(time.Second):
		t.Fatal("Did not receive service request")
	}
}
