package server

import (
	"encoding/json"
	"testing"
	"time"
)

// skipRequestInfoStamp must only skip the documented internal subject spaces,
// matching them as exact "$PREFIX." prefixes (case sensitive, dot required).
func TestSkipRequestInfoStamp(t *testing.T) {
	for _, tc := range []struct {
		subject string
		skip    bool
	}{
		// Non-$ subjects are never skipped, even if a prefix appears later.
		{"", false},
		{"foo.bar", false},
		{"foo.$JS.x", false},
		// The five documented internal prefixes are skipped.
		{"$JS.API.STREAM.INFO.foo", true},
		{"$KV.bucket.key", true},
		{"$O.obj.chunk", true},
		{"$MQTT.msgs.foo", true},
		{"$NRG.R.peer", true},
		// $-prefixed subjects that are not in the skip list are stamped.
		{"$SYS.REQ.SERVER.PING", false},
		{"$G.foo", false},
		// The trailing dot is part of the prefix: near-misses are not skipped.
		{"$JSX.not", false},
		{"$JS", false},
		{"$", false},
		{"$KVX.x", false},
		{"$NRGG", false},
		// Matching is case sensitive.
		{"$js.lower", false},
	} {
		if got := skipRequestInfoStamp([]byte(tc.subject)); got != tc.skip {
			t.Errorf("skipRequestInfoStamp(%q) = %v, want %v", tc.subject, got, tc.skip)
		}
	}
}

// getClientInfoForRequest returns a trimmed ClientInfo only for the connection
// kinds that can originate a stampable request, and nil otherwise.
func TestGetClientInfoForRequest(t *testing.T) {
	// A nil receiver must be handled gracefully.
	var nilc *client
	if ci := nilc.getClientInfoForRequest(); ci != nil {
		t.Fatalf("Expected nil for nil client, got %+v", ci)
	}

	for _, tc := range []struct {
		kind int
		want bool
	}{
		{CLIENT, true},
		{LEAF, true},
		{JETSTREAM, true},
		{ACCOUNT, true},
		{ROUTER, false},
		{GATEWAY, false},
		{SYSTEM, false},
		{-1, false},
	} {
		c := &client{kind: tc.kind}
		if ci := c.getClientInfoForRequest(); (ci != nil) != tc.want {
			t.Fatalf("kind %d: got non-nil=%v, want %v", tc.kind, ci != nil, tc.want)
		}
	}

	// Identity and connection fields are copied from the client, and the
	// heavier detailed fields are left unset (the trimmed form).
	c := &client{kind: CLIENT, host: "10.0.0.1", rtt: 5 * time.Millisecond}
	c.acc = &Account{Name: "ACC"}
	c.opts.Username = "alice"
	c.opts.Name = "myapp"
	c.opts.Lang = "go"

	ci := c.getClientInfoForRequest()
	if ci == nil {
		t.Fatal("Expected client info")
	}
	if ci.Account != "ACC" || ci.User != "alice" || ci.Name != "myapp" || ci.Lang != "go" {
		t.Fatalf("Unexpected identity fields: %+v", ci)
	}
	if ci.Kind != "Client" || ci.ClientType != "nats" {
		t.Fatalf("Unexpected kind/type: kind=%q type=%q", ci.Kind, ci.ClientType)
	}
	if ci.Host != "10.0.0.1" || ci.RTT != 5*time.Millisecond {
		t.Fatalf("Unexpected host/rtt: host=%q rtt=%v", ci.Host, ci.RTT)
	}
	if ci.Jwt != "" || ci.IssuerKey != "" || len(ci.Tags) != 0 || ci.Start != nil ||
		ci.ID != 0 || ci.Version != "" || ci.Server != "" || ci.Cluster != "" {
		t.Fatalf("Detailed fields unexpectedly set on trimmed CI: %+v", ci)
	}
}

// getRawAuthUser drives the CI.User field, and must redact token-based auth so
// the secret is never leaked into a stamped request.
func TestGetClientInfoForRequestAuthUser(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(c *client)
		want  string
	}{
		{"username", func(c *client) { c.opts.Username = "bob" }, "bob"},
		{"nkey", func(c *client) { c.opts.Nkey = "UABC" }, "UABC"},
		{"jwt", func(c *client) { c.opts.JWT = "ey.jwt"; c.pubKey = "UPUB" }, "UPUB"},
		{"token", func(c *client) { c.opts.Token = "s3cr3t" }, "[REDACTED]"},
		{"anonymous", func(c *client) {}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &client{kind: CLIENT}
			tc.setup(c)
			if ci := c.getClientInfoForRequest(); ci.User != tc.want {
				t.Fatalf("User = %q, want %q", ci.User, tc.want)
			}
		})
	}
}

// stampRequestInfoHeaderIfNeeded must stamp exactly when the option is on, the
// connection is a CLIENT/LEAF, the message carries a reply, and the subject is
// not one of the skipped prefixes — and otherwise return the message untouched.
func TestStampRequestInfoHeaderIfNeeded(t *testing.T) {
	mkClient := func(kind int, stamp bool) *client {
		s := &Server{opts: &Options{StampRequestInfo: stamp}}
		s.stampReqInfo.Store(stamp)
		c := &client{kind: kind, srv: s, host: "127.0.0.1"}
		c.acc = &Account{Name: "A"}
		c.opts.Username = "req"
		c.opts.Name = "reqname"
		c.pa.subject = []byte("svc.echo")
		c.pa.reply = []byte("_INBOX.1")
		return c
	}

	payload := []byte("hello")

	t.Run("stamps client request", func(t *testing.T) {
		c := mkClient(CLIENT, true)
		out := c.stampRequestInfoHeaderIfNeeded(payload)
		hdr := getHeader(ClientInfoHdr, out)
		if hdr == nil {
			t.Fatal("Expected header to be stamped")
		}
		var ci ClientInfo
		if err := json.Unmarshal(hdr, &ci); err != nil {
			t.Fatalf("Bad CI JSON %q: %v", hdr, err)
		}
		if ci.User != "req" || ci.Account != "A" || ci.Name != "reqname" {
			t.Fatalf("Unexpected CI: %+v", ci)
		}
		// pubArgs must be updated so downstream delivery sees the new header:
		// hdr marks the boundary between the header block and the original body.
		if c.pa.hdr <= 0 || string(out[c.pa.hdr:]) != string(payload) {
			t.Fatalf("pubArgs not updated: hdr=%d out=%q", c.pa.hdr, out)
		}
	})

	t.Run("stamps leaf request", func(t *testing.T) {
		c := mkClient(LEAF, true)
		if getHeader(ClientInfoHdr, c.stampRequestInfoHeaderIfNeeded(payload)) == nil {
			t.Fatal("Expected header for LEAF")
		}
	})

	// On a LEAF inbound, a forwarded ClientInfoHdr from a remote domain
	// must have its identity replaced (the leaf connection's auth, not the
	// forwarded values), but its Reply field must be preserved so chained
	// service-import responses can be routed back across the leaf boundary
	// (mirrors the logic at client.go:4901-4926).
	t.Run("leaf preserves forwarded Reply when replacing identity", func(t *testing.T) {
		c := mkClient(LEAF, true)
		// Build a message carrying a forwarded CI from the remote domain:
		// different account/user/name plus a Reply that came from the
		// original requestor's service-import chain.
		fwd, err := json.Marshal(&ClientInfo{
			Account: "REMOTE", User: "alice", Name: "remote-app",
			Reply: "_INBOX.original.42",
		})
		if err != nil {
			t.Fatalf("marshal forwarded CI: %v", err)
		}
		// Construct the HMSG-style buffer: hdrLine + CI header + CRLF + body.
		// setHeader-on-empty produces this exact shape so we can reuse it
		// to prime the inbound message.
		c.pa.hdr = 0
		primed := c.setHeader(ClientInfoHdr, bytesToString(fwd), payload)
		// c.pa.hdr/size are now set to match `primed`. Reset the cache so
		// the stamp does a fresh build under this LEAF identity.
		c.ciStampHdr = nil

		out := c.stampRequestInfoHeaderIfNeeded(primed)
		hdr := getHeader(ClientInfoHdr, out)
		if hdr == nil {
			t.Fatal("Expected CI header on output")
		}
		var stamped ClientInfo
		if err := json.Unmarshal(hdr, &stamped); err != nil {
			t.Fatalf("Bad CI JSON: %v", err)
		}
		// Identity is replaced with the leaf connection's own auth.
		if stamped.Account == "REMOTE" || stamped.User == "alice" || stamped.Name == "remote-app" {
			t.Fatalf("Forwarded identity must be replaced, got %+v", stamped)
		}
		if stamped.Account != "A" || stamped.User != "req" {
			t.Fatalf("Identity not replaced with leaf connection's, got %+v", stamped)
		}
		// Reply from the forwarded CI must survive.
		if stamped.Reply != "_INBOX.original.42" {
			t.Fatalf("Forwarded Reply not preserved, got %q", stamped.Reply)
		}
	})

	// When the option is enabled and the message has no forwarded CI, the
	// stamped header must NOT carry a Reply (the trimmed CI deliberately
	// omits it; older code never set it for the common path).
	t.Run("non-leaf path leaves Reply empty", func(t *testing.T) {
		c := mkClient(CLIENT, true)
		c.ciStampHdr = nil
		out := c.stampRequestInfoHeaderIfNeeded(payload)
		var stamped ClientInfo
		if err := json.Unmarshal(getHeader(ClientInfoHdr, out), &stamped); err != nil {
			t.Fatalf("Bad CI JSON: %v", err)
		}
		if stamped.Reply != _EMPTY_ {
			t.Fatalf("Did not expect Reply on CLIENT path, got %q", stamped.Reply)
		}
	})

	// The per-client cached JSON must be picked up on the second stamp
	// (proving the cache is wired) and invalidated when an input field
	// changes (RTT update, account swap).
	t.Run("cache reused and invalidated on input change", func(t *testing.T) {
		c := mkClient(CLIENT, true)
		c.rtt = 7 * time.Millisecond

		extract := func() ClientInfo {
			t.Helper()
			// Simulate the parser resetting per-message state before each
			// inbound message; otherwise setHeader's c.pa.hdr from the prior
			// stamped result would index past the fresh payload.
			c.pa.hdr = 0
			out := c.stampRequestInfoHeaderIfNeeded(payload)
			var ci ClientInfo
			if err := json.Unmarshal(getHeader(ClientInfoHdr, out), &ci); err != nil {
				t.Fatalf("Bad CI JSON: %v", err)
			}
			return ci
		}

		ci1 := extract()
		if ci1.RTT != 7*time.Millisecond || ci1.Account != "A" {
			t.Fatalf("Unexpected first CI: %+v", ci1)
		}

		// Cache populated: changing the underlying field WITHOUT invalidating
		// must NOT affect the stamped value (proves the cache is being used).
		c.rtt = 99 * time.Millisecond
		if ci := extract(); ci.RTT != 7*time.Millisecond {
			t.Fatalf("Cache did not serve stale stamp: RTT=%v", ci.RTT)
		}

		// processPong-style invalidation: next stamp must reflect new RTT.
		c.ciStampHdr = nil
		if ci := extract(); ci.RTT != 99*time.Millisecond {
			t.Fatalf("Cache not invalidated after RTT update: RTT=%v", ci.RTT)
		}

		// swapAccountAfterReload-style invalidation: next stamp must reflect
		// the new account.
		c.acc = &Account{Name: "B"}
		c.ciStampHdr = nil
		if ci := extract(); ci.Account != "B" {
			t.Fatalf("Cache not invalidated after account swap: Account=%q", ci.Account)
		}
	})

	for _, tc := range []struct {
		name  string
		setup func() *client
	}{
		{"nil server", func() *client { c := mkClient(CLIENT, true); c.srv = nil; return c }},
		{"option disabled", func() *client { return mkClient(CLIENT, false) }},
		{"no reply subject", func() *client { c := mkClient(CLIENT, true); c.pa.reply = nil; return c }},
		{"router kind", func() *client { return mkClient(ROUTER, true) }},
		{"gateway kind", func() *client { return mkClient(GATEWAY, true) }},
		{"jetstream kind", func() *client { return mkClient(JETSTREAM, true) }},
		{"skipped subject", func() *client { c := mkClient(CLIENT, true); c.pa.subject = []byte("$JS.API.X"); return c }},
	} {
		t.Run("not stamped: "+tc.name, func(t *testing.T) {
			c := tc.setup()
			out := c.stampRequestInfoHeaderIfNeeded(payload)
			if getHeader(ClientInfoHdr, out) != nil {
				t.Fatalf("Expected no header for %q", tc.name)
			}
			if string(out) != string(payload) {
				t.Fatalf("Expected message unchanged for %q, got %q", tc.name, out)
			}
		})
	}
}

// Benchmarks for the three relevant paths through stampRequestInfoHeaderIfNeeded.
// Run with: go test -run=- -bench=BenchmarkStampRequestInfoHeader ./server/

func benchSetupClient(stamp bool) *client {
	s := &Server{opts: &Options{StampRequestInfo: stamp}}
	s.stampReqInfo.Store(stamp)
	c := &client{kind: CLIENT, srv: s, host: "127.0.0.1"}
	c.acc = &Account{Name: "A"}
	c.opts.Username = "req"
	c.opts.Name = "reqname"
	c.opts.Lang = "go"
	c.pa.subject = []byte("svc.echo")
	c.pa.reply = []byte("_INBOX.1")
	c.rtt = time.Millisecond
	return c
}

// Disabled (default) path: must be a single atomic.Load.
func BenchmarkStampRequestInfoHeader_Disabled(b *testing.B) {
	c := benchSetupClient(false)
	msg := []byte("hello")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.stampRequestInfoHeaderIfNeeded(msg)
	}
}

// Enabled, cache hit: the steady-state case in production. Should avoid the
// per-request json.Marshal + ClientInfo allocation.
func BenchmarkStampRequestInfoHeader_EnabledCacheHit(b *testing.B) {
	c := benchSetupClient(true)
	msg := []byte("hello")
	// Prime the cache.
	_ = c.stampRequestInfoHeaderIfNeeded(msg)
	c.pa.hdr = 0
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.pa.hdr = 0 // simulate per-message parser reset
		_ = c.stampRequestInfoHeaderIfNeeded(msg)
	}
}

// Enabled, cache miss (e.g. immediately after a PONG): worst-case enabled path.
func BenchmarkStampRequestInfoHeader_EnabledCacheMiss(b *testing.B) {
	c := benchSetupClient(true)
	msg := []byte("hello")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.ciStampHdr = nil // force rebuild every iteration
		c.pa.hdr = 0
		_ = c.stampRequestInfoHeaderIfNeeded(msg)
	}
}
