package server

import (
	"bytes"
	"encoding/json"
	"testing"
)

// requestInfoHeaderBlockValid accepts only the strict wire form that nats.go
// writes: "NATS/1.0" first, CRLF line ends, and one empty line at the end.
func TestRequestInfoHeaderBlockValid(t *testing.T) {
	for _, tc := range []struct {
		name  string
		hdr   string
		valid bool
	}{
		{"empty block", "NATS/1.0\r\n\r\n", true},
		{"one header", "NATS/1.0\r\nA: b\r\n\r\n", true},
		{"two headers", "NATS/1.0\r\nA: b\r\nNats-Request-Info: x\r\n\r\n", true},
		{"inline status", "NATS/1.0 503\r\n\r\n", true},
		{"status and description", "NATS/1.0 408 Request Timeout\r\nA: b\r\n\r\n", true},
		{"no status line", "A: b\r\n\r\n", false},
		{"short", "NATS/1.0\r\n", false},
		{"no final empty line", "NATS/1.0\r\nA: b\r\n", false},
		{"no final CRLF", "NATS/1.0\r\nA: b\r\n\r", false},
		{"N1 frame", "NATS/1.0\nNats-Request-Info: x\r\n\r\n\r\n", false},
		{"status line LF", "NATS/1.0\nNats-Request-Info: x\r\n\r\n", false},
		{"LF before key", "NATS/1.0\r\nA: b\nNats-Request-Info: x\r\n\r\n", false},
		{"LF line end", "NATS/1.0\r\nA: b\n\r\n", false},
		{"inner empty line", "NATS/1.0\r\nA: b\r\n\r\nNats-Request-Info: x\r\n\r\n", false},
		{"empty line after status", "NATS/1.0\r\n\r\nNats-Request-Info: x\r\n\r\n", false},
		{"two final empty lines", "NATS/1.0\r\nA: b\r\n\r\n\r\n", false},
		{"bare CR", "NATS/1.0\r\nA: b\rNats-Request-Info: x\r\n\r\n", false},
		{"CR before CRLF", "NATS/1.0\r\nA: b\r\r\n\r\n", false},
		// The inline status rule of nats.go v1.54.0: after "NATS/1.0" and the
		// trim of white space (strings.TrimSpace), a status has at least three
		// bytes. nats.go v1.53.1 panics on a shorter status.
		{"short status", "NATS/1.0 5\r\n\r\n", false},
		{"status space only", "NATS/1.0 \r\n\r\n", false},
		{"two-digit status", "NATS/1.0 50\r\n\r\n", false},
		{"short status with spaces", "NATS/1.0  50  \r\n\r\n", false},
		{"short status after tab", "NATS/1.0\t5\r\n\r\n", false},
		{"short status before NBSP", "NATS/1.0 5 \r\n\r\n", false},
		{"short status before a header", "NATS/1.0 5\r\nA: b\r\n\r\n", false},
		{"short status without space", "NATS/1.05\r\n\r\n", false},
		{"two-byte rune status", "NATS/1.0 é\r\n\r\n", false},
		{"status without space", "NATS/1.0503\r\n\r\n", true},
		{"status after tab", "NATS/1.0\t503\r\n\r\n", true},
		{"status before NBSP", "NATS/1.0 503 \r\n\r\n", true},
		{"three-byte rune status", "NATS/1.0 €\r\n\r\n", true},
		{"no responders status", "NATS/1.0 503 No Responders\r\n\r\n", true},
	} {
		if got := requestInfoHeaderBlockValid([]byte(tc.hdr)); got != tc.valid {
			t.Errorf("%s: requestInfoHeaderBlockValid(%q) = %v, want %v", tc.name, tc.hdr, got, tc.valid)
		}
	}
}

// The header block check applies only to CLIENT (not MQTT) and LEAF messages
// with a header, and only while stamp_request_info is on.
func TestRequestInfoHeaderBlockCheckScope(t *testing.T) {
	bad := []byte("NATS/1.0\nNats-Request-Info: x\r\n\r\n\r\nhello\r\n")
	badHdr := len("NATS/1.0\nNats-Request-Info: x\r\n\r\n\r\n")
	good := []byte("NATS/1.0\r\nNats-Request-Info: x\r\n\r\nhello\r\n")
	goodHdr := len("NATS/1.0\r\nNats-Request-Info: x\r\n\r\n")
	mk := func(kind int, stamp bool, hdr int) *client {
		s := &Server{opts: &Options{StampRequestInfo: stamp}}
		s.stampReqInfo.Store(stamp)
		c := &client{kind: kind, srv: s}
		c.pa.hdr = hdr
		return c
	}
	for _, tc := range []struct {
		name string
		c    *client
		msg  []byte
		want bool
	}{
		{"client malformed", mk(CLIENT, true, badHdr), bad, true},
		{"leaf malformed", mk(LEAF, true, badHdr), bad, true},
		{"client well formed", mk(CLIENT, true, goodHdr), good, false},
		{"leaf well formed", mk(LEAF, true, goodHdr), good, false},
		{"header size past the message", mk(CLIENT, true, len(good)+1), good, true},
		{"stamping off", mk(CLIENT, false, badHdr), bad, false},
		{"no header", mk(CLIENT, true, -1), bad, false},
		{"zero header", mk(CLIENT, true, 0), bad, false},
		{"route", mk(ROUTER, true, badHdr), bad, false},
		{"gateway", mk(GATEWAY, true, badHdr), bad, false},
		{"system", mk(SYSTEM, true, badHdr), bad, false},
		{"jetstream", mk(JETSTREAM, true, badHdr), bad, false},
		{"account", mk(ACCOUNT, true, badHdr), bad, false},
	} {
		if got := tc.c.malformedRequestInfoHeader(tc.msg); got != tc.want {
			t.Errorf("%s: malformedRequestInfoHeader = %v, want %v", tc.name, got, tc.want)
		}
	}
	mqttClient := mk(CLIENT, true, badHdr)
	mqttClient.mqtt = &mqtt{}
	if mqttClient.malformedRequestInfoHeader(bad) {
		t.Error("mqtt: the server writes MQTT header blocks, want no check")
	}
	noServer := mk(CLIENT, true, badHdr)
	noServer.srv = nil
	if noServer.malformedRequestInfoHeader(bad) {
		t.Error("no server: want no check")
	}
}

// In a block that passes the check, the stamp removes every client copy of
// Nats-Request-Info and keeps the other headers.
func TestStampRequestInfoRemovesEveryClientCopy(t *testing.T) {
	s := &Server{opts: &Options{StampRequestInfo: true}}
	s.stampReqInfo.Store(true)
	c := &client{kind: CLIENT, srv: s, host: "127.0.0.1"}
	c.acc = &Account{Name: "A"}
	c.opts.Username = "req"
	c.pa.subject = []byte("svc.echo")
	c.pa.reply = []byte("_INBOX.1")

	forged := `{"acc":"A","user":"forged"}`
	hdr := "NATS/1.0\r\nNats-Request-Info: " + forged + "\r\nX-Trace: t\r\nNats-Request-Info: " + forged +
		"\r\nNats-Request-Info:" + forged + "\r\n\r\n"
	msg := []byte(hdr + "hello\r\n")
	c.pa.hdr = len(hdr)
	c.pa.size = len(msg) - LEN_CR_LF
	if !requestInfoHeaderBlockValid(msg[:c.pa.hdr]) {
		t.Fatalf("Test block must pass the check: %q", hdr)
	}

	out := c.stampRequestInfoHeaderIfNeeded(msg)
	block := out[:c.pa.hdr]
	if n := bytes.Count(block, []byte(ClientInfoHdr+":")); n != 1 {
		t.Fatalf("Want one %s line, got %d in %q", ClientInfoHdr, n, block)
	}
	if !requestInfoHeaderBlockValid(block) {
		t.Fatalf("Stamped block is not in the strict form: %q", block)
	}
	var ci ClientInfo
	if err := json.Unmarshal(getHeader(ClientInfoHdr, block), &ci); err != nil {
		t.Fatalf("Bad stamp: %v", err)
	}
	if ci.Account != "A" || ci.User != "req" {
		t.Fatalf("Want the server stamp for A/req, got %+v", ci)
	}
	if v := getHeader("X-Trace", block); string(v) != "t" {
		t.Fatalf("Other header lost: X-Trace=%q", v)
	}
	if string(out[c.pa.hdr:]) != "hello\r\n" {
		t.Fatalf("Payload changed: %q", out[c.pa.hdr:])
	}
}
