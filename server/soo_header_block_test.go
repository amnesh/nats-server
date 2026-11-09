package server

import (
	"bytes"
	"encoding/json"
	"strings"
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

	// The check also applies on the subjects that the stamp skips, with and
	// without a reply subject, because a stream stores the block (fork review
	// R4). A scope that used skipRequestInfoStamp would fail these rows.
	for _, subject := range []string{"$KV.b.k", "$JS.API.X", "$O.b.C.x", "$MQTT.msgs.x", "$NRG.x"} {
		if !skipRequestInfoStamp([]byte(subject)) {
			t.Fatalf("%s: want a subject that the stamp skips", subject)
		}
		for _, kind := range []int{CLIENT, LEAF} {
			for _, reply := range []string{"", "_INBOX.1"} {
				c := mk(kind, true, badHdr)
				c.pa.subject = []byte(subject)
				c.pa.reply = []byte(reply)
				if !c.malformedRequestInfoHeader(bad) {
					t.Errorf("kind %d, subject %q, reply %q: malformedRequestInfoHeader = false, want true", kind, subject, reply)
				}
				c.pa.hdr = goodHdr
				if c.malformedRequestInfoHeader(good) {
					t.Errorf("kind %d, subject %q, reply %q: well formed block rejected", kind, subject, reply)
				}
			}
		}
	}
}

// A LEAF drop logs one rate-limited warning. It names the subject and the
// reply with %q and contains no header bytes. The format is the rate-limit
// key, so a drop on another subject in the same interval adds no line (fork
// review R2).
func TestStampRequestInfoLeafDropWarningNamesSubject(t *testing.T) {
	hdr := "NATS/1.0\nNats-Request-Info: {\"user\":\"forged\"}\r\n\r\n\r\n"
	msg := []byte(hdr + "hello\r\n")
	s := &Server{opts: &Options{StampRequestInfo: true}}
	s.stampReqInfo.Store(true)
	l := &captureWarnLogger{warn: make(chan string, 4)}
	s.SetLogger(l, false, false)
	c := &client{kind: LEAF, srv: s}
	c.pa.subject = []byte("$JS.M.abc")
	c.pa.reply = []byte("$JS.ACK.ORIGIN.mirror.1.7.7.1700000000000000000.0")
	c.pa.hdr = len(hdr)

	if !c.rejectMalformedRequestInfoHeader(msg) {
		t.Fatal("Want a dropped leaf message")
	}
	select {
	case w := <-l.warn:
		for _, want := range []string{`Subject "$JS.M.abc"`, `Reply "$JS.ACK.ORIGIN.mirror.1.7.7.1700000000000000000.0"`} {
			if !strings.Contains(w, want) {
				t.Errorf("Warning %q does not contain %s", w, want)
			}
		}
		for _, banned := range []string{"NATS/1.0", "Nats-Request-Info", "forged"} {
			if strings.Contains(w, banned) {
				t.Errorf("Warning %q contains header bytes %q", w, banned)
			}
		}
	default:
		t.Fatal("Want a warning for the dropped leaf message")
	}

	c.pa.subject = []byte("svc.other")
	if !c.rejectMalformedRequestInfoHeader(msg) {
		t.Fatal("Want a dropped leaf message")
	}
	select {
	case w := <-l.warn:
		t.Fatalf("Want no second warning in the interval, got %q", w)
	default:
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

// The store check rejects a header block that is not strict only while
// stamping is on and only for a message that is not sourced. Mirror and
// source ingest (sourced) are not checked, also with a block that the check
// rejects otherwise (option 4 of the leaf stall probe, P6-U32).
func TestRequestInfoStoreHeaderBlockDecision(t *testing.T) {
	mk := func(stamp bool) *Server {
		s := &Server{opts: &Options{StampRequestInfo: stamp}}
		s.stampReqInfo.Store(stamp)
		return s
	}
	strict := []string{
		"NATS/1.0\r\n\r\n",
		"NATS/1.0\r\nNats-Msg-Id: 1\r\n\r\n",
		"NATS/1.0 503\r\nA: b\r\n\r\n",
	}
	loose := []string{
		// The N1 frame after removeHeaderStatusIfPresent in
		// processInboundJetStreamMsg: the stream gets this block.
		"NATS/1.0\r\n\r\n\r\n",
		"NATS/1.0\r\nX-Trace: t\nNats-Request-Info: x\r\n\r\n",
		"NATS/1.0\r\nX-Trace: t\r\n\r\nNats-Request-Info: x\r\n\r\n",
		"NATS/1.0\r\nNats-Request-Info: x\r\n",
		"NATS/1.0 5\r\nA: b\r\n\r\n",
		"A: b\r\n\r\n",
	}
	for _, stamp := range []bool{true, false} {
		for _, sourced := range []bool{true, false} {
			s := mk(stamp)
			for _, hdr := range strict {
				if storeRejectsHeaderBlock(s, []byte(hdr), sourced) {
					t.Errorf("stamp=%v sourced=%v: strict block %q rejected", stamp, sourced, hdr)
				}
			}
			for _, hdr := range loose {
				want := stamp && !sourced
				if got := storeRejectsHeaderBlock(s, []byte(hdr), sourced); got != want {
					t.Errorf("stamp=%v sourced=%v: block %q: reject = %v, want %v", stamp, sourced, hdr, got, want)
				}
			}
			if storeRejectsHeaderBlock(s, nil, sourced) {
				t.Errorf("stamp=%v sourced=%v: no header rejected", stamp, sourced)
			}
		}
	}
	if storeRejectsHeaderBlock(nil, []byte(loose[0]), false) {
		t.Error("no server: want no check")
	}
}

// A store reject returns JSBadRequestErr and logs one rate-limited warning.
// The warning names the account and the stream and contains no subject and no
// header bytes.
func TestRequestInfoStoreHeaderBlockWarning(t *testing.T) {
	s := &Server{opts: &Options{StampRequestInfo: true}}
	s.stampReqInfo.Store(true)
	l := &captureWarnLogger{warn: make(chan string, 4)}
	s.SetLogger(l, false, false)
	mset := &stream{srv: s, acc: &Account{Name: "ACC"}}
	hdr := []byte("NATS/1.0\r\nX-Trace: t\r\n\r\nNats-Request-Info: {\"user\":\"forged\"}\r\n\r\n")

	if apiErr := mset.rejectStoreHeaderBlock("ORDERS", []byte("NATS/1.0\r\nA: b\r\n\r\n"), false); apiErr != nil {
		t.Fatalf("Strict block rejected: %v", apiErr)
	}
	if apiErr := mset.rejectStoreHeaderBlock("ORDERS", hdr, true); apiErr != nil {
		t.Fatalf("Sourced block rejected: %v", apiErr)
	}
	apiErr := mset.rejectStoreHeaderBlock("ORDERS", hdr, false)
	if apiErr == nil {
		t.Fatal("Want a reject")
	}
	if !IsNatsErr(apiErr, JSBadRequestErr) || apiErr.Code != 400 || apiErr.ErrCode != 10003 {
		t.Fatalf("Want JSBadRequestErr (400, 10003), got %+v", apiErr)
	}
	select {
	case w := <-l.warn:
		if !strings.Contains(w, "'ACC > ORDERS'") {
			t.Errorf("Warning %q does not name the account and the stream", w)
		}
		for _, banned := range []string{"NATS/1.0", "Nats-Request-Info", "forged", "X-Trace"} {
			if strings.Contains(w, banned) {
				t.Errorf("Warning %q contains header bytes %q", w, banned)
			}
		}
	default:
		t.Fatal("Want a warning for the reject")
	}
	if mset.rejectStoreHeaderBlock("ORDERS", hdr, false) == nil {
		t.Fatal("Want a second reject")
	}
	select {
	case w := <-l.warn:
		t.Fatalf("Want no second warning for the stream in the interval, got %q", w)
	default:
	}
}
