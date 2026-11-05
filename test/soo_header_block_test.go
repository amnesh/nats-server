package test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// These tests send raw header blocks that a nats.go client cannot write. With
// stamp_request_info on, a CLIENT or LEAF header block must have the strict
// wire form. Otherwise the server strip and the nats.go header parser can
// disagree: nats.go ends a line at a bare LF and stops at the first empty
// line, while the strip finds a key only after CRLF. The server must then
// not deliver the message. The service subscriber is a nats.go client, the
// same parser that the NCDL and AMNET consumers use.

const forgedRequestInfo = `{"acc":"A","user":"forged","kind":"Client"}`

type malformedHeaderFrame struct {
	name string
	hdr  string
}

// malformedHeaderFrames are the frames of the P6 review findings N1 and F2.
// On fork v2.15.3-amnesh.4 the first three give the nats.go subscriber the
// forged value (N1 as the only value), the fourth hides the server stamp, and
// the fifth makes the server stamp part of the forged value.
var malformedHeaderFrames = []malformedHeaderFrame{
	{"n1-lf-then-inner-empty-line", "NATS/1.0\nNats-Request-Info: " + forgedRequestInfo + "\r\n\r\n\r\n"},
	{"status-line-lf", "NATS/1.0\nNats-Request-Info: " + forgedRequestInfo + "\r\n\r\n"},
	{"lf-before-key", "NATS/1.0\r\nX-Trace: t\nNats-Request-Info: " + forgedRequestInfo + "\r\n\r\n"},
	{"inner-empty-line", "NATS/1.0\r\nX-Trace: t\r\n\r\nNats-Request-Info: " + forgedRequestInfo + "\r\n\r\n"},
	{"missing-final-empty-line", "NATS/1.0\r\nNats-Request-Info: " + forgedRequestInfo + "\r\n"},
}

// stampObservation is one message that the nats.go service received.
type stampObservation struct {
	payload string
	values  []string
	trace   string
}

type stampService struct {
	ch chan stampObservation
}

// runStampService subscribes a nats.go service on svc.echo as user svc.
func runStampService(t *testing.T, url string) *stampService {
	t.Helper()
	nc, err := nats.Connect(url, nats.UserInfo("svc", "pwd"), nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) {}))
	if err != nil {
		t.Fatalf("Error connecting service: %v", err)
	}
	t.Cleanup(nc.Close)
	svc := &stampService{ch: make(chan stampObservation, 64)}
	if _, err := nc.Subscribe("svc.echo", func(m *nats.Msg) {
		values := append([]string(nil), m.Header.Values(server.ClientInfoHdr)...)
		svc.ch <- stampObservation{payload: string(m.Data), values: values, trace: m.Header.Get("X-Trace")}
	}); err != nil {
		t.Fatalf("Error subscribing service: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("Error flushing service: %v", err)
	}
	return svc
}

// until returns the messages before the message with the given payload, and
// that message. The subscription delivers in order, so a message that the
// server queued before the marker arrives before it.
func (s *stampService) until(t *testing.T, payload string) ([]stampObservation, stampObservation) {
	t.Helper()
	var before []stampObservation
	timeout := time.After(5 * time.Second)
	for {
		select {
		case o := <-s.ch:
			if o.payload == payload {
				return before, o
			}
			before = append(before, o)
		case <-timeout:
			t.Fatalf("Service did not receive %q; received before: %+v", payload, before)
		}
	}
}

// requireServerStamp checks that the message has exactly one
// Nats-Request-Info value and that it names the authenticated connection.
func requireServerStamp(t *testing.T, o stampObservation, user string) {
	t.Helper()
	if len(o.values) != 1 {
		t.Fatalf("Message %q: want one Nats-Request-Info value, got %q", o.payload, o.values)
	}
	var ci server.ClientInfo
	if err := json.Unmarshal([]byte(o.values[0]), &ci); err != nil {
		t.Fatalf("Message %q: bad Nats-Request-Info value %q: %v", o.payload, o.values[0], err)
	}
	if ci.Account != "A" || ci.User != user {
		t.Fatalf("Message %q: want the server stamp for A/%s, got %q", o.payload, user, o.values[0])
	}
}

// rawProtoConn reads the protocol lines of a raw connection.
type rawProtoConn struct {
	t    *testing.T
	conn net.Conn
	seen []byte
	mark int
}

func (r *rawProtoConn) send(proto string) {
	r.t.Helper()
	sendProto(r.t, r.conn, proto)
}

// until reads until the text after the last match contains want. It returns
// the text up to and including want, and true. When the connection ends
// first, it returns the text and false. A timeout fails the test.
func (r *rawProtoConn) until(want string) (string, bool) {
	r.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, 4096)
	for {
		if i := bytes.Index(r.seen[r.mark:], []byte(want)); i >= 0 {
			text := string(r.seen[r.mark : r.mark+i+len(want)])
			r.mark += i + len(want)
			return text, true
		}
		r.conn.SetReadDeadline(deadline)
		n, err := r.conn.Read(buf)
		r.seen = append(r.seen, buf[:n]...)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				r.t.Fatalf("No %q within 5s; received %q", want, r.seen[r.mark:])
			}
			text := string(r.seen[r.mark:])
			r.mark = len(r.seen)
			return text, false
		}
	}
}

// closed reports whether the server closes the connection within wait.
func (r *rawProtoConn) closed(wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	buf := make([]byte, 4096)
	for {
		r.conn.SetReadDeadline(deadline)
		n, err := r.conn.Read(buf)
		r.seen = append(r.seen, buf[:n]...)
		if err != nil {
			var ne net.Error
			return !errors.As(err, &ne) || !ne.Timeout()
		}
	}
}

// dialRawStampClient connects a raw CLIENT as user req with headers on.
func dialRawStampClient(t *testing.T, opts *server.Options) *rawProtoConn {
	t.Helper()
	conn := createClientConn(t, opts.Host, opts.Port)
	t.Cleanup(func() { conn.Close() })
	checkInfoMsg(t, conn)
	raw := &rawProtoConn{t: t, conn: conn}
	raw.send("CONNECT {\"verbose\":false,\"pedantic\":false,\"user\":\"req\",\"pass\":\"pwd\",\"name\":\"raw\",\"headers\":true,\"protocol\":1}\r\nPING\r\n")
	if _, ok := raw.until("PONG\r\n"); !ok {
		t.Fatalf("Raw client closed at connect: %q", raw.seen)
	}
	return raw
}

func headerPub(op, subject, reply, hdr, payload string) string {
	return fmt.Sprintf("%s %s %s %d %d\r\n%s%s\r\n", op, subject, reply, len(hdr), len(hdr)+len(payload), hdr, payload)
}

func runStampHeaderServer(t *testing.T, stamp bool, leaf bool) (*server.Server, *server.Options) {
	t.Helper()
	conf := fmt.Sprintf(`
		listen: 127.0.0.1:-1
		stamp_request_info: %v
		accounts: {
			A: {
				users: [
					{user: req, password: pwd}
					{user: svc, password: pwd}
					{user: leaf, password: pwd}
				]
			}
		}
	`, stamp)
	if leaf {
		conf += "leafnodes { listen: 127.0.0.1:-1 }\n"
	}
	file := createConfFile(t, []byte(conf))
	t.Cleanup(func() { os.Remove(file) })
	srv, opts := RunServerWithConfig(file)
	t.Cleanup(srv.Shutdown)
	return srv, opts
}

// A raw CLIENT publish with a malformed header block is not delivered. The
// client gets -ERR 'Message Header Violation' and the server closes it. A
// later request from another connection is the barrier: the service gets
// it, and no message before it.
func TestStampRequestInfoRejectsMalformedClientHeader(t *testing.T) {
	_, opts := runStampHeaderServer(t, true, false)
	svc := runStampService(t, fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port))

	ctl, err := nats.Connect(fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port), nats.UserInfo("req", "pwd"))
	if err != nil {
		t.Fatalf("Error connecting control client: %v", err)
	}
	defer ctl.Close()

	for _, frame := range malformedHeaderFrames {
		t.Run(frame.name, func(t *testing.T) {
			raw := dialRawStampClient(t, opts)
			raw.send(headerPub("HPUB", "svc.echo", "_INBOX.raw.reply", frame.hdr, "bad-"+frame.name) + "PING\r\n")
			text, open := raw.until("PONG\r\n")
			closed := !open || raw.closed(time.Second)
			errSeen := strings.Contains(text, "-ERR 'Message Header Violation'")

			// The barrier request comes after the server handled the frame:
			// the raw client saw its -ERR, its close, or its PONG.
			marker := "control-" + frame.name
			if err := ctl.PublishRequest("svc.echo", "_INBOX.ctl.reply", []byte(marker)); err != nil {
				t.Fatalf("Error publishing control request: %v", err)
			}
			before, control := svc.until(t, marker)
			for _, o := range before {
				t.Errorf("Server delivered %q; nats.go read Nats-Request-Info values %q", o.payload, o.values)
			}
			if !errSeen {
				t.Errorf("Raw client got no -ERR 'Message Header Violation'; received %q", text)
			}
			if !closed {
				t.Errorf("Server did not close the raw client")
			}
			requireServerStamp(t, control, "req")
		})
	}
}

// Positive control: a well-formed header block with client copies of the key
// is delivered, with every client copy removed and one server stamp.
func TestStampRequestInfoStripsEveryClientCopy(t *testing.T) {
	_, opts := runStampHeaderServer(t, true, false)
	svc := runStampService(t, fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port))
	raw := dialRawStampClient(t, opts)

	one := "NATS/1.0\r\nNats-Request-Info: " + forgedRequestInfo + "\r\n\r\n"
	three := "NATS/1.0\r\nNats-Request-Info: " + forgedRequestInfo + "\r\nX-Trace: t\r\nNats-Request-Info: " +
		forgedRequestInfo + "\r\nNats-Request-Info:" + forgedRequestInfo + "\r\n\r\n"
	raw.send(headerPub("HPUB", "svc.echo", "_INBOX.raw.reply", one, "good-one") +
		headerPub("HPUB", "svc.echo", "_INBOX.raw.reply", three, "good-three") + "PING\r\n")
	if text, ok := raw.until("PONG\r\n"); !ok || strings.Contains(text, "-ERR") {
		t.Fatalf("Raw client rejected or closed: %q", text)
	}

	before, o := svc.until(t, "good-one")
	if len(before) != 0 {
		t.Fatalf("Unexpected messages: %+v", before)
	}
	requireServerStamp(t, o, "req")
	before, o = svc.until(t, "good-three")
	if len(before) != 0 {
		t.Fatalf("Unexpected messages: %+v", before)
	}
	requireServerStamp(t, o, "req")
	if o.trace != "t" {
		t.Fatalf("Other header lost: X-Trace=%q", o.trace)
	}
}

// A raw LEAF connection sends each malformed frame, then a well-formed frame
// with a client copy of the key. The hub drops the first message and keeps
// the leaf connection: one bad client behind a leaf must not close the link
// of all its clients. The second message is the barrier and the positive
// control: it arrives with one server stamp for the leaf user.
func TestStampRequestInfoDropsMalformedLeafHeader(t *testing.T) {
	hub, opts := runStampHeaderServer(t, true, true)
	svc := runStampService(t, fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port))

	conn := createLeafConn(t, opts.LeafNode.Host, opts.LeafNode.Port)
	defer conn.Close()
	checkInfoMsg(t, conn)
	leaf := &rawProtoConn{t: t, conn: conn}
	leaf.send("CONNECT {\"user\":\"leaf\",\"pass\":\"pwd\",\"headers\":true}\r\nPING\r\n")
	if _, ok := leaf.until("PONG\r\n"); !ok {
		t.Fatalf("Leaf connection closed at connect: %q", leaf.seen)
	}
	checkLeafNodeConnected(t, hub)

	good := "NATS/1.0\r\nNats-Request-Info: " + forgedRequestInfo + "\r\n\r\n"
	for _, frame := range malformedHeaderFrames {
		t.Run(frame.name, func(t *testing.T) {
			marker := "control-" + frame.name
			leaf.send(headerPub("HMSG", "svc.echo", "_INBOX.leaf.reply", frame.hdr, "bad-"+frame.name) +
				headerPub("HMSG", "svc.echo", "_INBOX.leaf.reply", good, marker) + "PING\r\n")
			text, open := leaf.until("PONG\r\n")
			before, control := svc.until(t, marker)
			for _, o := range before {
				t.Errorf("Hub delivered %q; nats.go read Nats-Request-Info values %q", o.payload, o.values)
			}
			if !open {
				t.Fatalf("Hub closed the leaf connection; received %q", text)
			}
			if strings.Contains(text, "-ERR") {
				t.Errorf("Hub sent an error to the leaf: %q", text)
			}
			requireServerStamp(t, control, "leaf")
		})
	}
	checkLeafNodeConnected(t, hub)
}

// With stamp_request_info off (the default) the server keeps the upstream
// behavior: it does not check the header block and delivers the message.
func TestStampRequestInfoDisabledKeepsHeaderBlock(t *testing.T) {
	_, opts := runStampHeaderServer(t, false, false)
	svc := runStampService(t, fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port))
	raw := dialRawStampClient(t, opts)

	frame := malformedHeaderFrames[0]
	raw.send(headerPub("HPUB", "svc.echo", "_INBOX.raw.reply", frame.hdr, "off-"+frame.name) + "PING\r\n")
	if text, ok := raw.until("PONG\r\n"); !ok || strings.Contains(text, "-ERR") {
		t.Fatalf("Raw client rejected or closed with stamping off: %q", text)
	}
	before, o := svc.until(t, "off-"+frame.name)
	if len(before) != 0 {
		t.Fatalf("Unexpected messages: %+v", before)
	}
	if len(o.values) != 1 || o.values[0] != forgedRequestInfo {
		t.Fatalf("With stamping off, want the client header unchanged, got %q", o.values)
	}
}
