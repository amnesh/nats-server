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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// These tests cover the store check (soo-changes.go, P6-U32). While
// stamp_request_info is on, the server that stores a message for a stream
// rejects a header block that is not strict, for each input path and client
// kind. Mirror and source ingest are not checked.

// looseStoreHeaderBlocks are header blocks that the check rejects and that a
// stream gets without a change: removeHeaderStatusIfPresent changes only the
// first line, and these blocks have no inline status. They are the stall
// probe blocks of 2026-11-08 (a bare LF before a key, an inner empty line).
var looseStoreHeaderBlocks = []string{
	"NATS/1.0\r\nX-A: 1\nX-B: 2\r\n\r\n",
	"NATS/1.0\r\nX-A: 1\r\n\r\nX-B: 2\r\n\r\n",
}

const strictStoreHeaderBlock = "NATS/1.0\r\nX-Control: 1\r\n\r\n"

// storeHeaderLogger keeps the warnings of the store check.
type storeHeaderLogger struct {
	DummyLogger
	mu    sync.Mutex
	warns []string
}

func (l *storeHeaderLogger) Warnf(format string, v ...any) {
	w := fmt.Sprintf(format, v...)
	if !strings.Contains(w, "malformed header block") {
		return
	}
	l.mu.Lock()
	l.warns = append(l.warns, w)
	l.mu.Unlock()
}

// rejects returns the number of store check warnings for stream.
func (l *storeHeaderLogger) rejects(stream string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	var n int
	for _, w := range l.warns {
		if strings.HasPrefix(w, "Rejected a message with a malformed header block") &&
			strings.HasSuffix(w, " > "+stream+"'") {
			n++
		}
	}
	return n
}

func (l *storeHeaderLogger) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.warns...)
}

func runStoreHeaderServer(t *testing.T, stamp bool) *Server {
	t.Helper()
	opts := DefaultTestOptions
	opts.Port = -1
	opts.JetStream = true
	opts.StoreDir = t.TempDir()
	opts.StampRequestInfo = stamp
	s := RunServer(&opts)
	t.Cleanup(s.Shutdown)
	return s
}

func storeHeaderStream(t *testing.T, s *Server, name string) *stream {
	t.Helper()
	mset, err := s.GlobalAccount().lookupStream(name)
	require_NoError(t, err)
	return mset
}

func storeHeaderMsgs(t *testing.T, s *Server, name string) uint64 {
	t.Helper()
	return storeHeaderStream(t, s, name).state().Msgs
}

// storedHeaderBlocks returns the stored header block of each message of a
// stream in sequence order.
func storedHeaderBlocks(t *testing.T, s *Server, acc *Account, name string) [][]byte {
	t.Helper()
	mset, err := acc.lookupStream(name)
	require_NoError(t, err)
	var state StreamState
	mset.store.FastState(&state)
	var blocks [][]byte
	var smv StoreMsg
	for seq := state.FirstSeq; state.Msgs > 0 && seq <= state.LastSeq; seq++ {
		sm, err := mset.store.LoadMsg(seq, &smv)
		if err != nil {
			continue
		}
		blocks = append(blocks, copyBytes(sm.hdr))
	}
	return blocks
}

// requireStoredHeaderBlocksStrict fails when a stored header block of the
// stream is not strict. It returns the number of stored blocks.
func requireStoredHeaderBlocksStrict(t *testing.T, s *Server, acc *Account, name string) int {
	t.Helper()
	var n int
	for _, hdr := range storedHeaderBlocks(t, s, acc, name) {
		if len(hdr) == 0 {
			continue
		}
		if !requestInfoHeaderBlockValid(hdr) {
			t.Fatalf("Stream %q stores a header block that is not strict: %q", name, hdr)
		}
		n++
	}
	return n
}

func storeHeaderPubAck(t *testing.T, m *nats.Msg) *JSPubAckResponse {
	t.Helper()
	var resp JSPubAckResponse
	if err := json.Unmarshal(m.Data, &resp); err != nil {
		t.Fatalf("Bad PubAck %q: %v", m.Data, err)
	}
	return &resp
}

func requireStoreHeaderReject(t *testing.T, m *nats.Msg) {
	t.Helper()
	resp := storeHeaderPubAck(t, m)
	if resp.Error == nil || !IsNatsErr(resp.Error, JSBadRequestErr) {
		t.Fatalf("Want a JSBadRequestErr PubAck, got %q", m.Data)
	}
}

func requireStoreHeaderSeq(t *testing.T, m *nats.Msg, seq uint64) {
	t.Helper()
	resp := storeHeaderPubAck(t, m)
	if resp.Error != nil || resp.PubAck == nil || resp.Sequence != seq {
		t.Fatalf("Want a PubAck for sequence %d, got %q", seq, m.Data)
	}
}

// rawStorePub is a raw CLIENT connection. It can send a header block that a
// nats.go client cannot write.
type rawStorePub struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
}

func dialRawStorePub(t *testing.T, s *Server) *rawStorePub {
	t.Helper()
	conn, err := net.Dial("tcp", s.Addr().String())
	require_NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	r := &rawStorePub{t: t, conn: conn, br: bufio.NewReader(conn)}
	r.read("INFO ")
	r.write("CONNECT {\"verbose\":false,\"pedantic\":false,\"headers\":true,\"protocol\":1}\r\n")
	r.ping()
	return r
}

func (r *rawStorePub) write(proto string) {
	r.t.Helper()
	r.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := r.conn.Write([]byte(proto)); err != nil {
		r.t.Fatalf("Raw write: %v", err)
	}
}

// read reads protocol lines until a line starts with prefix. Any -ERR fails
// the test.
func (r *rawStorePub) read(prefix string) {
	r.t.Helper()
	r.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		line, err := r.br.ReadString('\n')
		if err != nil {
			r.t.Fatalf("Raw read: %v", err)
		}
		if strings.HasPrefix(line, "-ERR") {
			r.t.Fatalf("Raw connection got %q", line)
		}
		if strings.HasPrefix(line, prefix) {
			return
		}
	}
}

// ping is a barrier: the server has read every message before the PONG.
func (r *rawStorePub) ping() {
	r.t.Helper()
	r.write("PING\r\n")
	r.read("PONG")
}

func (r *rawStorePub) hpub(subject, reply, hdr, payload string) {
	r.t.Helper()
	if reply != _EMPTY_ {
		subject += " " + reply
	}
	r.write(fmt.Sprintf("HPUB %s %d %d\r\n%s%s\r\n", subject, len(hdr), len(hdr)+len(payload), hdr, payload))
	r.ping()
}

// The store check rejects a loose header block on each path that is not a
// CLIENT or LEAF ingress: a direct store call, an internal client (kind
// ACCOUNT), an atomic batch commit, and a fast batch. A publish with a reply
// gets a JSBadRequestErr PubAck. A publish without a reply is dropped with a
// warning that names the account and the stream. With stamping off, all
// these paths store the block (upstream behavior).
func TestJetStreamStampRequestInfoStoreRejectsLooseHeaderBlock(t *testing.T) {
	for _, stamp := range []bool{true, false} {
		t.Run(fmt.Sprintf("stamp=%v", stamp), func(t *testing.T) {
			s := runStoreHeaderServer(t, stamp)
			l := &storeHeaderLogger{}
			s.SetLogger(l, false, false)
			nc, _ := jsClientConnect(t, s)
			defer nc.Close()
			for _, cfg := range []*StreamConfig{
				{Name: "DIRECT", Subjects: []string{"direct.>"}, Storage: FileStorage},
				{Name: "ACC", Subjects: []string{"acc.>"}, Storage: FileStorage},
				{Name: "ATOM", Subjects: []string{"atom.>"}, Storage: FileStorage, AllowAtomicPublish: true},
				{Name: "FAST", Subjects: []string{"fast.>"}, Storage: FileStorage, AllowBatchPublish: true},
			} {
				addStream(t, nc, cfg)
			}
			sub := natsSubSync(t, nc, "reply.>")
			natsFlush(t, nc)
			acc := s.GlobalAccount()
			loose := []byte(looseStoreHeaderBlocks[0])

			// The store function of a standalone publish. The same block as
			// mirror or source ingest (sourced) is not checked.
			mset := storeHeaderStream(t, s, "DIRECT")
			err := mset.processJetStreamMsg("direct.a", _EMPTY_, copyBytes(loose), []byte("x"), 0, 0, nil, false, true)
			if stamp {
				require_Error(t, err, NewJSBadRequestError())
				require_Equal(t, storeHeaderMsgs(t, s, "DIRECT"), 0)
				require_Equal(t, l.rejects("DIRECT"), 1)
			} else {
				require_NoError(t, err)
				require_Equal(t, storeHeaderMsgs(t, s, "DIRECT"), 1)
			}
			err = mset.processJetStreamMsg("direct.b", _EMPTY_, copyBytes(loose), []byte("x"), 0, 0, nil, true, true)
			require_NoError(t, err)
			if stamp {
				require_Equal(t, storeHeaderMsgs(t, s, "DIRECT"), 1)
			} else {
				require_Equal(t, storeHeaderMsgs(t, s, "DIRECT"), 2)
			}

			// An internal client of the account (kind ACCOUNT). The ingress
			// check does not see it. One internal send queue keeps the order,
			// so the strict publish with a reply is a barrier for the publish
			// without a reply before it.
			require_NoError(t, s.sendInternalAccountMsgWithReply(acc, "acc.a", _EMPTY_, copyBytes(loose), []byte("x"), false))
			require_NoError(t, s.sendInternalAccountMsgWithReply(acc, "acc.b", "reply.acc.1", []byte(strictStoreHeaderBlock), []byte("x"), false))
			m := natsNexMsg(t, sub, 5*time.Second)
			if stamp {
				requireStoreHeaderSeq(t, m, 1)
				require_Equal(t, l.rejects("ACC"), 1)
			} else {
				requireStoreHeaderSeq(t, m, 2)
			}
			require_NoError(t, s.sendInternalAccountMsgWithReply(acc, "acc.c", "reply.acc.2", copyBytes(loose), []byte("x"), false))
			m = natsNexMsg(t, sub, 5*time.Second)
			if stamp {
				requireStoreHeaderReject(t, m)
				require_Equal(t, storeHeaderMsgs(t, s, "ACC"), 1)
			} else {
				requireStoreHeaderSeq(t, m, 3)
			}

			// An atomic batch. The commit checks each staged message before it
			// stores or proposes the batch, so no message of the batch is
			// stored. A loose block in staging gets the empty staging ack.
			looseBatch := "NATS/1.0\r\nNats-Batch-Id: ab1\r\nNats-Batch-Sequence: 1\r\nX-A: 1\nX-B: 2\r\n\r\n"
			commit := "NATS/1.0\r\nNats-Batch-Id: ab1\r\nNats-Batch-Sequence: 2\r\nNats-Batch-Commit: 1\r\n\r\n"
			require_NoError(t, s.sendInternalAccountMsgWithReply(acc, "atom.a", "reply.atom.1", []byte(looseBatch), []byte("x"), false))
			m = natsNexMsg(t, sub, 5*time.Second)
			require_Len(t, len(m.Data), 0)
			require_NoError(t, s.sendInternalAccountMsgWithReply(acc, "atom.b", "reply.atom.2", []byte(commit), []byte("x"), false))
			m = natsNexMsg(t, sub, 5*time.Second)
			if stamp {
				requireStoreHeaderReject(t, m)
				require_Equal(t, storeHeaderMsgs(t, s, "ATOM"), 0)
				require_Equal(t, l.rejects("ATOM"), 1)
			} else {
				requireStoreHeaderSeq(t, m, 2)
				require_Equal(t, storeHeaderMsgs(t, s, "ATOM"), 2)
			}

			// A fast batch. A first message that fails gets the PubAck error of
			// a normal publish.
			reply := generateFastBatchReply("reply.fast", "fb1", 1, 0, FastBatchGapFail, FastBatchOpStart)
			require_NoError(t, s.sendInternalAccountMsgWithReply(acc, "fast.a", reply, copyBytes(loose), []byte("x"), false))
			// The server acks a new fast batch with its flow control before it
			// checks the first message.
			m = natsNexMsg(t, sub, 5*time.Second)
			require_True(t, strings.HasPrefix(string(m.Data), "{\"type\":\"ack\""))
			if stamp {
				m = natsNexMsg(t, sub, 5*time.Second)
				requireStoreHeaderReject(t, m)
				require_Equal(t, storeHeaderMsgs(t, s, "FAST"), 0)
				require_Equal(t, l.rejects("FAST"), 1)
			} else {
				reply = generateFastBatchReply("reply.fast", "fb1", 2, 0, FastBatchGapFail, FastBatchOpCommit)
				require_NoError(t, s.sendInternalAccountMsgWithReply(acc, "fast.b", reply, []byte(strictStoreHeaderBlock), []byte("x"), false))
				m = natsNexMsg(t, sub, 5*time.Second)
				requireStoreHeaderSeq(t, m, 2)
				require_Equal(t, storeHeaderMsgs(t, s, "FAST"), 2)
			}

			if !stamp {
				if w := l.all(); len(w) != 0 {
					t.Fatalf("Want no warning with stamping off, got %q", w)
				}
			}
		})
	}
}

// The store check runs in processJetStreamMsgWithBatch only for the form of a
// new message: lseq and ts are 0. A Raft apply has the entry sequence and
// timestamp. After a scale-down to R1 removes the Raft node, the apply loop
// can still apply an entry that the old leader acknowledged; the stream then
// has no Raft node, like this single-server stream. The check must not reject
// that entry, also when this server has stamping on and the old leader had it
// off. A call with lseq and ts of 0 still gets the check.
func TestJetStreamStampRequestInfoStoreSkipsRaftApplyForm(t *testing.T) {
	s := runStoreHeaderServer(t, true)
	l := &storeHeaderLogger{}
	s.SetLogger(l, false, false)
	nc, _ := jsClientConnect(t, s)
	defer nc.Close()
	addStream(t, nc, &StreamConfig{Name: "APPLY", Subjects: []string{"apply.>"}, Storage: FileStorage})
	mset := storeHeaderStream(t, s, "APPLY")
	require_False(t, mset.IsClustered())

	// The apply form: the first entry has lseq 0 and a timestamp, a later
	// entry has the last sequence.
	ts := time.Now().UnixNano()
	for i, hdr := range looseStoreHeaderBlocks {
		err := mset.processJetStreamMsg("apply.a", _EMPTY_, []byte(hdr), []byte("x"), uint64(i), ts+int64(i), nil, false, true)
		require_NoError(t, err)
	}
	require_Equal(t, storeHeaderMsgs(t, s, "APPLY"), uint64(len(looseStoreHeaderBlocks)))
	for i, hdr := range storedHeaderBlocks(t, s, s.GlobalAccount(), "APPLY") {
		require_Equal(t, string(hdr), looseStoreHeaderBlocks[i])
	}
	require_Equal(t, l.rejects("APPLY"), 0)

	// The form of a new message gets the check.
	err := mset.processJetStreamMsg("apply.b", _EMPTY_, []byte(looseStoreHeaderBlocks[0]), []byte("x"), 0, 0, nil, false, true)
	require_Error(t, err, NewJSBadRequestError())
	require_Equal(t, storeHeaderMsgs(t, s, "APPLY"), uint64(len(looseStoreHeaderBlocks)))
	require_Equal(t, l.rejects("APPLY"), 1)
}

// Header blocks that the server and nats.go write pass the store check.
// With stamping on, each internal writer stores its messages, and each stored
// header block is strict: KV and object store operations, message counters,
// per-message TTL and subject delete markers, message schedules, atomic
// batches with a commit and with an EOB commit, a fast batch, a republish,
// and the mirror and source of a stream.
func TestJetStreamStampRequestInfoStoreKeepsServerHeaderBlocks(t *testing.T) {
	s := runStoreHeaderServer(t, true)
	l := &storeHeaderLogger{}
	s.SetLogger(l, false, false)
	nc, js := jsClientConnect(t, s)
	defer nc.Close()
	acc := s.GlobalAccount()

	// KV operations.
	kv, err := js.CreateKeyValue(&nats.KeyValueConfig{Bucket: "CFG", History: 5})
	require_NoError(t, err)
	rev, err := kv.Put("a", []byte("1"))
	require_NoError(t, err)
	_, err = kv.Update("a", []byte("2"), rev)
	require_NoError(t, err)
	_, err = kv.Create("b", []byte("1"))
	require_NoError(t, err)
	require_NoError(t, kv.Delete("b"))
	require_NoError(t, kv.Purge("a"))
	_, err = kv.Put("c", []byte("1"))
	require_NoError(t, err)

	// Object store operations.
	obs, err := js.CreateObjectStore(&nats.ObjectStoreConfig{Bucket: "OBJ"})
	require_NoError(t, err)
	_, err = obs.PutBytes("blob", bytes.Repeat([]byte("z"), 300*1024))
	require_NoError(t, err)
	_, err = obs.PutBytes("small", []byte("z"))
	require_NoError(t, err)
	require_NoError(t, obs.Delete("small"))

	for _, cfg := range []*StreamConfig{
		{Name: "PLAIN", Subjects: []string{"plain.>"}, Storage: FileStorage},
		{Name: "CNT", Subjects: []string{"cnt.>"}, Storage: FileStorage, AllowMsgCounter: true},
		{Name: "TTL", Subjects: []string{"ttl.>"}, Storage: FileStorage, MaxAge: 2 * time.Second, AllowMsgTTL: true, SubjectDeleteMarkerTTL: 2 * time.Second},
		{Name: "SCHED", Subjects: []string{"sched.>"}, Storage: FileStorage, AllowMsgSchedules: true},
		{Name: "ATOM", Subjects: []string{"atom.>"}, Storage: FileStorage, AllowAtomicPublish: true},
		{Name: "FAST", Subjects: []string{"fast.>"}, Storage: FileStorage, AllowBatchPublish: true},
		{Name: "RPT", Subjects: []string{"rp.out.>"}, Storage: FileStorage},
		{Name: "RP", Subjects: []string{"rp.in.>"}, Storage: FileStorage, RePublish: &RePublish{Source: "rp.in.>", Destination: "rp.out.>"}},
		{Name: "MIR", Storage: FileStorage, Mirror: &StreamSource{Name: "PLAIN"}},
		{Name: "SRC", Storage: FileStorage, Sources: []*StreamSource{{Name: "PLAIN"}}},
	} {
		addStream(t, nc, cfg)
	}

	// Stream headers of a nats.go publish.
	m := nats.NewMsg("plain.a")
	m.Header.Set(JSMsgId, "id-1")
	m.Header.Set(JSExpectedStream, "PLAIN")
	m.Header.Set("X-A", "1")
	_, err = js.PublishMsg(m)
	require_NoError(t, err)
	m = nats.NewMsg("plain.b")
	m.Header.Set(JSExpectedLastSeq, "1")
	_, err = js.PublishMsg(m)
	require_NoError(t, err)
	_, err = js.Publish("plain.c", []byte("no header"))
	require_NoError(t, err)

	// Message counters.
	for i := 0; i < 2; i++ {
		m = nats.NewMsg("cnt.a")
		m.Header.Set(JSMessageIncr, "1")
		_, err = js.PublishMsg(m)
		require_NoError(t, err)
	}

	// A per-message TTL, and a message that MaxAge removes with a subject
	// delete marker. The store makes the marker.
	m = nats.NewMsg("ttl.a")
	m.Header.Set(JSMessageTTL, "2s")
	_, err = js.PublishMsg(m)
	require_NoError(t, err)
	_, err = js.Publish("ttl.b", nil)
	require_NoError(t, err)

	// A message schedule. The store makes the scheduled message.
	m = nats.NewMsg("sched.s1")
	m.Header.Set(JSSchedulePattern, fmt.Sprintf("@at %s", time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)))
	m.Header.Set(JSScheduleTarget, "sched.t1")
	m.Header.Set("X-A", "1")
	_, err = js.PublishMsg(m)
	require_NoError(t, err)

	// Atomic batches with a commit and with an EOB commit. For EOB the
	// server adds the commit header to the last stored message.
	for _, tc := range []struct {
		id     string
		commit string
		size   uint64
	}{{"ab1", "1", 3}, {"ab2", "eob", 2}} {
		var resp *nats.Msg
		for seq := 1; seq <= 3; seq++ {
			m = nats.NewMsg("atom.a")
			m.Header.Set(JSBatchId, tc.id)
			m.Header.Set(JSBatchSeq, fmt.Sprintf("%d", seq))
			if seq == 3 {
				m.Header.Set(JSBatchCommit, tc.commit)
			}
			resp, err = nc.RequestMsg(m, 5*time.Second)
			require_NoError(t, err)
		}
		pa := storeHeaderPubAck(t, resp)
		if pa.Error != nil || pa.BatchId != tc.id || pa.BatchSize != tc.size {
			t.Fatalf("Batch %s: want a PubAck for %d messages, got %q", tc.id, tc.size, resp.Data)
		}
	}

	// A fast batch.
	inbox := nats.NewInbox()
	fsub := natsSubSync(t, nc, inbox+".>")
	natsFlush(t, nc)
	for seq, op := range []int{FastBatchOpStart, FastBatchOpAppend, FastBatchOpCommit} {
		m = nats.NewMsg("fast.a")
		m.Header.Set("X-A", "1")
		m.Reply = generateFastBatchReply(inbox, "fb1", uint64(seq+1), 0, FastBatchGapFail, op)
		require_NoError(t, nc.PublishMsg(m))
	}
	checkFor(t, 5*time.Second, 10*time.Millisecond, func() error {
		rm := natsNexMsg(t, fsub, 5*time.Second)
		if pa := storeHeaderPubAck(t, rm); pa.PubAck == nil || pa.Stream != "FAST" {
			return fmt.Errorf("not a PubAck: %q", rm.Data)
		} else if pa.Error != nil || pa.BatchSize != 3 {
			t.Fatalf("Want a fast batch PubAck for 3 messages, got %q", rm.Data)
		}
		return nil
	})

	// A republish, with and without a header block.
	m = nats.NewMsg("rp.in.a")
	m.Header.Set("X-A", "1")
	_, err = js.PublishMsg(m)
	require_NoError(t, err)
	_, err = js.Publish("rp.in.b", []byte("no header"))
	require_NoError(t, err)

	// The store makes the subject delete marker when MaxAge removes ttl.b.
	// MaxAge also removes the marker about 2 s later, so a separate fast poll
	// checks its block in that window.
	checkFor(t, 20*time.Second, 10*time.Millisecond, func() error {
		for _, hdr := range storedHeaderBlocks(t, s, acc, "TTL") {
			if len(sliceHeader(JSMarkerReason, hdr)) > 0 {
				if !requestInfoHeaderBlockValid(hdr) {
					t.Fatalf("Subject delete marker is not strict: %q", hdr)
				}
				return nil
			}
		}
		return fmt.Errorf("no subject delete marker")
	})

	// Wait for the other asynchronous writers: the scheduled message, the
	// republish, the mirror, and the source.
	checkFor(t, 20*time.Second, 100*time.Millisecond, func() error {
		var scheduled bool
		for _, hdr := range storedHeaderBlocks(t, s, acc, "SCHED") {
			scheduled = scheduled || len(sliceHeader(JSScheduler, hdr)) > 0
		}
		switch {
		case !scheduled:
			return fmt.Errorf("no scheduled message")
		case storeHeaderMsgs(t, s, "RPT") != 2:
			return fmt.Errorf("republish: %d messages", storeHeaderMsgs(t, s, "RPT"))
		case storeHeaderMsgs(t, s, "MIR") != 3 || storeHeaderMsgs(t, s, "SRC") != 3:
			return fmt.Errorf("mirror or source not complete")
		}
		return nil
	})

	require_Equal(t, storeHeaderMsgs(t, s, "PLAIN"), 3)
	require_Equal(t, storeHeaderMsgs(t, s, "CNT"), 2)
	require_Equal(t, storeHeaderMsgs(t, s, "ATOM"), 5)
	require_Equal(t, storeHeaderMsgs(t, s, "FAST"), 3)
	// The TTL stream can be empty now: its messages and the marker expire.
	requireStoredHeaderBlocksStrict(t, s, acc, "TTL")
	for _, name := range []string{"KV_CFG", "OBJ_OBJ", "PLAIN", "CNT", "SCHED", "ATOM", "FAST", "RP", "RPT", "MIR", "SRC"} {
		if n := requireStoredHeaderBlocksStrict(t, s, acc, name); n == 0 {
			t.Fatalf("Stream %q has no stored header block to check", name)
		}
	}
	if w := l.all(); len(w) != 0 {
		t.Fatalf("Want no store check warning, got %q", w)
	}
}

// Mirror and source ingest are not checked. The test stores loose blocks
// while stamping is off (as data from before the check), turns stamping on
// with a reload, and then makes a mirror and a source of the stream. Both
// store the loose blocks. The mirror republishes them, and the stream that
// gets the republish (an internal client, kind JETSTREAM) rejects them.
func TestJetStreamStampRequestInfoStoreSkipsMirrorAndSourceIngest(t *testing.T) {
	content := fmt.Sprintf("listen: 127.0.0.1:-1\njetstream: {store_dir: %q}\nstamp_request_info: false\n", t.TempDir())
	conf := createConfFile(t, []byte(content))
	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()
	l := &storeHeaderLogger{}
	s.SetLogger(l, false, false)
	nc, js := jsClientConnect(t, s)
	defer nc.Close()
	acc := s.GlobalAccount()

	addStream(t, nc, &StreamConfig{Name: "LEG", Subjects: []string{"leg.>"}, Storage: FileStorage})
	raw := dialRawStorePub(t, s)
	for i, hdr := range looseStoreHeaderBlocks {
		raw.hpub(fmt.Sprintf("leg.%d", i), _EMPTY_, hdr, "x")
	}
	// The stream stores after the read loop, so wait for the count.
	checkFor(t, 5*time.Second, 10*time.Millisecond, func() error {
		if n := storeHeaderMsgs(t, s, "LEG"); n != uint64(len(looseStoreHeaderBlocks)) {
			return fmt.Errorf("legacy stream has %d messages", n)
		}
		return nil
	})
	legacy := storedHeaderBlocks(t, s, acc, "LEG")
	require_Len(t, len(legacy), len(looseStoreHeaderBlocks))
	for i, hdr := range legacy {
		if string(hdr) != looseStoreHeaderBlocks[i] || requestInfoHeaderBlockValid(hdr) {
			t.Fatalf("Legacy message %d: want the loose block %q, got %q", i+1, looseStoreHeaderBlocks[i], hdr)
		}
	}

	reloadUpdateConfig(t, s, conf, strings.Replace(content, "stamp_request_info: false", "stamp_request_info: true", 1))
	require_True(t, s.stampReqInfo.Load())

	addStream(t, nc, &StreamConfig{Name: "TGT", Subjects: []string{"rp.>"}, Storage: FileStorage})
	// The mirror republishes. A source adds Nats-Stream-Source, and a stream
	// rejects that header in a message that is not sourced (upstream
	// JSMessageSourceHdrNotAllowedErr), so the source does not republish.
	addStream(t, nc, &StreamConfig{Name: "MIR", Storage: FileStorage, Mirror: &StreamSource{Name: "LEG"},
		RePublish: &RePublish{Source: "leg.>", Destination: "rp.>"}})
	addStream(t, nc, &StreamConfig{Name: "SRC", Storage: FileStorage, Sources: []*StreamSource{{Name: "LEG"}}})

	// A strict control message after the loose ones. Ingest and republish
	// keep the order, so when TGT has the control message, it has seen the
	// loose ones.
	m := nats.NewMsg("leg.control")
	m.Header.Set("X-Control", "1")
	_, err := js.PublishMsg(m)
	require_NoError(t, err)
	checkFor(t, 10*time.Second, 50*time.Millisecond, func() error {
		if n := storeHeaderMsgs(t, s, "MIR"); n != 3 {
			return fmt.Errorf("mirror has %d messages", n)
		}
		if n := storeHeaderMsgs(t, s, "SRC"); n != 3 {
			return fmt.Errorf("source has %d messages", n)
		}
		if n := storeHeaderMsgs(t, s, "TGT"); n != 1 {
			return fmt.Errorf("republish target has %d messages", n)
		}
		return nil
	})

	mirrored := storedHeaderBlocks(t, s, acc, "MIR")
	sourced := storedHeaderBlocks(t, s, acc, "SRC")
	for i := range looseStoreHeaderBlocks {
		if !bytes.Equal(mirrored[i], legacy[i]) {
			t.Fatalf("Mirror message %d: want %q, got %q", i+1, legacy[i], mirrored[i])
		}
		if requestInfoHeaderBlockValid(sourced[i]) || len(sliceHeader(JSStreamSource, sourced[i])) == 0 {
			t.Fatalf("Source message %d: want the loose block with the source header, got %q", i+1, sourced[i])
		}
	}
	if got := storedHeaderBlocks(t, s, acc, "TGT"); len(got) != 1 || len(sliceHeader("X-Control", got[0])) == 0 {
		t.Fatalf("Republish target: want only the control message, got %q", got)
	}
	if l.rejects("TGT") == 0 {
		t.Fatalf("Want a warning for the republish target, got %q", l.all())
	}
	for _, name := range []string{"LEG", "MIR", "SRC"} {
		if n := l.rejects(name); n != 0 {
			t.Fatalf("Stream %q: want no store check warning, got %d", name, n)
		}
	}
}
