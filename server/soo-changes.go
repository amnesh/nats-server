package server

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Subject prefixes for which we skip stamping ClientInfoHdr: the receivers
// either strip the header (JetStream stream-store paths via processInboundJetStreamMsg)
// or never consult it for these subjects (NRG internal traffic). Skipping avoids
// per-publish JSON marshaling and buffer reallocation on these hot paths.
var skipRequestInfoStampPrefixes = [][]byte{
	[]byte("$JS."),
	[]byte("$KV."),
	[]byte("$O."),
	[]byte("$MQTT."),
	[]byte("$NRG."),
}

func skipRequestInfoStamp(subject []byte) bool {
	if len(subject) == 0 || subject[0] != '$' {
		return false
	}
	for _, p := range skipRequestInfoStampPrefixes {
		if bytes.HasPrefix(subject, p) {
			return true
		}
	}
	return false
}

// msgHeaderViolationErr is the -ERR text for a rejected header block. It is
// the text of the upstream close state MsgHeaderViolation.
const msgHeaderViolationErr = "Message Header Violation"

var (
	requestInfoHeaderStatus = []byte("NATS/1.0")
	requestInfoHeaderEnd    = []byte("\r\n\r\n")
)

// requestInfoHeaderStatusLen is the minimum length of an inline status after
// "NATS/1.0" and the trim of white space. It is statusLen of nats.go.
const requestInfoHeaderStatusLen = 3

// requestInfoHeaderBlockValid reports whether a header block has the strict
// wire form: it starts with "NATS/1.0", every line ends with CRLF, it has no
// bare CR or LF, its only empty line is the last line, and an inline status
// has at least three bytes. A client header parser (nats.go readMIMEHeader)
// ends a line at a bare LF and stops at the first empty line, but
// removeHeaderIfPresent finds a key only after CRLF and setHeader appends the
// server stamp at the end of the block. In the strict form both agree on each
// line, so the strip removes every client copy of Nats-Request-Info and a
// client parser reads the server stamp.
func requestInfoHeaderBlockValid(hdr []byte) bool {
	n := len(hdr)
	if n < len(emptyHdrLine) || !bytes.HasPrefix(hdr, requestInfoHeaderStatus) {
		return false
	}
	// The first CRLFCRLF ends the block, so no other line is empty.
	if bytes.Index(hdr, requestInfoHeaderEnd) != n-len(requestInfoHeaderEnd) {
		return false
	}
	for i, b := range hdr {
		switch b {
		case '\r':
			if i+1 == n || hdr[i+1] != '\n' {
				return false
			}
		case '\n':
			if i == 0 || hdr[i-1] != '\r' {
				return false
			}
		}
	}
	// The inline status rule of nats.go v1.54.0 DecodeHeadersMsg
	// (nats.go:4517-4523):
	//
	//	if len(l) > hdrPreEnd {
	//		status := strings.TrimSpace(l[hdrPreEnd:])
	//		if len(status) < statusLen {
	//			return nil, ErrBadHeaderMsg
	//		}
	//
	// l is the first line without its CRLF, hdrPreEnd is len("NATS/1.0"), and
	// statusLen is 3. nats.go v1.53.1 and earlier have no such check and slice
	// status[3:] (nats.go:4441-4444), so "NATS/1.0 5" makes the subscriber
	// panic in its read loop. bytes.TrimSpace trims the same white space as
	// strings.TrimSpace. The loop above proved that each CR starts a CRLF, so
	// the first CR ends the first line.
	line := hdr[:bytes.IndexByte(hdr, '\r')]
	if len(line) > len(requestInfoHeaderStatus) &&
		len(bytes.TrimSpace(line[len(requestInfoHeaderStatus):])) < requestInfoHeaderStatusLen {
		return false
	}
	return true
}

// malformedRequestInfoHeader reports whether an inbound CLIENT or LEAF message
// has a header block that is not in the strict wire form while stamping is
// on. It checks every such message, also without a reply subject and on a
// skipped subject, because a stream stores the header block and removes only
// the copies after CRLF. MQTT clients are not checked: the server writes their
// header blocks.
func (c *client) malformedRequestInfoHeader(msg []byte) bool {
	if c.pa.hdr <= 0 || c.srv == nil || !c.srv.stampReqInfo.Load() {
		return false
	}
	if c.kind != LEAF && (c.kind != CLIENT || c.isMqtt()) {
		return false
	}
	return c.pa.hdr > len(msg) || !requestInfoHeaderBlockValid(msg[:c.pa.hdr])
}

// rejectMalformedRequestInfoHeader drops a message that
// malformedRequestInfoHeader selects and returns true. The server gives a
// CLIENT the -ERR "Message Header Violation" and closes it with
// MsgHeaderViolation. A LEAF connection stays up, because one bad client behind
// a leaf must not close the link of all the clients behind it; the hub logs a
// rate-limited warning. The logs of this check contain no header bytes.
func (c *client) rejectMalformedRequestInfoHeader(msg []byte) bool {
	if !c.malformedRequestInfoHeader(msg) {
		return false
	}
	if mt, _ := c.isMsgTraceEnabled(); mt != nil {
		mt.setIngressError(msgHeaderViolationErr)
	}
	if c.kind == LEAF {
		// A dropped stored message (a mirror, source, or consumer delivery)
		// comes again after each consumer reset. The subject and the reply let
		// the operator find it: the reply of a JetStream delivery ($JS.ACK...)
		// names the stream, the consumer, and the stream sequence. The format,
		// not the statement, is the rate-limit key, so distinct subjects do not
		// add log lines.
		c.rateLimitFormatWarnf("Dropped a leafnode message with a malformed header block - Subject %q - Reply %q",
			c.pa.subject, c.pa.reply)
		return true
	}
	c.sendErr(msgHeaderViolationErr)
	c.Errorf("Message Header Violation - Subject %q", c.pa.subject)
	c.closeConnection(MsgHeaderViolation)
	return true
}

// storeRejectsHeaderBlock is the decision of the store check. A stream must
// not store a message when the server that stores it has stamping on, the
// message is not sourced, and its header block is not in the strict wire form
// (requestInfoHeaderBlockValid).
//
// The ingress check above covers only CLIENT and LEAF messages on a server
// with stamping on. A message can also come to the stream over a route or a
// gateway from a server with stamping off, or from an internal client (for
// example a republish). A stored block that is not strict stops a mirror, a
// source, or an ordered consumer across a leaf link into a server with
// stamping on: that server drops each delivery, and the reader creates its
// consumer again at the same stream sequence without end. The store check
// stops such a block before the stream stores it.
//
// sourced is true for the stream's own mirror and source ingest, and for the
// messages that the store makes (subject delete markers and scheduled
// messages). These are not checked. A reject of mirror or source ingest only
// moves the stop from the leaf link to the ingest of the stream, and a reject
// of a scheduled message can stop its schedule.
func storeRejectsHeaderBlock(s *Server, hdr []byte, sourced bool) bool {
	if sourced || len(hdr) == 0 || s == nil || !s.stampReqInfo.Load() {
		return false
	}
	return !requestInfoHeaderBlockValid(hdr)
}

// rejectStoreHeaderBlock applies the store check to a message for stream name
// before the stream stores it or proposes it. On a reject it logs a
// rate-limited warning that names the account and the stream, and returns the
// error for the PubAck: JSBadRequestErr (code 400, error code 10003, "bad
// request"). Otherwise it returns nil. The statement of the warning is the
// rate-limit key, so the server writes one line for each stream in each
// interval. The warning contains no subject and no header bytes.
//
// The callers are checkMsgHeadersPreClusteredProposal (a clustered publish
// before its proposal, and each atomic or fast batch message) and
// processJetStreamMsgWithBatch (a stream without a Raft node, and a
// trace-only message). The callers can hold the stream lock. Thus this
// function takes no stream lock and reads only mset.srv and mset.acc, which do
// not change after the stream is created.
func (mset *stream) rejectStoreHeaderBlock(name string, hdr []byte, sourced bool) *ApiError {
	s := mset.srv
	if !storeRejectsHeaderBlock(s, hdr, sourced) {
		return nil
	}
	var accName string
	if mset.acc != nil {
		accName = mset.acc.Name
	}
	s.RateLimitWarnf("Rejected a message with a malformed header block for stream '%s > %s'", accName, name)
	return NewJSBadRequestError()
}

func (c *client) stampRequestInfoHeaderIfNeeded(msg []byte) []byte {
	// Hot path: when disabled (the default), pay only one atomic load. The
	// mirror is kept in sync with opts.StampRequestInfo by setOpts (which runs
	// before reload's per-option Apply), so no optsMu RLock is needed here.
	if c.srv == nil || !c.srv.stampReqInfo.Load() {
		return msg
	}
	if len(c.pa.reply) == 0 || (c.kind != CLIENT && c.kind != LEAF) {
		return msg
	}
	if skipRequestInfoStamp(c.pa.subject) {
		return msg
	}

	// For LEAF inbound, if the message carries a forwarded ClientInfoHdr from
	// a remote domain, capture its Reply field. The identity portion will be
	// replaced with this leaf connection's info (per the security model
	// documented at client.go:4901-4904: do not trust forwarded identity),
	// but Reply must be preserved because chained service-import handling
	// (client.go:4906-4911) uses it to route the response back to the
	// original requestor across the leaf boundary.
	var fwdReply string
	if c.kind == LEAF && c.pa.hdr > 0 {
		if fwd := sliceHeader(ClientInfoHdr, msg[:c.pa.hdr]); fwd != nil {
			var fwdCI ClientInfo
			if json.Unmarshal(fwd, &fwdCI) == nil {
				fwdReply = fwdCI.Reply
			}
		}
	}

	// Look up the cached, pre-marshaled CI. On miss, snapshot the inputs
	// under c.mu then Marshal OUTSIDE the lock to keep the critical section
	// to just field reads. The cache publish is best-effort: a concurrent
	// invalidation (e.g. swapAccountAfterReload on the reload goroutine)
	// may have raced; if so, leave its decision and use our marshaled bytes
	// for this one request only.
	c.mu.Lock()
	b := c.ciStampHdr
	if b != nil {
		c.mu.Unlock()
	} else {
		snapshot := ClientInfo{
			Account:    accForClient(c),
			User:       c.getRawAuthUser(),
			Name:       c.opts.Name,
			Tags:       c.tags,
			Kind:       c.kindString(),
			ClientType: c.clientTypeString(),
			Lang:       c.opts.Lang,
			Host:       c.host,
			RTT:        c.rtt,
		}
		c.mu.Unlock()
		b, _ = json.Marshal(&snapshot)
		if b != nil {
			c.mu.Lock()
			if c.ciStampHdr == nil {
				c.ciStampHdr = b
			}
			c.mu.Unlock()
		}
	}
	if b == nil {
		return msg
	}

	// If we preserved a forwarded Reply, splice it into a one-off CI for
	// just this request. The cache deliberately omits Reply since it varies
	// per request and would otherwise defeat caching.
	if fwdReply != _EMPTY_ {
		var ci ClientInfo
		if json.Unmarshal(b, &ci) == nil {
			ci.Reply = fwdReply
			if nb, _ := json.Marshal(&ci); nb != nil {
				return c.setHeader(ClientInfoHdr, bytesToString(nb), msg)
			}
		}
	}
	return c.setHeader(ClientInfoHdr, bytesToString(b), msg)
}

// getClientInfoForRequest returns a trimmed ClientInfo used to stamp inbound
// request messages. It carries enough to identify the requestor (account,
// user, name, tags, kind, client type, lang, host, RTT) without the heavier
// fields of the detailed form (JWT, issuer key, server/cluster, start time).
func (c *client) getClientInfoForRequest() *ClientInfo {
	if c == nil || (c.kind != CLIENT && c.kind != LEAF && c.kind != JETSTREAM && c.kind != ACCOUNT) {
		return nil
	}
	var ci ClientInfo
	c.mu.Lock()
	ci.Account = accForClient(c)
	ci.User = c.getRawAuthUser()
	ci.Name = c.opts.Name
	ci.Tags = c.tags
	ci.Kind = c.kindString()
	ci.ClientType = c.clientTypeString()
	ci.Lang = c.opts.Lang
	ci.Host = c.host
	ci.RTT = c.rtt
	c.mu.Unlock()
	return &ci
}

// calloutDecidesIdentity reports whether an auth callout decides who this
// connection is: its account has external authorization and the verified
// user is not one of the account's auth users. This is the condition under
// which processClientOrLeafAuthentication calls the callout for a JWT user.
// Lock should be held; the account read lock is taken after it.
func (c *client) calloutDecidesIdentity() bool {
	return c.acc != nil && c.acc.hasExternalAuth() && !c.acc.isExternalAuthUser(c.pubKey)
}

// getConnectRawAuthUser returns the auth user for the auth callout request,
// the auth error events, and the authentication error log. While a callout
// decides the identity, for example of a sentinel JWT connection, it keeps
// the upstream order with the CONNECT nkey and user fields before the JWT
// subject. Otherwise it equals getRawAuthUser, so a verified JWT subject that
// a grant or verification hook rejects is reported. Lock should be held.
func (c *client) getConnectRawAuthUser() string {
	if c.calloutDecidesIdentity() {
		switch {
		case c.opts.Nkey != _EMPTY_:
			return c.opts.Nkey
		case c.opts.Username != _EMPTY_:
			return c.opts.Username
		}
	}
	return c.getRawAuthUser()
}

// getConnectAuthUser is the log form of getConnectRawAuthUser, for the
// authentication error log. Lock should be held.
func (c *client) getConnectAuthUser() string {
	if c.calloutDecidesIdentity() {
		switch {
		case c.opts.Nkey != _EMPTY_:
			return fmt.Sprintf("Nkey %q", c.opts.Nkey)
		case c.opts.Username != _EMPTY_:
			return fmt.Sprintf("User %q", c.opts.Username)
		}
	}
	return c.getAuthUser()
}
