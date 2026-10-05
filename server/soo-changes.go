package server

import (
	"bytes"
	"encoding/json"
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
