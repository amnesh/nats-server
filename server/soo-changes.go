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
	if c.srv == nil || !c.srv.getOpts().StampRequestInfo {
		return msg
	}
	if len(c.pa.reply) == 0 || (c.kind != CLIENT && c.kind != LEAF) {
		return msg
	}
	if skipRequestInfoStamp(c.pa.subject) {
		return msg
	}
	ci := c.getClientInfoForRequest()
	if ci == nil {
		return msg
	}
	if b, _ := json.Marshal(ci); b != nil {
		return c.setHeader(ClientInfoHdr, bytesToString(b), msg)
	}
	return msg
}

// getClientInfoForRequest returns a trimmed ClientInfo used to stamp inbound
// request messages. It carries enough to identify the requestor (account,
// user, name, kind, client type, lang, host, RTT) without the heavier fields
// of the detailed form (JWT, issuer key, tags, server/cluster, start time).
func (c *client) getClientInfoForRequest() *ClientInfo {
	if c == nil || (c.kind != CLIENT && c.kind != LEAF && c.kind != JETSTREAM && c.kind != ACCOUNT) {
		return nil
	}
	var ci ClientInfo
	c.mu.Lock()
	ci.Account = accForClient(c)
	ci.User = c.getRawAuthUser()
	ci.Name = c.opts.Name
	ci.Kind = c.kindString()
	ci.ClientType = c.clientTypeString()
	ci.Lang = c.opts.Lang
	ci.Host = c.host
	ci.RTT = c.rtt
	c.mu.Unlock()
	return &ci
}
