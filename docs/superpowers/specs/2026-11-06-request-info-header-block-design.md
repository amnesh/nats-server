# Request Info header block check

Status: implementation and local verification (AMNET P6 unit U27; store
check amendment P6-U32).

## Defect

With `stamp_request_info` on, a CLIENT or LEAF connection can make a nats.go
subscriber read a forged `Nats-Request-Info` value as the only value. The
frame is `HPUB <service> <own inbox> ...` with the header block
`NATS/1.0\nNats-Request-Info: {forged}\r\n\r\n\r\n`:

1. `getHeaderKeyIndex` finds a key only after CRLF, so `removeHeaderIfPresent`
   does not remove the forged line after the bare LF.
2. `setHeader` writes the server stamp at the end of the block, after the
   inner empty line.
3. nats.go `readMIMEHeader` ends a line at a bare LF and stops at the first
   empty line. It reads one value: the forged value.

`nats.Msg` keeps no raw header bytes, so a consumer cannot detect the frame.
A consumer check (a reply subject and exactly one value) closes the case
without a reply subject and the case with two values, but not this frame.

## Policy

When `stamp_request_info` is on, check the header block of each CLIENT (not
MQTT) and LEAF message that has headers. The check is the first statement of
`processInboundClientMsg` and `processInboundLeafMsg`, so it runs before the
origin-marker rewrite, the statistics, the permissions, delivery, the stamp,
and the strip. It reads the header block that the parser gives to these
functions: message-trace setup and subject mapping run before it (see
"Message-trace setup" below). The check also applies without a reply subject and on the skipped subjects,
because a stream stores the block and removes only the copies after CRLF.
The block must start with `NATS/1.0`, end each line with CRLF, have no bare
CR or LF, and have no empty line before its end. An inline status must have
at least three bytes after the trim of white space (the rule of nats.go
`v1.54.0` `DecodeHeadersMsg`).

In this form the server strip and nats.go agree on each line. The existing
loop in `removeHeaderIfPresent` removes every client copy, and nats.go reads
the server stamp.

Status rule (amendment, fork review R1): nats.go `v1.53.1` and earlier slice
`status[3:]` without a length check, so the block `NATS/1.0 5\r\n\r\n` or
`NATS/1.0 \r\n\r\n` makes a subscriber panic in its read loop. The check uses
the exact `v1.54.0` rule on the first line `l` (the bytes before the first
CRLF): if `len(l) > 8`, then `len(TrimSpace(l[8:])) >= 3`. The check stops
this attack only while `stamp_request_info` is on and only for CLIENT and
LEAF ingress; consumers must also use nats.go `v1.54.0` or later. Every
status that the server writes has three digits.

A failed check drops the message. A CLIENT gets
`-ERR 'Message Header Violation'` and is closed with the upstream close state
`MsgHeaderViolation`, which upstream defines and does not use. A LEAF link
stays up and the hub logs a rate-limited warning: one bad client behind a
leaf must not stop the link for all clients behind it. The warning names the
subject and the reply with `%q` (amendment, fork review R2). The format is
the rate-limit key, so distinct subjects add no log lines. The logs of the
check contain no header bytes. Upstream message-trace setup can log a header
value (`Nats-Trace-Origin-Account`) before the check.

When the feature is off, nothing changes (upstream behavior). The ingress
check does not check routes and gateways; each server that accepts CLIENT or
LEAF connections must enable the feature. The store check (below) covers a
message for a stream that comes over a route or a gateway.

## Message-trace setup (amendment, fork review R3)

The parser calls `initMsgTrace` before `processInboundMsg`. With a
`Nats-Trace-Origin-Account` header, or with a `traceparent` header and a
sampling miss, trace setup replaces the `Nats-Trace-Dest` value with
`trace disabled` through `setHeader`. `setHeader` removes the last CRLF of
the block and appends the new line and the final empty line. A block without
its final empty line thus gets the strict form before the check, and passes.
This is not a bypass: the new block is strict. The stamp strip removes the
client copy of `Nats-Request-Info`, which is now merged with the appended
line, and nats.go reads one value, the server stamp. A block with another
defect (a bare LF, an inner empty line, a short status) keeps it after the
change, and the check rejects it.

## Store check (amendment, P6-U32)

Defect: a stored block that is not strict stops a mirror or a source across a
leaf link into a server with the feature on (stall probe of 2026-11-08). The
receiver drops each delivery, and the reader creates its consumer again at
the same stream sequence without end. With only the ingress check, a route or
a gateway from a server with the feature off, and an internal client, can
still give a stream such a block.

Policy (owner option 4): when the feature is on, the server that stores a
message for a stream (the stream leader, or the only server of a stream
without a Raft group) rejects a header block that is not strict, with
`requestInfoHeaderBlockValid`, for each client kind and each input path. The
check runs before the store and before the Raft proposal:
`checkMsgHeadersPreClusteredProposal` covers a clustered publish and each
atomic or fast batch message; `processJetStreamMsgWithBatch` covers a new
message (`lseq` and `ts` are 0) on a stream without a Raft group and a
trace-only message. It never runs at a Raft apply, so the replicas do not
diverge. An apply has the sequence and the timestamp of the entry. This is
also true after a scale-down to R1 removes the Raft node while the apply loop
still applies an entry that the old leader acknowledged (P6-U32 review L1).

The check skips sourced messages: the mirror and source ingest of the stream
(a reject there only moves the stop into the ingest), and the messages that
the store makes (subject delete markers and scheduled messages; a reject can
stop a schedule). The upstream `sourced` flag marks all of them. The check
reads the block that the stream gets, after `removeHeaderStatusIfPresent` in
`processInboundJetStreamMsg` and before the server removes its own
`Nats-Request-Info`. Thus a short inline status becomes no header block, and
the N1 frame becomes `NATS/1.0\r\n\r\n\r\n`, which the check rejects.

The restart recovery of a partial atomic batch write stores without the
check, because the staged messages carry the batch headers. They got the
check at their commit only if the feature was on at that commit; a batch
committed while the feature was off and recovered after a restart with the
feature on is stored without the check (P6-U32 review L3).

Result: a publish with a reply gets a `PubAck` with `JSBadRequestErr` (400,
10003), an existing upstream error, so the upstream error code table does not
change. A publish without a reply is dropped. Each reject logs the
rate-limited warning
`Rejected a message with a malformed header block for stream '<account> > <stream>'`
(the statement is the key; no subject, no header bytes).

Server writers: `genHeader`, `client.setHeader`, `setHeader`, and the fixed
blocks are strict. The MQTT request header block was not strict (an empty
line before its end, so each new session record stored
`NATS/1.0\r\n\r\n\r\n`). The fork corrects it (FORK-CHANGES section 13);
without the correction the store check rejects each new MQTT session record.
A server without the correction can still send such a record over a route:
a new session record, a transferred legacy session record (`$MQTT_sess`), or
a transferred legacy retained message (`$MQTT_rmsgs`). Thus upgrade all MQTT
servers with stamping off and then turn it on, or keep the leaders of these
streams on old servers until all servers have the correction
(FORK-CHANGES section 13). An MQTT retained record copies the CONNECT user
name into `Nmqtt-RSrc` without a check (upstream); a user name with a CR or
an LF makes a block that is not strict, and the store check rejects that
retained message while stamping is on.

## Limits that stay

- No stamp and no strip on a message without a reply subject or on a
  skipped subject (`$JS.`, `$KV.`, `$O.`, `$MQTT.`, `$NRG.`). Such a message
  keeps a client copy (CRLF form). Consumers must require a reply subject.
- A message that the server delivers from stored or internal state, for
  example a JetStream push delivery, has a reply subject that does not prove
  a server stamp.
- A stream can hold a block that is not strict. Sources: data stored before
  the store check was on, a message that a stream leader with the feature off
  stored, a stream snapshot restore (the restore payload carries the stored
  messages, so no check reads them), the mirror or source ingest of such a
  block or a scheduled message made from it, and an MQTT session record from
  before the MQTT correction. Server-written header blocks have the strict
  form, except an MQTT retained record with a client user name that has a CR
  or an LF. With the store check on each stream leader, a route or a gateway no
  longer adds such a block. A server with the check
  drops the LEAF delivery of such a message. A mirror, a source, or an
  ordered consumer (for example a legacy nats.go KV watch) across a leaf
  link then sees a sequence gap, creates its consumer again at the same
  stream sequence, and gets the same drop again. It stops at that message
  (amendment, fork review R2). The LEAF warning names the reply
  (`$JS.ACK...`), which gives the stream, the consumer, and the stream
  sequence. Recovery: delete that message at the origin, or purge the stream
  up to the next sequence, or turn the feature off on the receiving server.
  Prevention: run the fixed fork with the feature on all servers before data
  enters the streams; the store check needs the feature on each server that
  can lead a stream.

## Verification

- Unit: the block grammar (also the short inline status, with tab, NBSP, and
  multibyte boundary rows), the check scope (kinds, MQTT, feature off), and
  the removal of three client copies by the stamp.
- Black-box raw TCP, short status: `NATS/1.0 5` and `NATS/1.0 ` through a raw
  CLIENT (`-ERR`, close, no delivery) and a raw LEAF (no delivery, the link
  stays up). The observer is a raw subscriber, because a nats.go `v1.53.1`
  subscriber panics on such a block. Positive control:
  `NATS/1.0 503 No Responders` passes through both, and nats.go reads the
  status and one server stamp.
- Black-box raw TCP: the N1 frame, a bare LF in the status line, a bare LF
  before the key, an inner empty line, and a block without its final empty
  line, through a raw CLIENT (`-ERR`, close, no delivery) and a raw LEAF (no
  delivery, the link stays up). Positive control: a CRLF block with client
  copies arrives with one server stamp. Feature off: the frame passes.
- Fork review R4: unit scope rows for each skipped subject prefix (`$KV.`,
  `$JS.`, `$O.`, `$MQTT.`, `$NRG.`), with and without a reply subject; a
  black-box leg that publishes the N1 frame without a reply subject to a
  stream subject and to a `$KV.` subject (`-ERR`, close, no stored message);
  and a trace leg: a `traceparent` block with its final empty line passes,
  without it the client is rejected and the trace event has the ingress
  error, and a block that trace setup changes passes with one server stamp.
- Fork review R2: a unit test of the LEAF warning text (subject and reply,
  no header bytes) and of its rate-limit key.
- P6-U32 store check: unit tests of the decision (stamping, sourced, and
  block) and of the warning (error, text, rate-limit key). A two-server
  cluster with stamping on only at the stream leader: a raw client of the
  other server publishes loose blocks to R1 and R2 streams (dropped without a
  reply, `JSBadRequestErr` with a reply, no stored message on any peer), and
  R1 and R2 mirrors and sources on the leader ingest a loose block. A single
  server: a direct store call, an internal ACCOUNT client, an atomic batch
  commit, and a fast batch reject a loose block with stamping on and store
  it with stamping off; KV, object store, counter, TTL and marker, schedule,
  atomic and fast batch, republish, mirror, source, and MQTT messages store
  strict blocks with stamping on; legacy loose blocks (stored with stamping
  off, then a reload) go into a mirror and a source, and the stream that gets
  the republish of the mirror rejects them. Review L1: a store call with the
  sequence and timestamp of a Raft entry (the apply form, also on a stream
  without a Raft node) stores a loose block, and a call with both 0 rejects
  it.
