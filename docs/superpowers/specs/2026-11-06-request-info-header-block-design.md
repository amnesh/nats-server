# Request Info header block check

Status: implementation and local verification (AMNET P6 unit U27).

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

When the feature is off, nothing changes (upstream behavior). Routes and
gateways are not checked; each server that accepts CLIENT or LEAF
connections must enable the feature.

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

## Limits that stay

- No stamp and no strip on a message without a reply subject or on a
  skipped subject (`$JS.`, `$KV.`, `$O.`, `$MQTT.`, `$NRG.`). Such a message
  keeps a client copy (CRLF form). Consumers must require a reply subject.
- A message that the server delivers from stored or internal state, for
  example a JetStream push delivery, has a reply subject that does not prove
  a server stamp.
- A stream can hold a block that is not strict. Sources: data stored before
  the check was on, a message that came over a route or a gateway from a
  server without the check, and a stream snapshot restore (the restore
  payload carries the stored messages, so the check does not read them).
  Server-written header blocks have the strict form. A server with the check
  drops the LEAF delivery of such a message. A mirror, a source, or an
  ordered consumer (for example a legacy nats.go KV watch) across a leaf
  link then sees a sequence gap, creates its consumer again at the same
  stream sequence, and gets the same drop again. It stops at that message
  (amendment, fork review R2). The LEAF warning names the reply
  (`$JS.ACK...`), which gives the stream, the consumer, and the stream
  sequence. Recovery: delete that message at the origin, or purge the stream
  up to the next sequence, or turn the feature off on the receiving server.
  Prevention: run the fixed fork with the feature on all servers before data
  enters the streams.

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
