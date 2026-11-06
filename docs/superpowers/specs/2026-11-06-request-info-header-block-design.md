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
MQTT) and LEAF message that has headers, before any other inbound work. The
check also applies without a reply subject and on the skipped subjects,
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
leaf must not stop the link for all clients behind it. No log contains
header bytes.

When the feature is off, nothing changes (upstream behavior). Routes and
gateways are not checked; each server that accepts CLIENT or LEAF
connections must enable the feature.

## Limits that stay

- No stamp and no strip on a message without a reply subject or on a
  skipped subject (`$JS.`, `$KV.`, `$O.`, `$MQTT.`, `$NRG.`). Such a message
  keeps a client copy (CRLF form). Consumers must require a reply subject.
- A message that the server delivers from stored or internal state, for
  example a JetStream push delivery, has a reply subject that does not prove
  a server stamp.
- A stream can hold a block in another form that a server without the check
  stored. A LEAF delivery of such a message (for example a source or mirror
  delivery over a leaf link) is dropped. Server-written header blocks have
  the strict form.

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
