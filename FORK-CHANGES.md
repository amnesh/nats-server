# FORK-CHANGES.md

This fork of [nats-server](https://github.com/nats-io/nats-server) carries a small
set of **custom features** on top of an upstream release branch. 
This document explains every fork-specific change against
upstream NATS Server so that developers can use, operate, and maintain them.

> Maintenance model: custom commits are kept as small, self-contained patches on
> top of an upstream `release/vX.Y.Z` branch and cherry-picked forward when the
> fork is rebased onto a newer release. Each feature is isolated into its own
> file(s) with the smallest possible footprint in upstream files, so rebases rarely
> conflict.

## Changes at a glance

| # | Feature | Enable with | New files | Touched upstream files |
|---|---|---|---|---|
| 1 | **Authentication Verification Callout** (`authverify`) | `authorization { auth_verification: true }` | `server/authverify/` (pkg), `server/auth_verification.go` | `server/opts.go`, `server/auth.go` |
| 2 | **Request Info Stamping** (userinfo on all requests) | `stamp_request_info: true` (hot-reloadable) | `server/soo-changes.go` | `server/client.go`, `server/leafnode.go`, `server/opts.go`, `server/reload.go`, `server/server.go`, `server/stream.go`, `server/jetstream_batching.go` |
| 3 | Custom Listeners/Dialers (transport injection) | programmatic (`Options`) | — | listener/dialer plumbing (see commit `6f42d0a4f`) |
| 4 | **Scoped Resource Permission Groups** (`template.xpermissions`) | add signed groups to a scoped signing key template | `server/auth_xpermissions.go`, `server/auth_xpermissions_compile.go` | `server/accounts.go`, `server/server.go`, `server/auth.go`, `server/auth_callout.go` |
| 5 | **Leafnode scaling** (isolated hubs with 60k+ leaves) | always on; the isolation fast paths apply with `leafnodes { isolate: true }` or a remote's `request_isolation`. Optional: `leafnodes { sync_consumers_check_interval: "250ms" }` (off by default, hot-reloadable) | `server/leafnode_isolation.go`, `server/leafnode_dupindex.go`, `server/leafnode_synccheck.go` | `server/leafnode.go`, `server/sublist.go`, `server/accounts.go`, `server/client.go`, `server/server.go`, `server/opts.go`, `server/reload.go` |
| 6 | Leafnode `SignatureCB` kept across reload | programmatic (`RemoteLeafOpts.SignatureCB`) | — | `server/reload.go` |
| 7 | `Account.SetJetStreamLimits` (JetStream limits for accounts built in code) | programmatic | `server/account_jslimits.go` | — |
| 8 | Grant mode | operator-signed account JWT `nats.authverify.mode: "grant"` and programmatic `Options.AuthGrant` | `server/authverify/grant.go`, `server/auth_grant*.go` | `server/accounts.go`, `server/auth.go`, `server/client.go`, `server/leafnode.go`, `server/monitor.go`, `server/opts.go`, `server/reload.go`, `server/server.go` |
| 9 | Subject-only rollup | `feature_flags { js_subject_rollup_only: true }` | `server/jetstream_subject_rollup*_test.go` | `server/feature_flags.go`, `server/jetstream.go`, `server/stream.go`, `server/jetstream_batching.go` |
| 10 | Native inbox capture policy | `feature_flags { js_reject_inbox_capture: true }` | `server/jetstream_inbox_capture*.go` | `server/feature_flags.go`, `server/jetstream.go`, `server/client.go`, `server/events.go`, `server/leafnode.go`, `server/jetstream_api.go`, `server/jetstream_cluster.go`, `server/stream.go`, `server/stream_backup.go` |
| 11 | Leaf removal during the initial interest window (upstream defect correction) | always on | `server/leafnode_tsub_test.go` | `server/leafnode.go` |
| 12 | Grant reject codes, no leaf CONNECT with a revoked JWT, and a long leaf delay for a disabled account | a reject code from the grant hook, `DisconnectClient`, or the static callout `code`; the leaf checks are always on | `server/auth_reject_codes.go`, `server/leafnode_revoked.go`, `server/leafnode_account_disabled.go` | `server/authverify/grant.go`, `server/authverify/req.go`, `server/auth.go`, `server/auth_grant.go`, `server/auth_verification.go`, `server/client.go`, `server/monitor.go`, `server/websocket.go`, `server/leafnode.go` |
| 13 | MQTT request header block (upstream defect correction) | always on | `server/mqtt_soo_store_header_test.go` | `server/mqtt.go` |
| 14 | Source and mirror request after a leaf link connects (upstream defect correction) | always on | `server/jetstream_leafnode_late_link_test.go` | `server/stream.go` |
| 15 | `Server.RefreshClientTraceLevel` (trace flag of open connections) | programmatic | `server/client_trace_refresh.go` | `server/reload.go` |
| 16 | `Connz` marker for a connection that waits for its verification verdict | with auth verification (feature 1) or grant mode (feature 8) | `server/auth_verification_pending.go` | `server/auth.go`, `server/auth_verification.go`, `server/auth_grant.go`, `server/client.go`, `server/monitor.go` |

Features 1, 2, 4 and 5 are documented in full below. Feature 3 is summarized in between. Features 6 and 7 are documented after feature 5. Grant mode is documented in section 8. Sections 11, 13, and 14 record corrections of upstream defects. Section 12 documents the reject codes and the leaf checks for a revoked JWT and a disabled account. Section 15 documents an API for a host that changes the logger at run time. Section 16 documents the `Connz` marker of a connection that waits for its verification verdict.

---

# 1. Authentication Verification Callout (`authverify`)

## 1.1 What it is

A **post-authentication policy hook** for operator/JWT-mode connections. When
enabled, *after* the server has cryptographically verified a JWT-based
client/leaf (its nkey-signed nonce **and** its operator→account→user JWT chain),
the server asks a trusted service running in the **system account** for a verdict.
The service can:

- **reject** the connection, or
- **admit** it unchanged, or
- **admit with a narrowing override** — tighten the user's permissions and/or
  bring their expiration sooner.

The server remains the authoritative verifier of identity. The verification
service can never change *who* the user is, and **can never escalate** their
rights — only restrict them.

## 1.2 How this differs from upstream `auth_callout`

Upstream already has an *auth callout* (`server/auth_callout.go`, subject
`$SYS.REQ.USER.AUTH`). This feature is deliberately different:

| | Upstream `auth_callout` | This fork's `auth_verification` |
|---|---|---|
| When it runs | On local-auth **failure** / for external-auth accounts | On every **successful** JWT auth (when enabled) |
| Identity | **Substitutes** the user's nkey with an ephemeral one | **Preserves** the real nkey/JWT — server already verified it |
| Service returns | A freshly **minted user JWT** (full authority) | A **JSON verdict**: reject, or narrow-only override |
| Service privilege | Must hold account signing keys to mint JWTs | None — it only answers a question |
| Trust of the answer | Signed JWT verified against account keys | Trusted via **system-account access control** |

Use `auth_callout` when an external service should *own* authentication. Use
`auth_verification` when NATS should remain the authoritative identity layer and
you only want to layer a policy decision (e.g. a second factor, a per-session
permission tightening, or a shorter lease) on top.

## 1.3 Configuration

A single boolean inside the `authorization` block:

```
authorization {
  auth_verification: true
}
```

- Maps to `Options.AuthVerification bool`.
- Default: `false` (feature off; zero overhead).
- Everything else is **fixed** (not configurable):
  - request subject: `$SYS.REQ.USER.VERIFY` (`authverify.AuthVerificationSubject`)
  - response timeout: `2s` (`authverify.AuthVerificationTimeout`)
- The deployment **must have a `system_account` configured** — the request/reply
  happens there. With no system account, connections fail closed.

## 1.4 Which connections are verified (scope)

Verification runs only for connections that are **all** of:

- authenticated via a **user JWT** (operator mode), and
- of kind **CLIENT** or **LEAF**, and
- **not** in-process connections, and
- **not** bound to the **system account** (so the verification service itself can
  always connect — this is the bootstrap safety), and
- **not** delegated to the upstream `auth_callout` for that account.

Internal connections (ROUTER/GATEWAY) and non-JWT auth (config nkey, user/pass)
are out of scope. See `AuthVerifyInScope` in `server/auth_verification.go`.

## 1.5 The flow

```
client/leaf CONNECT (jwt + sig + user/pass/token + ...)
   │
   ▼  server verifies nkey signature + operator→account→user JWT chain
   │  (revocation / src-IP / connect-times all pass)
   ▼  feature enabled & in scope?
   │        │ no → admit as usual
   │        ▼ yes
   │  publish AuthVerifyRequest (JSON) on $SYS.REQ.USER.VERIFY in the system account,
   │  reply on a private inbox; wait up to 2s
   ▼
verification service replies with AuthVerifyResponse (JSON)
   │  reject            → connection DENIED (fail-closed)
   │  ok                → admit unchanged
   │  ok + override     → narrow permissions/expiry, then admit
   ▼
(no reply / timeout / bad nonce / transport error) → DENIED (fail-closed)
```

The round-trip happens in the connection's auth path **after** the server lock is
released (in the deferred block of `processClientOrLeafAuthentication`), so it
never blocks the rest of the server. Only the connecting client waits.

## 1.6 Request wire format (`AuthVerifyRequest`)

Plain JSON (not a signed JWT) published in the system account. Defined in
`server/authverify/req.go`:

```jsonc
{
  "server":       { "name": "...", "host": "...", "id": "...", "version": "...", "cluster": "..." },
  "request_nonce":"<opaque, must be echoed in the response>",
  "user_nkey":    "U...",            // the REAL verified user public key (identity preserved)
  "account":      "A...",            // bound account public key
  "client_info":  {                  // jwt.ClientInformation
    "host": "...", "id": 123, "user": "...", "name": "...",
    "tags": [...], "name_tag": "...", "kind": "Client", "type": "nats",
    "nonce": "..."                   // the server nonce the user signed (when a sig was sent)
  },
  "connect_opts": {                  // jwt.ConnectOptions — everything the client submitted
    "jwt": "...", "nkey": "...", "sig": "...",
    "auth_token": "...", "user": "...", "pass": "...",
    "lang": "...", "version": "...", "protocol": 1
  },
  "client_tls": {                    // omitted if no TLS
    "version": "1.3", "cipher": "...",
    "verified_chains": [[ "<PEM>", ... ]],   // if client certs were verified
    "certs": [ "<PEM>", ... ]                // peer certs if not verified
  }
}
```

The request carries **all submitted credentials** (including the plaintext
`pass`), connection info, TLS info, and the bound `account` — everything a policy
engine needs. It is not signed: the security boundary is the system account.

## 1.7 Response wire format (`AuthVerifyResponse`)

```jsonc
{
  "request_nonce": "<must equal the request's nonce, else the verdict is rejected>",
  "reject":        false,            // true => deny the connection
  "reason":        "",               // optional, logged on reject
  "permissions":   {                 // optional narrowing override (jwt.Permissions)
    "pub": { "allow": ["foo.>"], "deny": ["foo.secret.>"] },
    "sub": { "allow": ["_INBOX.>"] },
    "resp":{ "max": 1, "ttl": 2000000000 }
  },
  "expires":       0,                // optional unix-seconds; only honored if SOONER than the JWT exp
  "code":          0                 // optional reject code (section 12); only used with reject
}
```

Outcomes:
- `reject: true` → connection denied. The optional `code` selects the wire
  text and close state of section 12. An absent, unknown, or malformed `code`
  is a denial (`Authorization Violation`). A malformed `code` makes the
  complete response invalid, so it also rejects.
- no `permissions`/`expires` → admit unchanged.
- `permissions`/`expires` present → the server narrows the verified claims and
  re-registers the user before admitting.

## 1.8 Narrowing semantics (cannot escalate)

All override application is done by package `server/authverify` and is provably
non-escalating:

| Field | Rule |
|---|---|
| Expiration | effective = **sooner** of (JWT exp, override exp); `0` = "no change" |
| Pub/Sub **deny** | **union** (override denies are added) — always narrows |
| Pub/Sub **allow** | exact **intersection** — only subjects (and queues) allowed by *both* the base allow and the override allow survive; e.g. `foo.*.bar` ∩ `foo.baz.*` = `foo.baz.bar`. Only a token that is exactly `*` or `>` is a wildcard (`*bar` is a literal). If nothing is in both, the result is **deny all** (`deny: [">"]`), because an empty allow list would mean "allow all". |
| Response `max` / numeric limits | effective = **smaller** (`-1` = unlimited) |
| Response `ttl` | effective = **shorter** |

The base is the permissions **in effect** for the user: the user JWT permissions,
or the account default permissions when the user JWT has none. With a response
permission and no publish allow list, the user can publish only replies, and an
override allow cannot add publish subjects.

A compromised verification service therefore cannot widen any user — worst case it
over-restricts or rejects. Identity fields in the response are ignored entirely.

## 1.9 Security model

- **Fail-closed:** missing system account, transport error, timeout, an unparseable
  response, or a response whose `request_nonce` does not match → connection denied.
- **Verdict authenticity:** trust comes from system-account access control — only a
  client authorized in the system account can subscribe to
  `$SYS.REQ.USER.VERIFY` and publish on the private reply inbox. There is no
  separate signing key. This is safe because (a) the system account is the trust
  boundary and (b) overrides are narrow-only, so even a spoofed verdict cannot
  escalate.
- **Replay defense:** a fresh per-request nonce + a private per-request reply inbox
  + the 2s timeout.
- **Identity preserved:** `/connz`, account events, and audit all continue to show
  the real user nkey. The server's cryptographic chain (operator → account → user)
  remains authoritative.

## 1.10 Writing a verification service (developer guide)

The service is an ordinary NATS client connected to the **system account** that
subscribes to `$SYS.REQ.USER.VERIFY` and replies with a JSON `AuthVerifyResponse`.
It must **echo `request_nonce`**.

```go
import (
    "encoding/json"
    "github.com/nats-io/nats.go"
    "github.com/nats-io/jwt/v2"
)

// nc is connected with system-account credentials.
nc.Subscribe("$SYS.REQ.USER.VERIFY", func(m *nats.Msg) {
    var req struct {
        Nonce    string             `json:"request_nonce"`
        UserNkey string             `json:"user_nkey"`
        Account  string             `json:"account"`
        Connect  jwt.ConnectOptions `json:"connect_opts"`
        // ...client_info, client_tls as needed
    }
    if err := json.Unmarshal(m.Data, &req); err != nil {
        return // no reply -> server fails closed
    }

    resp := map[string]any{"request_nonce": req.Nonce}

    // Example policy: require a second-factor password for this user, and if
    // present, restrict them to their own subtree for the rest of the session.
    if !passwordOK(req.UserNkey, req.Connect.Password) {
        resp["reject"] = true
        resp["reason"] = "second factor failed"
    } else {
        resp["permissions"] = jwt.Permissions{
            Pub: jwt.Permission{Allow: jwt.StringList{"app." + req.UserNkey + ".>"}},
        }
        resp["expires"] = time.Now().Add(15 * time.Minute).Unix() // shorter lease
    }

    b, _ := json.Marshal(resp)
    m.Respond(b)
})
```

Operational notes:
- The service is on the **connect path** for every in-scope JWT connection. Run it
  **highly available** — if it is down, those connections cannot establish (fail
  closed). Keep its handler fast (well under the 2s timeout).
- It needs **no special privileges** beyond being able to receive on the subject
  and reply — it never mints JWTs.

## 1.11 Code map & tests

- `server/authverify/authverify.go` — the narrowing engine (`NarrowPermissions`,
  `NarrowExpiry`, `NarrowCount`) on `jwt` types, with its own exact subject
  intersection; never imports `server`.
- `server/authverify/req.go` — wire types (`AuthVerifyRequest`,
  `AuthVerifyResponse`), constants, `ParseAuthVerifyResponse`.
- `server/auth_verification.go` — config gating (`AuthVerifyInScope`,
  `authVerificationApplies`), the SYS transport (`processAuthVerification`),
  request building (`buildAuthVerifyRequest`, `clientTLSInfo`), and override
  application (`applyAuthVerifyOverride`, `effectiveJWTPermissions`).
- `server/opts.go` — `Options.AuthVerification bool` + the `auth_verification`
  config key.
- `server/auth.go` — one hook in the `processClientOrLeafAuthentication` deferred
  block.
- Tests: `server/authverify/*_test.go` (narrowing engine, escalation regression,
  capstone) and `server/auth_verification_test.go` (scope, config, response parse,
  and operator-mode integration: admit / reject / narrow / account default
  permissions kept / fail-closed-on-timeout).

---

# 2. Request Info Stamping (userinfo on all requests)

## 2.1 What it is

When enabled, the server stamps a **`Nats-Request-Info` header** containing the
requesting client's identity onto **every inbound request message** (any
CLIENT/LEAF publish that carries a reply subject). Downstream subscribers — typical
request/reply services — can then read *who* sent the request (account, user,
name, authenticated JWT tags, kind, language, host, RTT) directly from the
message header, without any application-level convention or extra round-trip.

## 2.2 How this differs from upstream

Upstream NATS already defines this header (`ClientInfoHdr = "Nats-Request-Info"`,
type `ClientInfo`) but only attaches it in **specific** internal paths — most
notably when a message crosses a **service import** between accounts. A plain
intra-account request does **not** carry it upstream.

This fork adds an option that stamps the header on **all** in-scope inbound
requests, so ordinary services in the same account also receive caller identity.

## 2.3 Configuration

A top-level server option, **hot-reloadable**:

```
stamp_request_info: true
```

- Maps to `Options.StampRequestInfo bool`. Default `false`.
- Changing it via config reload (`SIGHUP`) takes effect immediately; the server
  logs `Reloaded: inbound requests will [not ]be stamped with client info`.
- A hot-path atomic mirror (`Server.stampReqInfo`) is kept in sync so the disabled
  path costs only a single atomic load per publish.

## 2.4 Which messages are stamped

A message is stamped only if **all** hold:

- the feature is enabled, and
- the connection is **CLIENT** or **LEAF**, and
- the message has a **reply subject** (i.e. it is a request), and
- the subject is **not** an internal/system subject. These prefixes are skipped
  (they either strip the header or never read it, and skipping avoids per-publish
  marshaling on hot paths): `$JS.`, `$KV.`, `$O.`, `$MQTT.`, `$NRG.`.

Stamping is applied in the inbound publish path (`processInboundClientMsg`,
`server/client.go`) and the leaf inbound path (`server/leafnode.go`).

The server does not stamp and does not remove a client copy of the header on
a message without a reply subject or on a skipped subject. Such a message
keeps the client copy.

### Header block check

When the feature is enabled, the server also checks the header block of each
CLIENT message (not MQTT) and each LEAF message that has headers. The check
applies to all these messages, also to a message without a reply subject and
to a message on a skipped subject. The block must have the strict wire form:

- It starts with `NATS/1.0`. An inline status after it is permitted.
- Each line ends with CRLF. A bare CR or a bare LF is not permitted.
- The only empty line is the last line: the first CRLFCRLF ends the block.
- An inline status has at least three bytes. This is the rule of nats.go
  `v1.54.0` `DecodeHeadersMsg`: when the first line is longer than
  `NATS/1.0`, the remaining bytes after the trim of white space
  (`strings.TrimSpace`) must have a length of 3 or more. Thus
  `NATS/1.0 503` and `NATS/1.0 503 No Responders` pass, and `NATS/1.0 5` and
  `NATS/1.0 ` (one space) fail.

Reason: nats.go ends a header line at a bare LF and stops at the first empty
line. The server strip finds a key only after CRLF, and the server writes its
stamp at the end of the block. Without the check, a client can send the block
`NATS/1.0\nNats-Request-Info: {forged}\r\n\r\n\r\n` with a reply subject. The
strip does not find the forged key, the server stamp comes after the inner
empty line, and nats.go reads only the forged value. A consumer cannot see
this, because `nats.Msg` keeps no raw header bytes. In the strict form, the
strip removes every client copy of the key (`removeHeaderIfPresent` repeats
until it finds no copy), and nats.go reads the server stamp.

Reason for the status rule: nats.go `v1.53.1` and earlier do not check the
status length. For `NATS/1.0 5` they evaluate `"5"[3:]` in the read loop of
the connection. The slice is out of range, and the subscriber process stops
with a panic. A client with a publish grant to a subject that such a process
subscribes to (a service subject, or the inbox of a requester) can stop that
process with one message. The check stops this attack only while
`stamp_request_info` is on, and only for CLIENT and LEAF ingress. Consumers
must also use nats.go `v1.54.0` or later. No header block that nats.go writes
has an inline status, and each status that the server writes in
`server/*.go` has three digits, so the rule rejects no correct block.

Result of a failed check:

- CLIENT: the server does not deliver the message. It sends
  `-ERR 'Message Header Violation'` and closes the connection with the
  upstream close state `MsgHeaderViolation`. nats.go also closes its
  connection when it gets this text.
- LEAF: the server does not deliver the message and logs a rate-limited
  warning:
  `Dropped a leafnode message with a malformed header block - Subject "<subject>" - Reply "<reply>"`.
  The subject and the reply are quoted with `%q`. The format is the
  rate-limit key, so the server writes one line for each account in each
  interval (1 s by default), for the first drop in that interval. The leaf
  connection stays up, because one bad client behind a leaf must not stop the
  link for all the clients behind it. The drop is not in the inbound message
  statistics, because the check runs before the count.

The logs of the check contain no header bytes: the CLIENT error and the LEAF
warning name only the subject (and, for LEAF, the reply). Upstream code can
log a header value before the check: message-trace setup logs the value of
`Nats-Trace-Origin-Account`. This ingress check does not check routes and
gateways: each server that accepts CLIENT or LEAF connections must enable the
feature. The store check (below) also covers a message for a stream that comes
over a route or a gateway. When the feature is disabled, the server does not
check header blocks (upstream behavior).

The check reads the header block that the parser gives to
`processInboundClientMsg` and `processInboundLeafMsg`. Message-trace setup
(`initMsgTrace`, called in `server/parser.go`, code in `server/msgtrace.go`)
runs first and can change the block. With a `Nats-Trace-Origin-Account`
header, or with a `traceparent` header and a sampling miss, it replaces the
`Nats-Trace-Dest` value with `trace disabled` through `setHeader`.
`setHeader` removes the last CRLF of the block and appends the new line and
the final empty line. Thus a block without its final empty line gets the
strict form before the check, and passes. This is not a bypass: the new
block is strict, the stamp strip removes the client copy of
`Nats-Request-Info` that is now merged with the appended line, and nats.go
reads one value, the server stamp. A subject mapping also runs before the
check. A CLIENT close does not stop the parse of the same read buffer; a
later message in that buffer also gets the check and the stamp.

### Store check

When the feature is enabled, the server that stores a message for a stream
also checks its header block, with the same rules
(`requestInfoHeaderBlockValid`). This server is the stream leader, or the only
server of a stream without a Raft group (a single server, or an R1 stream in a
cluster). The check applies to each message that is not sourced, from each
client kind: a CLIENT or LEAF publish, a message over a route or a gateway
from a server with the feature off or without the check, and a message from
an internal client (for example a republish, kind JETSTREAM, or an internal
account publish, kind ACCOUNT).

The check runs before the stream stores the message or proposes it:

- `checkMsgHeadersPreClusteredProposal` (`server/jetstream_batching.go`): a
  clustered publish before its Raft proposal, and each message of an atomic
  batch or a fast batch, for each replica count. An atomic batch commit checks
  each staged message, so the stream stores no message of the batch.
- `processJetStreamMsgWithBatch` (`server/stream.go`), where the stream does
  its other consistency checks, and only for a new message, which has no
  Raft entry sequence and timestamp (`lseq` and `ts` are 0): a stream without
  a Raft group, and a trace-only message.

The check never runs at a Raft apply. An apply has the sequence and the
timestamp of the entry, so the check in `processJetStreamMsgWithBatch` does
not run, also on a follower with the feature on. This is also true after a
scale-down to R1: the server removes the Raft node, and the apply loop can
still apply an entry that the old leader acknowledged. That entry is stored
also when the old leader had the feature off and this server has it on.

The check reads the block that the stream gets, before the server removes its
own `Nats-Request-Info` copy. Before the check, `processInboundJetStreamMsg`
removes an inline status (`removeHeaderStatusIfPresent`). Thus the block
`NATS/1.0 5\r\n\r\n` becomes no header block and is stored without one, and
the N1 frame becomes `NATS/1.0\r\n\r\n\r\n`, which the check rejects.

These messages are not checked (`sourced`): the mirror and source ingest of the
stream, and the messages that the store makes (subject delete markers and
scheduled messages). A reject of mirror or source ingest only moves the stop
from the leaf link to the ingest of the stream, and a reject of a scheduled
message can stop its schedule. The restart recovery of a partial atomic batch
write also stores without the check, because the staged messages carry the
batch headers. They got the check at their commit only if the feature was on
at that commit. A batch that a server committed while the feature was off,
and that the server recovers after a restart with the feature on, is stored
without the check.

Result of a failed check:

- A publish with a reply subject (on a stream without `NoAck`) gets a
  `PubAck` with the error `JSBadRequestErr`: code 400, error code 10003,
  description `bad request`. This is an upstream error. The fork adds no error
  code, so the upstream error code table does not change. A fast batch gets
  the error as the `PubAck` of its first message or in a `BatchFlowErr` flow
  message.
- A publish without a reply subject is dropped.
- For each reject, the server logs a rate-limited warning:
  `Rejected a message with a malformed header block for stream '<account> > <stream>'`.
  The statement is the rate-limit key, so the server writes one line for
  each stream in each interval (1 s by default). The warning contains no
  subject and no header bytes.
- The message trace event of a traced message gets the error.

Header blocks that the server writes pass the check. `genHeader` and
`http.Header.Write` end each line with CRLF and replace a CR or an LF in a
value with a space. `setHeader` and `client.setHeader` keep a strict block
strict with each value that the server sets. The fixed blocks (status, flow
control, heartbeat, subject delete marker, direct get, republish, and stream
headers) are strict. One upstream builder was not strict: the MQTT request
header block (section 13). The store check needs that correction. Without
it, the check rejects each new MQTT session record, and an MQTT client with a
session cannot connect.

One server writer copies a client value into a header line without a check:
an MQTT retained record writes the CONNECT user name in `Nmqtt-RSrc`
(upstream). MQTT accepts a user name with a CR or an LF. Such a user name makes
a block that is not strict, so the store check rejects that retained message
while stamping is on, and MQTT logs that it cannot store the retained
message. A user name with a CRLF pair adds a strict header line to the record.
This is an upstream defect, and the fork does not correct it.

When the feature is disabled, the store check does nothing (upstream
behavior).

### Blocks that a stream can still hold

A stream can still hold a block that is not strict. Such a block can come
from:

- data that a stream stored before the store check was on;
- a message that a stream leader with the feature off stored;
- a stream snapshot restore (`$JS.API.STREAM.RESTORE` carries the stored
  messages in its payload, so no check reads their header blocks);
- the mirror or source ingest of such a block, and a scheduled message that
  the store makes from such a block;
- an MQTT session record that a server stored before the correction of
  section 13.

When each stream leader runs the store check with the feature on, a route or a
gateway can no longer add such a block. A server with the check drops the
LEAF delivery of such a message. For a mirror, a source, or an ordered
consumer (for example a legacy nats.go KV watch) across a leaf link, the
drop causes a sequence gap. The reader then creates its consumer again at
the same stream sequence, the server drops the message again, and the loop
does not end. The reader stops at that message, and later messages do not
arrive.

- Find the message: read the LEAF warning. The reply of a JetStream delivery
  names the stream, the consumer, and the stream sequence:
  `$JS.ACK.<stream>.<consumer>.<count>.<stream sequence>...`, or
  `$JS.ACK.<domain>.<account hash>.<stream>.<consumer>.<count>.<stream sequence>...`.
- Recover: at the origin, delete that message, or purge the stream up to
  the next sequence. Another option is to turn the feature off on the
  receiving server.
- Prevent: run the fixed fork with the feature on all servers before data
  enters the streams. The store check needs the feature on each server that
  can lead a stream. For MQTT, see the upgrade order in section 13. Before
  you turn the check on, examine the streams that cross a leaf link, also the
  mirrors and sources of such streams.

## 2.5 What gets stamped

The header value is a JSON `ClientInfo` (subset of the upstream type) carrying a
**trimmed identity set** — enough to identify the requestor, without the heavier
detailed fields (JWT, issuer key, server/cluster, start time):

| JSON field | Meaning |
|---|---|
| `acc` | account name / public key |
| `user` | verified JWT subject, or the raw auth user for another authentication mode |
| `name` | client `name` from CONNECT |
| `tags` | authenticated user JWT tags (omitted for non-JWT users or an empty tag list) |
| `kind` | connection kind (e.g. `Client`, `Leafnode`) |
| `client_type` | client type (e.g. `nats`, `mqtt`, `websocket`) |
| `lang` | client language |
| `host` | client host/IP |
| `rtt` | measured RTT |
| `reply` | (LEAF only) preserved original reply subject when forwarded across a leaf — see §2.6 |

Header name: **`Nats-Request-Info`** (`ClientInfoHdr`).

For an authenticated JWT connection, `getRawAuthUser` returns the verified
subject before optional CONNECT `nkey` or `user` fields. Request headers,
connect and disconnect events, CONNZ results and user filters, and the
`client` information of grant and verification hook requests use it. The log
labels `getAuthUser` and `getAuthUserLabel` (the connection log suffix and the
subscription removal notices) take the same first case. This rule is always on
for an operator-mode server; it does not depend on `stamp_request_info`. It
adds no wire field.

The auth callout request `client_info.user`, both auth error events, and the
authentication error log use `getConnectRawAuthUser` and `getConnectAuthUser`.
While an auth callout decides the identity, they keep the upstream order, with
CONNECT `nkey` and `user` before the JWT subject. A callout decides the
identity when the connection's account has external authorization and the
user is not one of its auth users (`calloutDecidesIdentity`, the same
condition that calls the callout). A sentinel JWT connection, including
`default_sentinel`, therefore reports the CONNECT user, not the sentinel
subject. In every other case these surfaces report like `getRawAuthUser`: a
grant or verification hook that rejects a verified JWT user reports the
verified subject, because no callout decides that identity. Static nkey,
username, token, and auth-callout names keep their existing fallbacks. An
auth callout clears the original JWT before it installs its user.

## 2.6 LEAF handling (forwarded requests)

For LEAF inbound messages that already carry a forwarded `Nats-Request-Info` header
from a remote domain:

- The **identity** portion is **replaced** with this leaf connection's own info —
  forwarded identity is not trusted (consistent with the server's existing
  service-import security model). This includes `tags`: the receiving server
  stamps the authenticated leaf transport JWT tags, not the original caller's
  forwarded tags.
- The **`reply`** field of the forwarded header is **preserved**, because chained
  service-import response routing across the leaf boundary depends on it.

The replacement removes every forwarded copy only because the header block
check (section 2.4) runs first. Without that check (fork `v2.15.3-amnesh.4`
and earlier), a copy after a bare LF stayed beside the server stamp, and a
copy before an inner empty line hid the server stamp from nats.go.

## 2.7 Performance & caching

- **Disabled (default):** one atomic load, then return. No allocation.
- **Header block check:** when enabled, one byte scan of the header block for
  each CLIENT or LEAF message that has headers. No allocation.
- **Enabled:** the marshaled header for a connection is **cached** on the client
  (`client.ciStampHdr`) and reused across requests, since the identity is stable
  for the life of the connection. The cache is invalidated when identity-affecting
  state changes (account swap on reload, re-register, close).
- Non-empty JWT tags increase each stamped request header by their JSON-encoded
  size. They remain part of the cached JSON, so this does not add per-request
  claim decoding or marshaling after the cache is populated.
- The per-request `reply` value (LEAF) is spliced in for that one request only and
  is deliberately excluded from the cache so it does not defeat caching.

## 2.8 Consuming the header (developer guide)

Any responder can read the caller's identity from the request message header:

```go
import (
    "encoding/json"
    "github.com/nats-io/nats.go"
)

nc.Subscribe("orders.create", func(m *nats.Msg) {
    if raw := m.Header.Get("Nats-Request-Info"); raw != "" {
        var ci struct {
            Account    string `json:"acc"`
            User       string `json:"user"`
            Name       string `json:"name"`
            Tags       []string `json:"tags"`
            Kind       string `json:"kind"`
            ClientType string `json:"client_type"`
            Lang       string `json:"lang"`
            Host       string `json:"host"`
        }
        if json.Unmarshal([]byte(raw), &ci) == nil {
            // authorize / audit / route using ci.Account, ci.User, ...
        }
    }
    // ... handle request, m.Respond(...)
})
```

> The server stamps the header on the wire; subscribers must opt in to read it.
> The header is informational identity provided by the trusted server (not the
> client), so it is safe to use for auditing and account-aware routing.

Trust the header only under these conditions:

- The message is a request that a CLIENT or LEAF connection published to a
  subject that is not skipped, so it has a reply subject. Require the reply
  subject and exactly one header value (`m.Header.Values`), not only
  `m.Header.Get`. A message without a reply subject keeps a client copy.
- Each server that accepts the publish runs with `stamp_request_info` and
  with the header block check (section 2.4). A server without the check
  passes a client copy that nats.go reads as the only value.
- Do not trust the header on a message that the server delivers from stored
  or internal state, for example a JetStream push delivery: its reply subject
  (`$JS.ACK...`) does not prove a server stamp. A stream removes only the
  copies after CRLF, and a stream source or mirror can copy a block that a
  server without the check accepted.

## 2.9 Code map & tests

- `server/soo-changes.go` — `stampRequestInfoHeaderIfNeeded` (hot path + cache),
  `getClientInfoForRequest`, `skipRequestInfoStamp` + the skip-prefix list.
  `requestInfoHeaderBlockValid`, `malformedRequestInfoHeader`, and
  `rejectMalformedRequestInfoHeader` are the header block check (section 2.4).
  `storeRejectsHeaderBlock` (the decision) and `rejectStoreHeaderBlock` (the
  warning and the `PubAck` error) are the store check.
  `getConnectRawAuthUser` and `getConnectAuthUser` serve the auth callout
  request, auth error events, and the authentication error log; they keep the
  upstream name order only while `calloutDecidesIdentity` is true.
- `server/client.go` — call sites in `processInboundClientMsg` (the header
  block check first, then the stamp); the
  `client.ciStampHdr` cache field and its invalidation points. `getRawAuthUser`
  selects the verified JWT subject for stamps, events, and monitoring;
  `getAuthUser` and `getAuthUserLabel` do the same for log labels.
- `server/leafnode.go` — leaf inbound call sites (the header block check first,
  then the stamp).
- `server/jetstream_batching.go` — the store check call in
  `checkMsgHeadersPreClusteredProposal` (clustered publish, atomic and fast
  batches).
- `server/stream.go` — the store check call in `processJetStreamMsgWithBatch`
  (a new message on a stream without a Raft group, and a trace-only message;
  never a Raft apply).
- `server/server.go` — the `Server.stampReqInfo` atomic mirror, set at startup and
  on reload.
- `server/opts.go` — `Options.StampRequestInfo` + the `stamp_request_info` key.
- `server/reload.go` — `stampRequestInfoReload` (hot-reload apply).
- Tests: `server/soo-changes_test.go`, `server/soo_identity_test.go`, and
  `test/soo-changes_test.go`. `TestClientInfoForRequestVerifiedJWTIdentity`
  covers static JWT and grant JWT connections over CLIENT and LEAF protocols.
  It checks request headers, system events, and CONNZ results and filters with
  optional CONNECT identity fields present. `TestAuthCalloutSentinelKeepsConnectUser`
  checks that a sentinel connection's callout request, auth error events, and
  authentication error log name the CONNECT user.
  `TestAuthHookRejectionNamesVerifiedSubject` checks that a grant or
  verification hook rejection names the verified subject on the same three
  surfaces. `TestAuthUserLogLabelsPreferVerifiedJWT`
  and the connection log label check in the identity test cover log labels.
- Header block check tests: `server/soo_header_block_test.go`
  (`TestRequestInfoHeaderBlockValid`, `TestRequestInfoHeaderBlockCheckScope`,
  `TestStampRequestInfoRemovesEveryClientCopy`) and
  `test/soo_header_block_test.go`. The black-box tests send raw frames that
  nats.go cannot write: the N1 frame, a bare LF in the status line, a bare LF
  before the key, an inner empty line, and a block without its final empty
  line. `TestStampRequestInfoRejectsMalformedClientHeader` (raw CLIENT:
  `-ERR`, close, no delivery), `TestStampRequestInfoDropsMalformedLeafHeader`
  (raw LEAF: no delivery, the link stays up),
  `TestStampRequestInfoStripsEveryClientCopy` (positive control: one server
  stamp), and `TestStampRequestInfoDisabledKeepsHeaderBlock` (feature off:
  upstream behavior). `TestStampRequestInfoRejectsShortStatusHeader` sends
  `NATS/1.0 5` and `NATS/1.0 ` through a raw CLIENT and a raw LEAF, with a
  raw subscriber as the observer (a nats.go `v1.53.1` subscriber panics on
  these blocks), and `NATS/1.0 503 No Responders` as the positive control.
  `TestStampRequestInfoRejectsMalformedStreamHeader` publishes the N1 frame
  without a reply subject to a stream subject and to a `$KV.` subject (`-ERR`,
  close, no stored message). `TestStampRequestInfoTraceHeaderBlock` sends
  `traceparent` blocks with and without the final empty line, and a block
  that message-trace setup changes to the strict form (one server stamp).
  `TestRequestInfoHeaderBlockCheckScope` also has rows for each skipped
  subject prefix, with and without a reply subject.
  `TestStampRequestInfoLeafDropWarningNamesSubject` checks the LEAF warning
  text and its rate-limit key.
- Store check tests: `TestRequestInfoStoreHeaderBlockDecision` (the decision
  for each combination of stamping, sourced, and block) and
  `TestRequestInfoStoreHeaderBlockWarning` (the error, the warning text, and
  its rate-limit key) in `server/soo_header_block_test.go`.
  `server/jetstream_soo_store_header_test.go`:
  `TestJetStreamStampRequestInfoStoreRejectsLooseHeaderBlock` (a direct store
  call, an internal ACCOUNT client with and without a reply, an atomic batch
  commit, and a fast batch, with stamping on and off),
  `TestJetStreamStampRequestInfoStoreKeepsServerHeaderBlocks` (KV and object
  store operations, counters, TTL and subject delete markers, schedules,
  atomic and fast batches, republish, mirror, and source store strict blocks
  with stamping on),
  `TestJetStreamStampRequestInfoStoreSkipsRaftApplyForm` (a call with the
  sequence and timestamp of a Raft entry stores a loose block, and a call
  with both 0 rejects it), and
  `TestJetStreamStampRequestInfoStoreSkipsMirrorAndSourceIngest` (loose blocks
  stored with stamping off, then a reload to stamping on: a mirror and a
  source store them, and the stream that gets the republish of the mirror
  rejects them). `server/jetstream_cluster_soo_store_header_test.go`:
  `TestJetStreamClusterStampRequestInfoStoreHeaderBlock` (a two-server
  cluster: a client of the server with stamping off publishes to R1 and R2
  streams with their leader on the server with stamping on, and R1 and R2
  mirrors and sources on that server ingest a loose block). The MQTT test is
  in section 13.

---

# 3. Custom Listeners/Dialers (summary)

Commit `6f42d0a4f` adds the ability to inject **custom `net.Listener`s and
dialers** (with a configurable `dialTimeout` and WebSocket TLS handling) into the
server programmatically via `Options`. This lets embedders run NATS over custom
transports (e.g. in-memory pipes, alternative network stacks, or test harnesses)
instead of only OS TCP sockets. It is configured in code (not in the config file).
See commit `6f42d0a4f` for the exact `Options` fields and plumbing.

---

# 4. Scoped Resource Permission Groups

Scoped user signing keys may carry a server extension at
`nats.signing_keys[].template.xpermissions`. The extension adds the complete
JetStream subject bundle for named resources while the typed JWT template keeps
ordinary `pub`, `sub`, `resp`, limits, bearer/proxy flags, and connection types.

```json
{
  "xpermissions": {
    "kv": [{"op":"rw", "bucket":"{{tag(kv)}}"}],
    "obj": [{"op":"ro", "bucket":"assets", "domain":"hub"}],
    "stream": [{"op":"admin", "stream":"orders"}],
    "consumer": [{"op":"ro", "stream":"orders", "consumer":"{{name()}}"}],
    "jsinfo": true
  }
}
```

`kv` and `obj` accept `ro`, `rw`, and `admin`; `stream` and `consumer`
accept `ro` and `admin`. Every supplied group is a nonempty array. `domain` is
optional per entry. `jsinfo: true` adds the three local account-info subjects;
`false` is a valid no-op. Resource selectors support the ordinary scoped
template value operations and Cartesian expansion. Only the complete literal
selector `*` is a wildcard; domains and resolved values cannot be wildcards.

The extension is parsed only from the verified raw account JWT. It is strictly
validated, correlated with the typed scoped signer, and installed atomically
with the typed scope. Unknown or duplicate fields, wrong types, empty groups,
bad operations, invalid selectors, and missing resolved selectors fail closed.
Generated subjects are additive allows, standard denies still win, and each
permission list retains the 4096 generated-subject budget. Account updates that
change only `xpermissions` disconnect users of the affected signer.

Legacy whole-entry resource calls such as `{{kvrw(tag(kv))}}` are rejected in
all four standard subject lists during account claim ingestion. Migrate each
call to its matching group and operation before upgrading. Mixed-version
clusters are unsupported during migration: older servers ignore the raw
extension, while upgraded servers reject the legacy calls.

Implementation and tests:

- `server/auth_xpermissions.go`: strict signed-payload parser and validation.
- `server/auth_xpermissions_compile.go`: selector expansion and subject bundles.
- `server/accounts.go` and `server/server.go`: atomic account lifecycle.
- `server/auth.go` and `server/auth_callout.go`: scoped authentication paths.
- `server/auth_xpermissions*_test.go`, `server/jwt_test.go`, and
  `server/auth_callout_test.go`: schema, compilation, lifecycle, and real-client
  coverage.

```sh
go test -run '^TestJWTXPermissions' ./server -count=1
```

The complete design and migration mapping are in
`docs/superpowers/specs/2026-09-18-xpermissions-grants-design.md`.

---

# 5. Leafnode scaling (isolated hubs with 60k+ leaves)

## 5.1 What it is

Performance changes that let one hub serve 60k+ leafnode connections in one
account when leaf interest is isolated (`leafnodes { isolate: true }`, or a
remote that sets `request_isolation`). There is no config key. The interest that
the hub sends to each leaf is the same as upstream.

Upstream cost grows with the number of leaves N for each connect, so a full
start costs O(N²), under the server lock in part. At about 6k leaves the hub
used all CPU, handshakes timed out, leaves connected again, and the load grew
(830k connects in 12 minutes in the reported case).

Upstream v2.15.1 (`46fa24964`, issue #8705) filters leaf interest out of the
snapshot of an isolated hub-side leaf with `Sublist.Filter`. That removes the
permission checks, but each connect still walks all account subscriptions, and
the other costs below stay. With the setup in 5.4, v2.15.1 connects 10k leaves
in 56 s with `/varz` blocked for most of that time, and only 5,031 of 60k. The
fork keeps its snapshot path; `Sublist.Filter` stays in the tree but the fork
does not use it. v2.15.1 also removed the post-loop isolation check, so an
isolated spoke connection sends the interest of its downstream leaves in its
snapshot. The fork keeps that check, before `canSubscribe`. Upstream PR #8749
fixes this in the spoke branch; when it is released, the fork can take it.
As in upstream, the snapshot of an isolated leaf does not load the leaf's
delivery deny filter (`c.mperms`): the leaf's own subscriptions load it in
`processLeafSub` when they arrive, which is after the snapshot.

## 5.2 Changes

| Upstream cost | Change |
|---|---|
| `initLeafNodeSmapAndSendSubs` walked **all** account subscriptions for each new leaf, ran `canSubscribe` and built a debug string for each, and only then dropped leaf interest for an isolated leaf. | For an isolated hub-side leaf, the snapshot uses `Sublist.nonLeafSubs`: a set of the non-leaf subscriptions that the sublist fills with one walk on first use and then keeps in `Insert` and `remove`, under the sublist write lock. Leaf interest is "client kind `LEAF` or `sub.leaf`" (routed from a leaf on another server), the same test as upstream. The isolation check runs before `canSubscribe`. |
| `updateLeafNodesEx` walked all leaves for each leaf `LS+`/`LS-` and locked each one, only to skip the isolated ones. | Each account keeps `sharedLeafs`, the leaves in `lleafs` that are not isolated, in the two places that change `lleafs` (`addClient`, `removeLeafNode`). When it is empty, leaf interest returns early. The isolation flag has an atomic copy (`leaf.isolatedHint`); isolation can only be turned on. A leaf that requests isolation in its CONNECT leaves the set. |
| `addLeafNodeConnection` searched for a previous connection from the same remote by walking all leaves under the server lock. | An index by (remote server, remote cluster, account, remote account) under the server lock, next to `s.leafs`. Each candidate is checked with the original condition. If a remote changes these fields after they were captured (an INFO to the accept side, or a second CONNECT, possibly into another account; both abnormal), the connection is marked before the change, the server logs a notice, and the check uses the full walk while that connection is open. |
| `client.Debugf` and `client.Tracef` formatted the message before the level check. | They check the level first, as `Server.Debugf`/`Tracef` do. |

## 5.3 Optional: coalesced source and mirror check

Upstream calls `checkInternalSyncConsumers` on the readloop of every leafnode
connect (hub side) and of every INFO that a solicited leafnode receives. It
locks every stream of the account that has a mirror or sources, and for each
disconnected or stale source it cancels the backoff and schedules a new setup.
For a source with a request in progress, it wakes the wait (section 14).
A connect therefore costs O(sourcing streams + their sources). With one hub
stream that sources from every leaf, a start of N leaves costs O(N²) and holds
that stream's lock on the readloops.

```
leafnodes {
  # Off when absent or 0 (upstream: a check on every connect).
  sync_consumers_check_interval: "250ms"
}
```

When set, the check runs on its own goroutine, at most once per interval for
each account. The first trigger after an idle period runs it at once; a
trigger during a check or the wait after it causes one more check after the
wait. So every connect is still followed by a check that starts after it, at
most one interval after the check that is running ends. Shutdown drops pending
checks. The setup that a check schedules still waits for the
upstream 2s request throttle and jitter. Streams are not filtered by domain,
because a leaf can be the path to other domains. The value is read at each
trigger and during each wait (at least every 100ms), so a config reload can
change it or turn it off. When it is turned off, new triggers check
synchronously as upstream; a goroutine that runs finishes its pending check.
A negative value, or an integer (seconds) that does not fit, is a config error.

## 5.4 Measured

Hub with `isolate: true`, compression off, leaf user with permissions, 16 cores,
raw leafnode connections with 16 subscriptions each from the same machine:

| Case | Upstream | Fork |
|---|---|---|
| 10k leaves at 1000/s | 1,706 connected, 8,294 timed out, 135 CPU-s, 2.5 GB | all connected in 10.9 s, 23 CPU-s, 0.7 GB |
| 60k leaves at 2000/s | — | all connected in 30.1 s, 55 CPU-s, 4.0 GB, no errors |
| 60k leaves at 10000/s | — | all connected in 6.1 s, 42 CPU-s, 4.4 GB, no errors |
| Snapshot for one isolated leaf, 900k leaf subscriptions | 125–133 ms | 7 µs (first use: one walk, about 125 ms) |

## 5.5 Code map & tests

- `server/leafnode_isolation.go` — `isLeafInterest`, `Sublist.nonLeafSubs` and
  its `Insert`/`remove` hooks, `client.setLeafIsolated`,
  and the `sharedLeafs` helpers.
- `server/leafnode_dupindex.go` — duplicate-check index and fallback.
- `server/leafnode_synccheck.go` — `syncCheckCoalescer` and
  `scheduleInternalSyncConsumersCheck`; config key in `server/opts.go`
  (`LeafNodeOpts.SyncConsumersCheckInterval`), reload allow-list entry in
  `server/reload.go`, `Account.syncCheck`.
- Hooks: `server/leafnode.go` (snapshot, `updateLeafNodesEx`,
  `addLeafNodeConnection`, `removeLeafNodeConnection`, isolation and identity
  writes), `server/sublist.go` (`Insert`, `remove`), `server/accounts.go`
  (`addClient`, `removeLeafNode`), `server/client.go` (`Debugf`, `Tracef`,
  account change in `registerWithAccount`), `server/server.go` (index fields).
- Tests: `server/leafnode_isolation_test.go` (snapshot with local, routed and
  leaf interest in a hub cluster; tracking across reload; requested isolation;
  randomized set consistency; isolated spoke snapshot; benchmark) and
  `server/leafnode_dupindex_test.go` (randomized index against the upstream walk;
  fallback on identity and account change, and its end),
  `server/leafnode_synccheck_test.go` (config, reload, coalescer bounds and
  ordering, shutdown) and `server/jetstream_leafnode_synccheck_test.go` (a leaf
  connect cancels a long source backoff, with and without the option). Upstream tests `TestLeafNodeIsolatedLeafSubjectPropagation*`,
  `TestLeafNodeLoopDetectedDueToReconnect` and
  `TestLeafNodeHubRejectDuplicateRemotes` cover the unchanged behavior.

---

# 6. Leafnode `SignatureCB` kept across reload

## 6.1 What it is

An embedder can set `RemoteLeafOpts.SignatureCB` to sign the hub's nonce for a
leafnode remote. Upstream compares each existing remote at a reload with
`reflect.DeepEqual`, and a non-nil func value is never equal to anything, not
even to itself. So with a `SignatureCB`, every `ReloadOptions` and every config
file reload (the new remote has no callback) failed with
`field "SignatureCB": old=..., new=...`. The fork ignores the field in that
comparison, like `TLSConfig`.

## 6.2 Which callback is used after a reload

**The callback from before the reload.** A running remote keeps its original
`*RemoteLeafOpts` (`leafNodeCfg.RemoteLeafOpts`), and a reload copies only
`TLSConfig`, `TLSHandshakeFirst`, `Compression` and `Disabled` into it. The
connect path reads `c.leaf.remote.SignatureCB`, so the old callback signs all
later reconnects. The new value is only stored in the new options, so
`s.getOpts().LeafNode.Remotes[i].SignatureCB` can differ from the callback in
use. A new callback takes effect only for a remote that the reload adds (for
example a remote with other URLs), or after a restart.

Note: `Options.Clone` does not copy `LeafNode.Remotes`; the clone shares the
`*RemoteLeafOpts` of the running server. Setting `SignatureCB` on such a shared
remote changes the running remote directly, without a reload and without a
lock. Build a new `RemoteLeafOpts` for `ReloadOptions` instead.

## 6.3 Code map & tests

- `server/reload.go`: `"SignatureCB"` in the per-remote ignore list of
  `getLeafNodeOptionsChanges`.
- `server/leafnode_sigcb_reload_test.go`: `TestLeafNodeSignatureCBReload`
  reloads with a different func, the same func and no func. Each reload
  succeeds, the leaf stays connected on the same connection, and after the hub
  closes the connection, the old callback signs the reconnect. A last case
  keeps the running `*RemoteLeafOpts` and adds a second remote with its own
  callback in the same reload; both connect.

---

# 7. `Account.SetJetStreamLimits`

## 7.1 What it is

`Account.jsLimits` is what `jetstream` in an account block of a config file
sets. It is unexported, so an embedder that builds `Options.Accounts` in code
could not set it. `EnableJetStream` and `UpdateJetStreamLimits` need a
registered account and running JetStream, and they do not survive a reload: at
`ReloadOptions` the server copies `jsLimits` from the new account objects
(`shallowCopy`), and `configJetStream` calls `DisableJetStream` for an account
without limits. Memory streams lose their messages.

```go
// SetJetStreamLimits records JetStream limits on an account that is given to
// the server in Options.Accounts.
func (a *Account) SetJetStreamLimits(limits map[string]JetStreamAccountLimits)
```

- Call it on the `*Account` before the server starts, or before the options go
  to `ReloadOptions`. It does not enable JetStream on a running account.
- The limits apply only when server-wide JetStream is enabled.
- Accounts built new for each `ReloadOptions` must get the limits again.
  `Options.Clone` copies them.
- `nil` means no JetStream for the account. An empty map means the default
  (dynamic) limits, as `EnableJetStream` and `jetstream: enabled` do. The map is
  copied.

## 7.2 Code map & tests

- `server/account_jslimits.go`: `Account.SetJetStreamLimits`, a wrapper of
  `assignJetStreamLimits`.
- `server/jetstream_account_jslimits_test.go`:
  `TestJetStreamAccountSetJetStreamLimitsReload` (new account objects with the
  limits, and a clone, keep JetStream across `ReloadOptions` and a memory stream
  keeps its messages; without limits JetStream is disabled) and
  `TestJetStreamAccountSetJetStreamLimitsValues` (nil, empty map, copy).

---

# Historical: Permission Template Macros (superseded)

The following section documents the removed whole-entry implementation for
release archaeology only. It is not accepted by current servers.

## 4.1 What it is

Scoped signing key templates (`UserScope.Template` in an account JWT) get a
set of new template operations, called macros. Each one expands a single
template entry into the full set of subjects a client needs for **one
JetStream resource**: a KV bucket, an Object Store bucket, a plain stream, one
consumer of a stream, or the account's JetStream discovery API. Design spec:
`docs/superpowers/specs/2026-09-17-permission-template-macros-v2-design.md`.

| Macro | Resource | Grants |
|---|---|---|
| `{{kvro(ARG)}}` | KV bucket | read: get, watch, history, keys, status |
| `{{kvrw(ARG)}}` | KV bucket | read + put, create, update, delete, purge, purge deletes |
| `{{kvadmin(ARG)}}` | KV bucket | read + write + create, update, delete the bucket |
| `{{objro(ARG)}}` | Object Store bucket | read: get, get info, list, watch, status |
| `{{objrw(ARG)}}` | Object Store bucket | read + put, delete, update meta |
| `{{objadmin(ARG)}}` | Object Store bucket | read + write + create, update, seal, delete the bucket |
| `{{jsread(ARG)}}` | stream | consume with any consumer: create, info, pull, ack, delete |
| `{{jsadmin(ARG)}}` | stream | read + purge + create, update, delete, message delete, snapshot, restore |
| `{{jsinfo()}}` | account | account info, stream names, stream list |
| `{{jsconsumer(STREAM, CONSUMER)}}` | one consumer | bind to that consumer: info, pull, ack |
| `{{jsconsumeradmin(STREAM, CONSUMER)}}` | one consumer | consumer use + create, pause, unpin, reset, delete that consumer |

`ARG` names the resource(s). It is any value-producing template operation the
server already supports, or a literal name:

| Argument | Resources |
|---|---|
| `tag(key)` | one per user JWT tag `key:<name>` |
| `account-tag(key)` | one per account JWT tag `key:<name>` |
| `name()`, `subject()`, `account-name()`, `account-subject()` | the user name / user nkey / account name / account nkey |
| `orders` (literal) | exactly that resource |

Macro names and tag keys are matched case-insensitively. Tag **values** are
used as they appear in the JWT. `nsc` and the `jwt` library lowercase tags
when they add them, so a resource with an uppercase name (streams are
case-sensitive) can only be named by a literal argument.

**Motivation.** Without macros, a template needs a dozen entries per bucket
(`$KV.{{tag(kv)}}.>`, `$JS.API.STREAM.INFO.KV_{{tag(kv)}}`, ...), and a user
JWT that lists buckets directly grows to 10 KB and more at 40 buckets. With
macros the account JWT carries one entry per resource role, and the user JWT
carries only tags:

```jsonc
// Account JWT: signing key scope template
"template": {
  "pub": { "allow": ["{{kvrw(tag(kv))}}", "{{kvro(tag(kvr))}}", "{{jsread(tag(js))}}", "{{jsinfo()}}"] },
  "sub": { "allow": ["_INBOX.>", "{{kvrw(tag(kv))}}", "{{kvro(tag(kvr))}}"] }
}
// User JWT (signed by that scoped key): tags only, no permissions
"tags": ["kv:orders", "kv:carts", "kvr:catalog", "js:audit"]
```

The server expands this at connect time. The user's nkey and JWT signature
chain are untouched: identity is verified as before, only the *way
permissions are written* in the account JWT changes.

## 4.2 Rules

- A macro must be the **whole entry**. `foo.{{kvrw(tag(kv))}}` or two macros in
  one entry is an error, and the user's authentication fails (same as for any
  invalid template today).
- Bucket macros work in all four lists. In `pub.allow` / `pub.deny` they emit
  the API subjects of §4.3; in `sub.allow` / `sub.deny` they emit only the
  bucket's data subject (`$KV.<b>.>` or `$O.<b>.>`).
- Stream macros, consumer macros and `jsinfo` are only valid in publish lists.
  A stream has no derivable data subject, so using them in a subscribe list is
  an error.
- `jsinfo` takes no argument: `{{jsinfo()}}`.
- A macro takes a fixed number of **positional** arguments, separated by
  commas: one for the bucket and stream macros, zero for `jsinfo`, two for the
  consumer macros (stream first, consumer second). A wrong number of arguments
  is an error. Whitespace around every part is trimmed, so
  `{{ jsconsumer( tag(js) , workers ) }}` is the same entry as
  `{{jsconsumer(tag(js),workers)}}`. Commas inside a value operation do not
  split the list, because the split is made at parenthesis depth zero.
- Each argument resolves to a **list** of values. The macro emits one subject
  set per element of the **cartesian product** of all lists, with the first
  argument as the outer loop. So `{{jsconsumer(tag(s), tag(c))}}` with tags
  `s:a`, `s:b`, `c:1`, `c:2` emits four sets, in the order (a,1), (a,2),
  (b,1), (b,2).
- Every macro also takes one optional **trailing named argument**,
  `domain=ARG`, which points the macro at a JetStream domain the client
  reaches through a leaf node: `{{kvrw(tag(kv), domain=hub)}}`. `ARG` is a
  literal or a value operation, exactly like a positional argument, so
  `domain=tag(dom)` gives one subject set per domain tag. The domain is the
  **innermost** loop of the cartesian product, so
  `{{jsread(tag(s), domain=tag(d))}}` with tags `s:a`, `s:b`, `d:1`, `d:2`
  emits the sets (a,1), (a,2), (b,1), (b,2). A domain value follows the same
  name rule and the same allow/deny rules as a resource name, so a user
  without the domain tag fails closed. `domain=` must follow every positional
  argument, may appear once, may not be empty, and is the only named argument
  the grammar defines: any other named key, a repeated or empty `domain=`, or
  a positional argument after a named one, is an error.
- Entries that are not macros pass through untouched and are then processed by
  the upstream template engine, so macros mix freely with `{{tag(x)}}` style
  entries and plain subjects.
- An argument that resolves to **no value** (the user has no matching tag) or
  to an **invalid name** emits nothing in an **allow** list and is an
  **error** in a **deny** list. This mirrors upstream's handling of unresolved
  tags. A valid name is one or more of `A-Z a-z 0-9 _ -`, the rule the
  official clients enforce when they create a bucket. As upstream, an allow
  list that was non-empty and becomes empty after expansion gets a
  compensating `deny >`, so a user without tags fails closed.
- The total number of subjects per list is capped by the existing
  `maxPermTemplateSubjectExpansions` (4096). With 16 subjects per read-only
  resource that is 256 resources per user, 227 for read/write, 163 for admin,
  585 for `jsconsumer` and 292 for `jsconsumeradmin`.
- The literal `*` is accepted as a positional argument and means every
  resource of that kind: `{{jsread(*)}}`, `{{kvrw(*)}}`,
  `{{jsconsumer(orders, *)}}`. It is a template author's decision, so `*`
  from a tag or from any other value operation stays an invalid value, and
  `*` is not accepted for `domain=`. See §4.3 for what a bucket wildcard
  grants.
- Unknown macro names such as `{{kvxx(...)}}` are rejected by the upstream
  "template operation is not defined" path, exactly as today.

## 4.3 What a macro expands to

`{stream}` is `KV_<b>`, `OBJ_<b>`, or the stream name. `{consumer}` is the
consumer name of a consumer macro. Levels are cumulative.

**read** (16 subjects), every macro except `jsinfo`:

```text
$JS.API.STREAM.INFO.{stream}
$JS.API.STREAM.MSG.GET.{stream}          # non-direct get (legacy Object Store, buckets without allow_direct)
$JS.API.DIRECT.GET.{stream}
$JS.API.DIRECT.GET.{stream}.>
$JS.API.CONSUMER.CREATE.{stream}         # legacy ephemeral create
$JS.API.CONSUMER.CREATE.{stream}.>       # named create, with or without filter subject
$JS.API.CONSUMER.DURABLE.CREATE.{stream}.>
$JS.API.CONSUMER.INFO.{stream}.>
$JS.API.CONSUMER.NAMES.{stream}
$JS.API.CONSUMER.LIST.{stream}
$JS.API.CONSUMER.DELETE.{stream}.>
$JS.API.CONSUMER.MSG.NEXT.{stream}.>     # pull consumers
$JS.ACK.{stream}.*.*.*.*.*.*             # acks, v1 reply format (9 tokens)
$JS.ACK.*.*.{stream}.*.*.*.*.*.>         # acks, v2 reply format (js_ack_fc_v2, 11+ tokens)
$JS.FC.{stream}.*.*                      # push flow control, v1 (5 tokens)
$JS.FC.*.*.{stream}.*.*                  # push flow control, v2 (7 tokens)
```

**write** adds, for `kvrw`, `objrw`, `kvadmin`, `objadmin`, `jsadmin`:

```text
$JS.API.STREAM.PURGE.{stream}            # KV PurgeDeletes, Object Store Put/Delete cleanup
$KV.<b>.>  or  $O.<b>.>                  # buckets only: put / delete / purge markers, object chunks and meta
```

**admin** adds, for `kvadmin`, `objadmin`, `jsadmin`:

```text
$JS.API.STREAM.CREATE.{stream}
$JS.API.STREAM.UPDATE.{stream}           # Object Store Seal
$JS.API.STREAM.DELETE.{stream}
$JS.API.STREAM.MSG.DELETE.{stream}
$JS.API.STREAM.SNAPSHOT.{stream}
$JS.API.STREAM.RESTORE.{stream}
$JS.API.INFO                             # clients call it before they create a bucket
```

**info**, for `jsinfo()`:

```text
$JS.API.INFO
$JS.API.STREAM.NAMES
$JS.API.STREAM.LIST
```

**consumer use** (7 subjects), for `jsconsumer` and `jsconsumeradmin`:

```text
$JS.API.STREAM.INFO.{stream}
$JS.API.CONSUMER.INFO.{stream}.{consumer}
$JS.API.CONSUMER.MSG.NEXT.{stream}.{consumer}    # pull requests
$JS.ACK.{stream}.{consumer}.*.*.*.*.*            # acks, v1 reply format (9 tokens)
$JS.ACK.*.*.{stream}.{consumer}.*.*.*.*.>        # acks, v2 reply format (11+ tokens)
$JS.FC.{stream}.{consumer}.*                     # push flow control, v1 (5 tokens)
$JS.FC.*.*.{stream}.{consumer}.*                 # push flow control, v2 (7 tokens)
```

**consumer admin** adds 7 subjects, for `jsconsumeradmin`:

```text
$JS.API.CONSUMER.CREATE.{stream}.{consumer}
$JS.API.CONSUMER.CREATE.{stream}.{consumer}.>    # create with a filter subject
$JS.API.CONSUMER.DURABLE.CREATE.{stream}.{consumer}
$JS.API.CONSUMER.DELETE.{stream}.{consumer}
$JS.API.CONSUMER.PAUSE.{stream}.{consumer}
$JS.API.CONSUMER.UNPIN.{stream}.{consumer}
$JS.API.CONSUMER.RESET.{stream}.{consumer}
```

A consumer macro is not cumulative with the read set. It grants nothing on
the stream except `STREAM.INFO`, so the user can bind to that one consumer
and to no other. With `jsconsumer` the user cannot create, change or delete
the consumer, so a filter the administrator set holds. With
`jsconsumeradmin` the user owns that one consumer and picks its filter, which
isolates users from each other but does not restrict the data they read.

**With a domain**, for example `domain=hub`, every set above changes in five
ways and in no other way:

1. `$JS.API.` becomes `$JS.hub.API.` in every API subject, `$JS.API.INFO`
   included.
2. The domain token of the **v2** ack and flow control patterns becomes the
   domain name: `$JS.ACK.hub.*.{stream}.*.*.*.*.*.>` and
   `$JS.FC.hub.*.{stream}.*.*`. The account hash stays a wildcard, because the
   remote may register the account under another name. The v1 patterns carry
   no domain token and do not change.
3. The KV data publish subject becomes `$JS.hub.API.$KV.<b>.>`. That is what
   nats.go publishes to when an API prefix is set, and the remote maps it back
   to `$KV.<b>.>`.
4. The Object Store data publish subject stays `$O.<b>.>`. Clients do not
   prefix it and the server has no `$O` domain mapping.
5. Subscribe lists do not change. A bucket's data subject is account local, so
   a bucket macro still emits `$KV.<b>.>` or `$O.<b>.>` there.

So `{{kvrw(tag(kv), domain=hub)}}` with tag `kv:cfg` emits
`$JS.hub.API.STREAM.INFO.KV_cfg` through `$JS.hub.API.STREAM.PURGE.KV_cfg`
plus `$JS.hub.API.$KV.cfg.>` in a publish list, and `$KV.cfg.>` in a
subscribe list.

The read set was derived from what nats.go v1.51 (both the legacy
`nats.KeyValue` API and the `jetstream` package) actually publishes, and is
verified end to end by the `TestJWTTemplateMacro*EndToEnd` tests. Every
subject is bound to the resource's own stream, so the wider patterns (for
example `CONSUMER.CREATE.{stream}.>`) cannot reach other streams. The ack and
flow control patterns use exact token counts so that a v1 pattern can never
match a v2 subject of another stream and vice versa.

**With a wildcard.** NATS wildcards match whole tokens, so `*` replaces the
whole stream token and the data subject becomes `$KV.*.>` or `$O.*.>`.
`{{jsread(*)}}` and `{{jsadmin(*)}}` are exact: every stream. A bucket
wildcard such as `{{kvrw(*)}}` grants all KV data **and the JetStream API of
every stream in the account**, not only of buckets, because the bucket name
lives inside the stream token and `KV_*` would be a literal, not a wildcard.
There is no subject pattern that means "all KV buckets but no other stream".
`{{jsconsumer(orders, *)}}` means every consumer of `orders`. Prefix forms
such as `team-*` are impossible for the same reason and are rejected.

**Operational notes:**

- A `jsread`-only user must bind to the stream explicitly, for example
  `nats.BindStream("orders")` in nats.go. Without it, the client resolves the
  stream through `$JS.API.STREAM.NAMES`, which only `jsinfo` grants.
- `jsinfo` is account-level discovery: `STREAM.NAMES` and `STREAM.LIST` return
  every stream in the account, including streams the user cannot read.
- The flow control patterns (`$JS.FC.`) are used by push consumers only when
  the server detects a stall. They are covered by the subject-set unit tests,
  not by the end-to-end tests.

**Deliberately not included:**

- `_INBOX.>` (or a custom inbox prefix) in `sub.allow`. JetStream API replies
  and consumer deliveries arrive on inboxes; add it once per template.
- Publish subjects of a plain stream. They come from the stream's
  configuration, not its name, so they stay ordinary template entries.
- Cross-account JetStream API imports with a custom prefix. Macros emit the
  default `$JS.API.` prefix, or `$JS.<domain>.API.` with `domain=`; an API
  imported under an arbitrary prefix stays an ordinary template entry. A
  client that targets the server's **own** domain needs no `domain=` either
  way, because the server maps `$JS.<local domain>.API.>` to `$JS.API.>`
  before the permission check.

## 4.4 Read-only users and consumers

Reading a stream, and therefore a bucket, goes through a consumer, except
for direct get. So the read set includes consumer creation, and a read-only
user can, on the resource's stream:

- create any consumer: push or pull, ephemeral or durable, any filter;
- get info and list consumer names;
- delete any consumer, including consumers other users created;
- pull from and ack on any consumer, including consumers other users
  created. This can take messages away from another user, or ack messages
  that user did not process.

The last two points are inherent to per-stream permissions: consumer names
are one token, so no subject pattern can say "only consumers this user
created". Push consumers deliver to an inbox chosen by the creating client
and are not exposed this way; pull consumers are, because `MSG.NEXT` is
addressed by consumer name. KV and Object Store clients use ephemeral push
consumers only today, but nats.go plans to move KV watch to pull-based
ordered consumers, so the read set keeps the pull and ack subjects. Users
who must not interfere with each other should get a consumer-level macro,
`jsconsumer` or `jsconsumeradmin`, instead of a stream-wide read macro.

## 4.5 Security model

- Expansion runs inside the server from the **verified account JWT**. A user can
  only obtain resources that the account's template author routed through
  tags, and only tags in the user's **signed** JWT count. No new trust is
  introduced.
- A read-only macro never emits the data subject or `STREAM.PURGE` in a
  publish list, so it cannot write data or purge.
- Names from tags are restricted to `A-Z a-z 0-9 _ -`. This is stricter than
  the server's stream name rule on purpose: the emitted subjects go through
  the upstream template pass afterwards, so a value must not be able to carry a
  template token (`kv:{{name()}}`), a wildcard (`kv:*`) or a separator
  (`kv:a.b`). `TestJWTTemplateMacroRejectsTemplateInjection` guards this.
- Off by default in the sense of this fork: there is no config knob, the opt-in
  is the account JWT. A template without macros is processed exactly as upstream,
  and upstream servers reject templates that use macros (authentication fails),
  so a macro can never grant more on an old server.

## 4.6 Code map & tests

- `server/auth_perm_macros.go` — macro table (`permMacros`), subject sets
  (`permMacroReadPubSubjects`, `permMacroWritePubSubjects`,
  `permMacroAdminPubSubjects`, `permMacroInfoPubSubjects`,
  `permMacroConsumerPubSubjects`, `permMacroConsumerAdminPubSubjects`), which
  are templates over the placeholders `{stream}`, `{consumer}`, `{api}` (the
  JetStream API prefix) and `{dom}` (the domain token of the v2 ack and flow
  control formats), argument list parsing (`parsePermMacro`,
  `splitPermMacroArgs`), argument resolution and the per-list expansion
  (`expandPermMacroList`, `expandPermissionMacros`).
- `server/auth.go` — one four-line hook in `processUserPermissionsTemplate`,
  placed after the fail-closed bookkeeping and before the upstream template
  pass. Both callers (operator-mode scoped signers and the auth callout) go
  through this function.
- Tests: `server/auth_perm_macros_test.go` and `server/auth_perm_macros_*_test.go`
  — unit tests for every macro, argument form, list kind, failure mode and
  the expansion cap, plus operator-mode end-to-end tests with real nats.go
  KV / Object Store / stream clients.

```sh
go test -run 'TestJWTTemplateMacro' ./server -count=1
```

Adding a macro for another resource is a one-line addition to `permMacros`
(stream prefix, data subject prefix, argument count, level flags).

---

# Maintenance notes

- Features 1–3 are gated **off by default**; feature 4 has no config knob and is
  active only for account JWTs carrying `template.xpermissions`. Feature 5 is
  always on and sends the same interest as upstream. Its coalesced source/mirror check is off unless
  `sync_consumers_check_interval` is set. Feature 6 applies only to remotes
  with a `SignatureCB`. Features 7 and 15 are APIs that do nothing until
  they are called. The marker of feature 16 shows only for a connection
  with auth verification or grant mode. These changes are always on: the verified JWT identity rule of
  section 2.5 (operator mode, when a JWT connection also sends CONNECT `nkey`
  or `user`; it changes reported identity and log labels), the upstream
  defect corrections of sections 11, 13, and 14, the leaf
  revoked-credential check of section 12.1, and the leaf delay for a disabled
  account of section 12.3. Otherwise an
  unconfigured server behaves like upstream.
- Features 1, 2 and 4 keep their logic in dedicated files (`server/authverify/`,
  `server/soo-changes.go`, `server/auth_xpermissions.go`, and
  `server/auth_xpermissions_compile.go`) with minimal, stable hooks in upstream
  files, to minimize merge conflicts when rebasing onto a newer upstream release.
- When upgrading the fork to a new upstream release, cherry-pick the custom commits
  forward and re-run the feature tests:

  ```sh
  # Features 1, 2, 4, 5, 6, 7 and 8, and sections 11, 12, 14 and 15
  go test -race -run 'AuthGrant|AuthVerify|LeafRemoteRevoked|RequestInfo|ClientInfoForRequest|SharesRequestUserInfo|AuthCalloutSentinelKeepsConnectUser|AuthHookRejectionNamesVerifiedSubject|AuthUserLogLabels|XPermissions|LeafNodeIsolated|LeafNodeSharedLeaf|LeafNodeNonLeafSubs|LeafNodeRequestedIsolation|LeafNodeDuplicateIndex|LeafNodeSyncCheck|LeafNodeSignatureCBReload|LeafNodeTsub|JetStreamLeafNodeLateLink|RefreshClientTraceLevel|JetStreamAccountSetJetStreamLimits|JetStreamSubjectRollupOnly' \
      ./server ./server/authverify ./test -count=1
  ```


# 8. Grant mode (in-process authorization hook)

Grant mode lets an embedding host supply a connection's complete permissions after
NATS verifies its JWT identity. It is off by default. The operator-signed account
JWT selects the mode, and linked Go code implements `authverify.GrantHook` through
`Options.AuthGrant`. There is no config-file key or network grant service.

```json
"nats": { "authverify": { "mode": "grant" } }
```

An absent block or `"mode": "static"` retains normal JWT authorization. Unknown
fields, types, and modes reject the claims. Grant mode cannot coexist with an
account auth callout. A mode change closes non-internal account connections with
`AuthModeChanged`. JetStream, account, and system internal clients remain active.
Admission rechecks the mode after account registration so a connection cannot miss a concurrent mode-change disconnect.

A user signed by the account identity key can opt into static authorization:

```json
"nats": { "authverify": { "mode": "static" } }
```

In a grant-mode account, the user block is invalid for any other signer. In a static
account, the server ignores the user block without parsing it. All other grant-mode
users must use a scoped signing key with a non-empty role. The hook receives its role,
verified identity, server, client, CONNECT, and TLS information. CLIENT connections, including in-process
connections, and LEAF connections participate. The system account is excluded.
Static users retain the existing `auth_verification` behavior and scope rules.

## 8.1 Hook and permission rules

`Verify(*authverify.GrantRequest) *authverify.GrantVerdict` runs synchronously and
must not block or perform I/O. A missing hook, panic, nil verdict, zero generation,
invalid grant, or missing admit `Done` callback rejects admission. An admit's
`Done(bool)` runs exactly once. `true` means the grant reached the authentication
admission point under the client lock. A concurrent close after that point is an
admitted close. `Closed(serverID, clientID)` runs asynchronously after `Done(true)`
returns and teardown removes the connection from server maps. Host callbacks run
without server or client locks held by the calling goroutine. The server recovers
and logs panics in `Done` and `Closed`. A panic in `Done(true)` closes the connection
with `GrantRejected`. A Closed notification starts a short tracked goroutine at
close time, so an open grant connection costs no goroutine. During shutdown the
server calls the host directly, so shutdown cannot discard the notification. That
call can run on the goroutine that called `Server.Shutdown`, so a host must not
hold a lock that its `Closed` takes while it calls `Shutdown`. Host callbacks must
not block.

`Grant` contains `Pub`, `Sub`, and optional `Resp`. Each direction has standard
`Allow` and `Deny` subject lists and token-prefix `AllowPrefix` rules. Empty allows
grant nothing. The hook replaces JWT, scoped-template, xpermissions, and account
default permissions. Identity validation, source and time restrictions, transport
restrictions, bearer policy, proxy requirements, and account limits still apply.
The earlier of JWT expiry and a nonzero grant expiry ends the connection.
Grant expiry uses its own timer, so updating a grant cannot strand CONNECT waiting
for a canceled authentication timeout.
Response permission defaults match normal JWT response permissions.

A prefix token such as `device-*` matches `device-123`, but not `device-`.
A rule must contain at least one prefix token. Other tokens use standard subject
syntax. For example, `$KV.device-*.>` permits a subscription to `$KV.device-123.>`
but not `$KV.*.>`. The subscription's entire subject space must fit a rule.
Standard denies still apply. Each subject or prefix list permits at most 4096
entries. Invalid entries reject the complete grant.

Accepted leaves reverse publish and subscribe rules with their standard lists.
For grant leaves, each ordinary subscription, mapping source, and service import
contributes the intersection of its subject with the exact publish grant. Prefix
rules contribute standard wildcard supersets. Source ownership retains overlaps
and queue weights across initialization, live changes, and reconnects. Mapping
and service-import notifications reconcile the current account inventory.

The hub keeps its own copy of the publish grant of each accepted grant leaf.
Interest projection, the INFO `export_grant` object, and the inbound publish
check read that copy. Each CONNECT decodes its `export` field into the
connection options. A second CONNECT does this before re-authentication installs
the grant again. The copy prevents that field from widening the projected
interest in this interval. `TestAuthGrantLeafSecondConnectExportKeepsInterestConfined`
holds this interval open and checks that no row outside the grant goes to the leaf.

A live leaf connection that authenticated without grant mode cannot enter grant
mode with a later CONNECT. Its interest map belongs to the earlier session and
has no grant sources, so the hub would send interest outside any grant until the
next snapshot. The server rejects the CONNECT with `Authorization Violation`
before it calls `Verify`, as it already does for a grant connection that changes
identity or leaves grant mode. A new connection is admitted normally. Other
re-CONNECTs keep their upstream behavior.
`TestAuthGrantLeafStaticToGrantReconnectRejected` covers the switch and a static
re-CONNECT control.

Legacy INFO Import and Export remain unchanged. A grant hub also sends the optional
INFO `export_grant` object with `allow`, `deny`, and `allow_prefix`. The `allow`
field is always present. A new solicited spoke installs this exact export grant;
missing or null `allow` grants no standard subjects. An invalid object, subject,
or prefix rule closes the link. Local `deny_exports` remains effective.
Older spokes ignore the field and use the narrower standard interest rows.
Exact wrong-prefix rejection requires both peers to run this fork revision.

The spoke admits the hub's reply interest but forwards only exact grant traffic
or a plain literal subject explicitly advertised by the hub. Literal reply
forwarding retains denies on the raw and gateway-stripped permission subject.
It never treats loop-detection or queue interest as reply authority. The hub's
response budget, expiry, and final message checks remain authoritative.

An accepted grant leaf drops unauthorized literal subscription interest after
its full permission and response check. The hub registers no subscription,
sends no error, and keeps the link open. It warns once per connection and logs
later drops at debug level. This also fixes older spokes using the Import prefix
superset. Static subscription violations and unauthorized publications retain
their existing close behavior. A public grant update still reconnects the leaf,
so widening the Sub grant replays previously dropped interest.
ReverseMatch visits descendants below single-token wildcard nodes, so broad leaf
interest sees permissions such as `in.*.>` without losing deeper subjects.

Grant connections have no built-in exception for MQTT, service replies,
JetStream acknowledgements, or gateway-routed replies. Non-grant connections
keep their existing behavior. Since v2.15.2, upstream also requires explicit
MQTT permissions on non-grant leaf connections.

## 8.2 Live replacement and planned close

`Server.UpdateClientGrant(authverify.GrantUpdate)` requires the client ID, account
public key, user nkey, and a generation greater than the installed generation.
It replaces CLIENT permissions, clears the publish permission cache, removes
unauthorized subscriptions with permission errors, and preserves reply tracking
when response permissions are unchanged. Expiry can be extended only within the
JWT limit. Reload retains the installed grant without another `Verify` call.
CONNECT and JetStream transport denies survive internal leaf reinstall and exact
INFO updates independently of replaceable grant denies.

A LEAF update closes the connection with `AuthorizationChanged`; reconnect runs
`Verify` again. An invalid update closes with `GrantRejected` and returns
`ErrGrantRejected`. Other errors are `ErrUnknownClient`, `ErrNotGrantMode`, and
`ErrStaleGeneration`. Account or user mismatch returns `ErrUnknownClient`.

`Server.UpdateAccountClaims` preserves the current account auth mode and
`xpermissions`, because typed claims cannot express these raw JWT extensions.
Raw signed JWT updates can replace them.

`Server.DisconnectClient(id, code)` acts only on grant connections. It returns
`ErrNotGrantMode` for a non-grant connection and `ErrUnknownClient` for an unknown
ID. It accepts every reject code. Section 12 gives the wire error and the
close state of each code, for a planned close and for an admission rejection.
Hook rejection reasons appear only in server logs.
Both APIs can run from any goroutine. A caller must not hold a lock that its own
`Closed` implementation needs.

## 8.3 Code and tests

- `server/authverify/grant.go` defines the host API.
- `server/auth_grant.go` owns admission, stored grants, timers, updates, and callbacks.
- `server/auth_grant_mode.go` parses signed account and user mode blocks.
- `server/auth_grant_leaf.go` projects leaf permissions and advertises request reply interest.
- `server/auth_grant_prefix.go` compiles and matches token-prefix rules.
- `server/auth_grant*_test.go` covers modes, lifecycle, matching, and transport behavior.

```sh
go test -race -run 'AuthGrant|AuthVerify' ./server ./server/authverify -count=1
```

The [grant-mode design](docs/superpowers/specs/2026-10-23-grant-mode-design.md)
records the complete API and admission contract.


Scoped user JWTs must still pass upstream scoped-signer validation. Explicit
user permission or limit fields are invalid for that JWT form and reject before
`Verify`. Grant replacement applies after this identity-validation prerequisite.

# 9. Subject-only rollup

`Nats-Rollup: all` can remove foreign subjects when a publisher can write only
one subject. The optional `js_subject_rollup_only` flag rejects this header on
client publications. `Nats-Rollup: sub` and normal publication keep their existing
behavior. Stream purge through the API keeps its existing permissions.

```text
feature_flags {
  js_subject_rollup_only: true
}
```

The default is `false`. The policy covers every stream, including streams
created after startup and streams with subject transforms. It applies to both
static and grant-mode connections. A change to feature flags requires restart.
Enable the flag on every cluster peer and every origin that accepts key-scoped
writers.

The policy uses one value set at JetStream startup. Both existing rollup
validation paths read that value. It adds no identity lookup, authorization
callback, or lock to publication. Ordinary, atomic-batch, and fast-batch
publications use these checks. Committed Raft application remains unchanged.

Trusted source and mirror replay retain the existing rollup exemption. A source
can replay a historical `all` header. Protection therefore belongs at each
publishing origin. The flag does not reject source history or replace source
trust checks.

The [subject-rollup design](docs/superpowers/specs/2026-10-24-subject-rollup-only-design.md)
records the policy and tests.

```sh
go test -race ./server -run 'TestJetStreamSubjectRollupOnly' -count=1
```


# 10. Native inbox capture policy

`FeatureFlagJsRejectInboxCapture` names `js_reject_inbox_capture`. Its default is false.
When enabled, ordinary stream create, update, and restore requests receive API error 10052 if the normalized config captures `_INBOX.>`.
The policy checks stream subjects, source and mirror external delivery prefixes, and declared source and mirror consumer delivery subjects.

```text
feature_flags {
  js_reject_inbox_capture: true
}
```

The exemption requires both authenticated IN_PROCESS origin and unrestricted current authority.
The first system-account import stamps the proof. CLIENT and LEAF ingress clear caller-supplied proof.
Route and gateway transit preserve verified metadata. Chained imports, proposals, advisories, and assignment snapshots do not carry the proof.
Enable enforcement only after every peer supports this sanitation.
Enable the flag on every peer and every origin that accepts ordinary stream-manager credentials.

Restore freezes the exemption and normalized admitted config before cluster proposal.
The assignment retains a separate restore-only bit. Legacy and V2 transfer completion checks run before the stream accepts messages.
A source or mirror consumer response must retain the server's requested delivery subject before it creates internal subscription interest. Source setup validates the response before it starts the shared worker or changes source identity and sequence state. A rejected high-sequence response cannot suppress genuine messages after a valid retry.
A mismatch uses the existing ConsumerSetupFailed error and retry path.

JetStream captures the policy flag at startup. A flag change requires restart.
Request-free recovery and apply remain unchanged, including streams admitted before enforcement.
Plain outgoing consumers, KV and object creation, and trusted declared delivery configs keep their existing behavior.

The [native inbox capture design](docs/superpowers/specs/2026-10-31-inbox-capture-policy-design.md) records provenance, field coverage, restore state, exclusions, and proof requirements.
The dedicated `server/jetstream_inbox_capture*_test.go` tests cover standalone and clustered admission, memory and file storage, spoof protection, final restore checks, response equality, and restart and leader controls.

```sh
rtk proxy env GOWORK=off GOFLAGS='-p=2 -buildvcs=false' GOMAXPROCS=4 GOCACHE=/work/.gotmp/ncdl-fork-buildcache-20261026 go test ./server -run 'Test.*InboxCapture' -count=1
```

The owner publishes the tested clean commit as `v2.15.3-amnesh.1` on upstream base `v2.15.2`.
The existing `v2.15.2` tag stays at its current commit.


# 11. Leaf removal during the initial interest window

This section corrects an upstream defect. Upstream `v2.15.2` contains it. On
2026-11-04, upstream `release/v2.15.3` (`ab05672b`, `v2.15.3-RC.1`) and `main`
(`ca2c4da1`) still contained it.

`initLeafNodeSmapAndSendSubs` records each snapshot subscription in `tsub` and
starts the `tsubt` timer. The timer clears `tsub` after 5 seconds. A
subscription can enter the snapshot before its own leaf update runs. That
update then removes the subscription from `tsub` and does not count it again.

`removeLeafNodeConnection` stopped the timer and set `tsubt` to nil, but kept
`tsub`. The account lists the leaf until `acc.removeClient` runs. A late leaf
update in that interval removed the last `tsub` entry and called `Stop` on the
nil timer. The panic stopped the server. A leaf credential holder that connects
and closes while hub subscriptions change can cause it.

The fork clears `tsub` in `removeLeafNodeConnection`. `updateSmap` stops the
timer only when it is present. The interest that a live leaf receives does not
change.

```sh
go test -race ./server -run 'TestLeafNodeTsubUpdateAfterLeafRemoval' -count=1
```


# 12. Grant reject codes

`authverify.RejectCode` classifies a rejection. The values are wire values of
the static callout (`AuthVerifyResponse.code`), so new codes are only
appended. The grant hook (`GrantVerdict.Code`), the static callout, and
`Server.DisconnectClient` use the same codes. An unknown code is `CodeDenied`.

| Code | Value | Admission `-ERR` | Admission close state | Planned close `-ERR` | Planned close state |
|---|---|---|---|---|---|
| `CodeDenied` | 0 | `Authorization Violation` | `AuthenticationViolation` | `Authorization Violation` | `GrantRejected` |
| `CodeResourceLimit` | 1 | `maximum connections exceeded` | `ResourceLimit` | `maximum connections exceeded` | `ResourceLimit` |
| `CodeRetry` | 2 | `Authorization Temporarily Unavailable` | `AuthorizationUnavailable` | none | `AuthorizationUnavailable` |
| `CodeQuarantined` | 3 | `Account Quarantined` | `AccountQuarantined` | none | `AccountQuarantined` |
| `CodeRevoked` | 4 | `User Authentication Revoked` | `Revocation` | `User Authentication Revoked` | `Revocation` |
| `CodeAccountDisabled` | 5 | `Authorization Violation - Account Disabled` | `AccountDisabled` | `Authorization Violation - Account Disabled` | `AccountDisabled` |

The new close states `AuthorizationUnavailable`, `AccountQuarantined`, and
`AccountDisabled` come after `ResourceLimit`. Their strings are
`Authorization Unavailable`, `Account Quarantined`, and `Account Disabled`. A
WebSocket close uses status 1008 (policy violation) for them, as for
`Revocation`. An admission rejection sends the `$SYS` auth
error events (`$SYS.SERVER.<id>.CLIENT.AUTH.ERR`, and
`$SYS.ACCOUNT.CLIENT.AUTH.ERR` in the account) with the close state string as
the reason. The planned close sends the normal disconnect event with the
close state string.

Client behavior with nats.go v1.53.1:

- `Authorization Temporarily Unavailable` and `Account Quarantined` are not
  authentication error texts. A client retries with its normal reconnect wait
  and does not stop after two equal errors. A first `Connect` fails unless the
  client sets `RetryOnFailedConnect`.
- A planned close for `CodeRetry` or `CodeQuarantined` sends no `-ERR`. While
  connected, nats.go closes for good on an error text that it does not know.
  After a close without `-ERR` it reconnects.
- nats.go classifies `User Authentication Revoked` as `ErrAuthRevoked`. It
  stops after the second equal rejection on one server, unless the client sets
  `IgnoreAuthErrorAbort`.
- nats.go classifies `Authorization Violation - Account Disabled` as
  `ErrAuthorization`, because the text starts with `Authorization Violation`
  (also v1.54.0). It stops after the second equal rejection on one server.
  After a planned close it gets the error while connected, reconnects one
  time, and stops at the next rejection.
- A leaf remote reconnects after `LeafNode.ReconnectInterval` for every code,
  but it does not send CONNECT again with a revoked JWT (section 12.1), and
  it waits 30 s after `CodeAccountDisabled` (section 12.3).

Only `CodeRevoked` sends the revoked text at admission. A JWT that the account
JWT revokes (upstream `checkUserRevoked`) still gets `Authorization Violation`
at admission. Upstream live revocation of a connected user keeps its text
`User Authentication Revoked`.

## 12.1 Leaf remote: no CONNECT with a revoked JWT

When a solicited leaf connection gets `User Authentication Revoked`, at
CONNECT or as a planned close, the remote keeps a SHA-256 digest of the user
JWT that it sent on that connection. It keeps only the last digest, in memory,
in the remote configuration. Before each later CONNECT, after it gets the JWT
from the credentials file or from `SignatureCB`, the remote compares the
digest. On a match it sends no CONNECT, logs a warning, closes the connection
with `Revocation`, and waits 30 seconds before the next check
(`leafNodeReconnectAfterPermViolation`). A different JWT, also for the same
user key, sends CONNECT normally. Each new JWT thus costs at most one CONNECT.
Two JWTs that a signer issues for the same claims in the same second are equal,
so a reissue in the same second as the revoked JWT stays blocked until the JWT
changes. Retry and quarantine keep the normal reconnect.

The JWT and the digest never reach a log. A restart, or a reload that removes
and adds the remote, clears the digest. A reload that keeps the remote keeps
it. A remote without a user JWT (nkey only, or user and password) is not
affected. The digest is one per remote, for all URLs of the remote.

This changes the upstream leaf behavior for the text
`User Authentication Revoked`, also when an account JWT update revokes a
connected leaf user. Upstream, the remote sends CONNECT with the same JWT
again after each reconnect interval.

## 12.2 Code and tests

- `server/authverify/grant.go` defines the codes. `server/authverify/req.go`
  adds `AuthVerifyResponse.Code`.
- `server/auth_reject_codes.go` maps a code to its authentication error, close
  state, and wire text. Hooks: `server/auth_grant.go` (admission and
  `DisconnectClient`), `server/auth_verification.go` (static callout; only
  the consumed verdict sets the code), `server/auth.go`
  (`getAuthErrClosedState`), `server/client.go` (close states and
  `authViolation`), `server/monitor.go` (strings), `server/websocket.go`
  (close status).
- `server/leafnode_revoked.go` holds the digest check. Hooks in
  `server/leafnode.go`: the `leaf` and `leafNodeCfg` fields, `sendLeafConnect`,
  `leafProcessErr`, and `leafNodeResumeConnectProcess`.
- `server/leafnode_account_disabled.go` holds the delay of section 12.3. Hook
  in `server/leafnode.go`: `leafProcessErr`.
- `server/auth_grant_transport_test.go` covers both wire paths, the nats.go
  client retry and stop, and the leaf retry. `server/auth_verification_test.go`
  (`TestAuthVerifyCalloutRejectCodes`) covers the static `code` and the `$SYS`
  events. `server/leafnode_revoked_test.go` covers both credential sources and
  both revocation moments: the hub gets no authentication attempt with the
  revoked JWT over three check periods while the remote keeps dialing, and a
  reissued JWT for the same user key connects at the next check.
  `server/auth_reject_account_disabled_test.go` covers section 12.3.

```sh
go test -race -run 'AuthGrant(Reject|Disconnect|Client|Connected|Leaf)|AuthVerifyCallout|LeafRemoteRevoked' ./server ./server/authverify -count=1
```

## 12.3 Account disabled

`CodeAccountDisabled` (value 5) is for an account that the host disables for
some time and enables again later. `CodeDenied` does not fit: a leaf remote
sends CONNECT again at each reconnect interval (1 s by default) with no end.
`CodeRevoked` does not fit: a leaf remote never sends CONNECT again with that
JWT, so it does not come back.

- The wire text is `Authorization Violation - Account Disabled`, at
  admission and at a planned close. The close state is `AccountDisabled`
  (`Account Disabled`).
- A client stops after the second equal error, as for `CodeDenied`.
- A soliciting leaf that gets the text, at CONNECT or at a planned close, sets
  the connect delay of its remote to `leafAccountDisabledDelay` (30 s), in the
  form of the other delays of `leafProcessErr`. After the delay, it sends
  CONNECT again with the same credentials. When the host admits the account
  again, the leaf connects at its next attempt, with no restart and no JWT
  change. Thus a leaf comes back about 30 s after the host enables the
  account at the latest, and a disabled account costs one CONNECT for each 30 s for each
  remote. The test-only `LeafNode.connDelay` option replaces the delay.
- A peer that does not know the code still sees an authorization violation.
  A server without the code treats value 5 from the static callout as
  `CodeDenied`, because it maps each unknown code to `CodeDenied` (static
  reading of the older code; the rows for code 99 test this rule on this
  server). A client without the text reads it as `Authorization Violation`.
  A leaf server without the text retries at each reconnect interval, as for
  `CodeDenied` (static reading, not tested).

Tests: rows in `TestAuthGrantRejectWire`, `TestAuthGrantDisconnectWire`, and
`TestAuthVerifyCalloutRejectCodes` check the wire text and the close state.
`TestAuthGrantClientAccountDisabledCodeStops` checks that a nats.go client
gets `ErrAuthorization` and stops, at CONNECT and after a planned close. It
passes with nats.go v1.53.1 (`go.mod`) and, in one run with a copied module
file, with v1.54.0.
`TestAuthGrantLeafAccountDisabledWaitsAndReconnects` lowers the delay to
500 ms. At CONNECT and after a planned close, each next attempt of the leaf
comes at least 500 ms after the previous one, and the leaf connects again with
the same JWT when the hook admits it. A control with `CodeDenied` retries
three times in less than 500 ms.


# 13. MQTT request header block

This section corrects an upstream defect. Upstream `v2.15.2` contains it.

The MQTT session manager sends its JetStream requests through an internal
client. When a request has no header block of its own, the send loop adds a
`Nats-Request-Info` header. It wrote `NATS/1.0\r\n`, the header line (which
`http.Header.Write` ends with CRLF), and then two CRLF. Thus the block was
`NATS/1.0\r\nNats-Request-Info: {...}\r\n\r\n\r\n`: it had an empty line
before its end. The stream store removes `Nats-Request-Info` and keeps the
rest, so a stream stored the block `NATS/1.0\r\n\r\n\r\n`. Each new MQTT
session record (`$MQTT_sess`) and each transferred legacy session or retained
record had it.

Such a block is not strict (section 2.4). A server with `stamp_request_info`
on drops the LEAF delivery of such a message, so a mirror, a source, or an
ordered consumer of `$MQTT_sess` across a leaf link stops at the first new
session record.

The fork writes one CRLF after the header line. The block ends with one empty
line. After the store removes `Nats-Request-Info` from a session record, only
`NATS/1.0\r\n\r\n` stays, and the store keeps no header block. The change is
always on. It also changes the bytes with stamping off: a new session record
has no header block (before: a 14-byte block), and each MQTT JetStream
request has 2 fewer header bytes.
MQTT reads the JSON body of a session record and named headers of the other
records, so no reader sees a change. Session records that a server stored
before the correction keep the old block.

Leaf links: a hub with stamping on drops a LEAF message with a block that is
not strict (section 2.4). Thus, without the correction, the hub drops each
MQTT JetStream request without its own header block that an MQTT server
behind a leaf link sends to the JetStream domain of the hub (static reading,
not tested). The correction removes this drop when the leaf server runs it.

The store check of section 2.4 needs this correction: without it, the check
rejects each new session record while stamping is on.

Upgrade order: a server without the correction writes these records with the
old block:

- the first session record of a new MQTT client ID (`$MQTT_sess`);
- a session record that it transfers from a legacy per-session stream
  (`$MQTT_sess`);
- a retained message that it transfers from the legacy retained format
  (`$MQTT_rmsgs`).

When the leader of `$MQTT_sess` or `$MQTT_rmsgs` has the store check and
stamping on, it rejects these records. Then the MQTT CONNECT of a new client
ID on the old server fails, and the transfer logs an error. Existing sessions
still save, because their records have a strict
`Nats-Expected-Last-Subject-Sequence` block.

Rolling upgrade of a cluster in which each server serves MQTT. Use one of
these procedures:

1. Upgrade all servers with `stamp_request_info` off. Then turn it on with a
   reload on each server. While the feature is off, the server does not do
   the ingress check of section 2.4 (the protection of `.5`), and it does not
   stamp requests.
2. Keep the leaders of `$MQTT_sess` and `$MQTT_rmsgs` on servers without the
   store check until you upgraded all servers. Move a leader with a stream
   leader stepdown that names a preferred old server.

```sh
go test -race ./server -run 'TestMQTTStampRequestInfoStoreHeaderBlocks' -count=1
```

The test runs MQTT QoS 1 and QoS 2 publishes, retained messages and a
retained delete, and a session with stamping on. It checks that each stored
header block in the MQTT streams is strict.


# 14. Source and mirror request after a leaf link connects

This section corrects an upstream defect. Upstream `v2.15.2` contains it. On
2026-11-20, upstream `release/v2.15.3` (`ab05672b`, `v2.15.3-RC.1`) and
`main` (`d163ae74`) still contained it.

A stream source or a mirror sends one consumer create request (a reset
request for a durable consumer) and waits for the reply: 30 s
(`srcConsumerWaitTime`), or 5 s for a reset. When no leaf link to the
origin exists, no reply comes. After the wait, the source counts one
failure and waits for the backoff of `calculateRetryBackoff` (10 s for
each failure, at most 2 minutes). A leaf connect or a leaf INFO runs
`retryDisconnectedSyncConsumers` (section 5.3). That function skipped a
source with a request in progress (`sip`), so a link that came up during
the wait did not help. On `v2.15.3-amnesh.6`, a link that came up just
after the request gave the data 40 s after the link (the 30 s wait and the
10 s backoff). A replication probe measured 35 s for a link that came up
5 s after the request. A server that restarts with a stored mirror or
source and no link sends the request during its start, so it has the same
delay.

Now `retryDisconnectedSyncConsumers` wakes the wait of a request in
progress and sets the failure count to 0. The wait then continues only
until the request throttle (`sourceConsumerRetryThreshold`, 2 s after the
request) lets a new request go. A reply that arrives before that is used.
When the wait ends with no reply, the setup removes the reply subscription
of the old request, counts no failure, and schedules a new request with no
backoff (only the 100 to 200 ms jitter). The new request has a new reply
subject, so a late reply to the old request has no subscriber and does not
change the source. The consumer that the old request made on the origin
gets no subscriber, and the origin deletes it after its inactive threshold
(10 s), as after an upstream timeout. One run measured the delete 10 s
after the late reply (a test like the late reply test below, not
committed).

From link up to the data, the tests measure about 2.1 s when the link
comes up just after the request, and 0.15 to 0.2 s when it comes up more
than 2 s after the request. Sources and mirrors, a first request and a
retry, and a mirror or source that a restart restores use the same path.

What does not change:

- With no leaf link event, the wait, the failure count, and the backoff
  are as upstream.
- A reply with an error after a wake counts a failure, as upstream.
- The 2 s throttle stays. A leaf event does not send requests more often
  than one for each 2 s for each source, and each request can get its
  reply for 2 s. Thus a burst of leaf connects does not end a request
  that an origin answers within 2 s.
- The check runs only on the server that gets the leaf connect or INFO,
  and only the stream leader acts. In a cluster, a stream leader on
  another server still waits (an upstream limit, also for sources without
  a request in progress).

Cost:

- Each leaf connect or INFO in the account wakes each request in progress
  of each source and mirror in the account. A request is woken at most one
  time.
- While leaf events continue, a source or mirror whose origin cannot be
  reached sends a request about every 2 s, not one for each 30 s wait and
  backoff. Nothing receives such a request. On a hub with one stream that
  sources from many leaves (section 5), a connect burst thus gives up to
  one request each 2 s for each source, also for the leaves that are not
  connected yet.
- After a wake, the new request waits for its jitter timer. Each later
  leaf event stops this timer and starts it again, as upstream does for a
  scheduled setup. Without the coalesced check of section 5.3, a burst
  with less than 100 ms between leaf events can delay the new request
  until the burst ends.
- When the origin is reachable but needs more than 2 s for the reply,
  each leaf event during a request ends that request at 2 s. If leaf
  events in the account come during each request, the source gets no
  consumer until the events stop. Before the change, each request had
  30 s. This is the main trade-off of the 2 s end.
- Each request that the origin gets makes a consumer there. On an origin
  stream with limits retention and no cluster, it is a new direct
  consumer for each request. A consumer of an ended request has no
  subscriber, and the origin deletes it after 10 s. Thus a slow origin
  under leaf event churn can hold up to about five such consumers for
  each source.

Code and tests:

- `server/stream.go`: the field `sourceInfo.wake`; the wake in
  `shouldRetry` of `retryDisconnectedSyncConsumers`; the wait in
  `setupMirrorConsumer` and `trySetupSourceConsumer`.
- `server/jetstream_leafnode_late_link_test.go`, with a hub and a leaf
  that turns its remote on and off with a config reload:
  `TestJetStreamLeafNodeLateLinkEndsRequestWait` (a source and a mirror;
  the link comes up just after the first request, or 2.5 s after it),
  `TestJetStreamLeafNodeLateLinkAfterOutage` (an outage longer than the
  first backoff, with a failure count of 1 and a retry in progress at link
  up; the request wait is 3 s in the test),
  `TestJetStreamLeafNodeLateLinkAfterRestart` (a leaf server restarts with
  a stored mirror or source and its link off; the link comes up at least
  3 s after the restored request), and `TestJetStreamLeafNodeLateLinkLateReply` (a
  late reply to the first request reaches the hub; the source keeps its
  consumer, and on the origin only that consumer has interest). Each test
  expects the data within 5 s after link up. Without the correction, each
  test fails at that check.

```sh
go test -race ./server -run 'TestJetStreamLeafNodeLateLink' -count=1
```


# 15. `Server.RefreshClientTraceLevel`

An open connection keeps the trace flag that it read when it connected
(`client.trace`, set by `setTraceLevel`). The parser reads this flag. Only a
config reload sets it again (`reloadClientTraceLevel`), and that function
returns at once when `Options.NoLog` is set. A host that embeds the server
sets `NoLog` and gives its logger with `SetLoggerV2`. When this host turns
trace on, the connections that are already open do not trace. When it
turns trace off, they stop the trace lines, because `client.Tracef` checks
the server flag, but the parser still does the trace work.

```go
// RefreshClientTraceLevel makes each open connection use the present trace
// setting of the server.
func (s *Server) RefreshClientTraceLevel()
```

- Call it after `SetLogger` or `SetLoggerV2`. It also applies when `NoLog`
  is set.
- It sets the same connections as a config reload: the system client (from
  the `sysTrace` flag), the clients (also MQTT and WebSocket),
  `grTmpClients`, the leaf nodes, the routes, and the gateways. Internal
  clients of JetStream and of accounts keep their flag, as after a reload.
- A connection that is between `initClient` and its entry in the server
  maps when the flag changes can keep the old flag, as after a reload.
- It locks the server and each connection. Do not call it from a logger
  method or from another server callback.
- It reads the temporary client map `grTmpClients` only while it holds
  `s.grMu`, in the order `s.mu`, then `s.grMu`, as `Shutdown` does. The
  setup of a leaf link, a route, or a gateway connection writes this map
  with only `s.grMu` (`addToTempClients`, `removeFromTempClients`). Tag
  `v2.15.3-amnesh.7` read the map without `s.grMu`. This was a data race,
  and a concurrent map write could stop the process. The config reload
  (`reloadClientTraceLevel`) uses the same function, so the repair also
  applies to it. Upstream `v2.15.2` has the same reads without the lock in
  its reload.

Code and tests:

- `server/client_trace_refresh.go`: `Server.RefreshClientTraceLevel`.
  `server/reload.go`: the body of `reloadClientTraceLevel` after its
  `NoLog` check is now `setClientsTraceLevel`, which both use. It holds
  `s.grMu` for the length of `grTmpClients` and for the copy of its
  clients.
- `server/client_trace_refresh_test.go`: `TestRefreshClientTraceLevel`
  runs a server with `NoLog` and a logger from `SetLoggerV2`. With trace on
  and no refresh, the open connection gives no trace line. After the
  refresh, it gives one. After trace off and the refresh, it gives none,
  and its cached flag is off. `TestRefreshClientTraceLevelWithTempClients`
  adds and removes temporary clients in one goroutine while the test calls
  `RefreshClientTraceLevel`. Without `s.grMu` in `setClientsTraceLevel`,
  the race detector reports a data race. Run it with `-race`.

```sh
go test -race ./server -run 'TestRefreshClientTraceLevel' -count=1
```


# 16. `Connz` marker for a connection that waits for its verdict

On the JWT path, the server registers the user and the account of a
connection before the verdict of auth verification (section 1) or of the
grant hook (section 8) arrives. `Connz` lists such a connection with its
account and its authorized user, also through
`$SYS.REQ.SERVER.<id>.CONNZ`. Before this change, no field separated it from
an admitted connection. A host that counts connections from `Connz` thus
counted a connection that the server could still reject.

`ConnInfo` gets one field:

```go
// Fork: the connection waits for the verdict of auth verification or of
// the grant hook. It is not admitted yet, and the server can reject it.
VerificationPending bool `json:"verification_pending,omitempty"`
```

- The server sets the marker before it registers the user and the account
  of a JWT connection that gets a verdict: a grant-mode connection, or a
  connection in the scope of auth verification. It removes the marker when
  the verdict admits the connection. A rejected connection keeps the marker
  until it closes and leaves the open list.
- Client and leaf connections get it. An accepted leaf is only in the
  account list (`Connz` with `acc`) during the wait. It enters the server
  list when its CONNECT completes (static reading; the test reads the
  account list).
- A host counts a connection as admitted only when the connection has its
  account and its user and no marker. A client before its CONNECT is in the
  server list with no account and no marker. The marker is set just before
  the server registers the user and the account, and a rejected connection
  keeps it until it closes, so the marker covers more than the wait itself.
- Only the open list has it. A closed connection record has no marker.
- With `omitempty`, the output of an admitted connection does not change.
  The HTTP monitor output and the system request reply use the same
  `ConnInfo`.
- A config reload authenticates an admitted connection again with the cached
  verdict, and it sets no marker.

Code and tests:

- `server/auth_verification_pending.go`: `markVerificationPending` and
  `clearVerificationPending`. Hooks: `server/auth.go` (the mark before
  `registerJWTUser`), `server/auth_verification.go`
  (`authVerifyConnection`), `server/auth_grant.go` (`authGrantConnection`),
  `server/client.go` (the field `verificationPending`), and
  `server/monitor.go` (the `ConnInfo` field and the open loop of `Connz`).
- `server/auth_verification_pending_test.go`:
  `TestAuthVerifyConnzVerificationPending` (a verification service holds its
  verdict; `Connz` through the server call, with and without the account
  filter, and through the system request shows the marker; after an admit,
  the marker is absent, also in the raw JSON and after an authentication
  again as at a config reload; after a reject, the connection leaves the open
  list) and `TestAuthGrantConnzVerificationPending` (a grant hook holds its
  verdict, for a client and a leaf, with an admit and a reject).

```sh
go test -race ./server -run 'ConnzVerificationPending' -count=1
```
