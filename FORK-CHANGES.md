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
| 2 | **Request Info Stamping** (userinfo on all requests) | `stamp_request_info: true` (hot-reloadable) | `server/soo-changes.go` | `server/client.go`, `server/leafnode.go`, `server/opts.go`, `server/reload.go`, `server/server.go` |
| 3 | Custom Listeners/Dialers (transport injection) | programmatic (`Options`) | — | listener/dialer plumbing (see commit `6f42d0a4f`) |
| 4 | **Scoped Resource Permission Groups** (`template.xpermissions`) | add signed groups to a scoped signing key template | `server/auth_xpermissions.go`, `server/auth_xpermissions_compile.go` | `server/accounts.go`, `server/server.go`, `server/auth.go`, `server/auth_callout.go` |
| 5 | **Leafnode scaling** (isolated hubs with 60k+ leaves) | always on; the isolation fast paths apply with `leafnodes { isolate: true }` or a remote's `request_isolation`. Optional: `leafnodes { sync_consumers_check_interval: "250ms" }` (off by default, hot-reloadable) | `server/leafnode_isolation.go`, `server/leafnode_dupindex.go`, `server/leafnode_synccheck.go` | `server/leafnode.go`, `server/sublist.go`, `server/accounts.go`, `server/client.go`, `server/server.go`, `server/opts.go`, `server/reload.go` |

Features 1, 2, 4 and 5 are documented in full below. Feature 3 is summarized in between.

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
  "expires":       0                 // optional unix-seconds; only honored if SOONER than the JWT exp
}
```

Outcomes:
- `reject: true` → connection denied.
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

## 2.5 What gets stamped

The header value is a JSON `ClientInfo` (subset of the upstream type) carrying a
**trimmed identity set** — enough to identify the requestor, without the heavier
detailed fields (JWT, issuer key, server/cluster, start time):

| JSON field | Meaning |
|---|---|
| `acc` | account name / public key |
| `user` | user id (raw auth user) |
| `name` | client `name` from CONNECT |
| `tags` | authenticated user JWT tags (omitted for non-JWT users or an empty tag list) |
| `kind` | connection kind (e.g. `Client`, `Leafnode`) |
| `client_type` | client type (e.g. `nats`, `mqtt`, `websocket`) |
| `lang` | client language |
| `host` | client host/IP |
| `rtt` | measured RTT |
| `reply` | (LEAF only) preserved original reply subject when forwarded across a leaf — see §2.6 |

Header name: **`Nats-Request-Info`** (`ClientInfoHdr`).

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

## 2.7 Performance & caching

- **Disabled (default):** one atomic load, then return. No allocation.
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

## 2.9 Code map & tests

- `server/soo-changes.go` — `stampRequestInfoHeaderIfNeeded` (hot path + cache),
  `getClientInfoForRequest`, `skipRequestInfoStamp` + the skip-prefix list.
- `server/client.go` — call site in `processInboundClientMsg`; the
  `client.ciStampHdr` cache field and its invalidation points.
- `server/leafnode.go` — leaf inbound call site.
- `server/server.go` — the `Server.stampReqInfo` atomic mirror, set at startup and
  on reload.
- `server/opts.go` — `Options.StampRequestInfo` + the `stamp_request_info` key.
- `server/reload.go` — `stampRequestInfoReload` (hot-reload apply).
- Tests: `server/soo-changes_test.go` and `test/soo-changes_test.go`.

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

## 5.2 Changes

| Upstream cost | Change |
|---|---|
| `initLeafNodeSmapAndSendSubs` walked **all** account subscriptions for each new leaf, ran `canSubscribe` and built a debug string for each, and only then dropped leaf interest for an isolated leaf. | For an isolated hub-side leaf, the snapshot uses `Sublist.nonLeafSubs`: a set of the non-leaf subscriptions that the sublist fills with one walk on first use and then keeps in `Insert` and `remove`, under the sublist write lock. Leaf interest is "client kind `LEAF` or `sub.leaf`" (routed from a leaf on another server), the same test as upstream. The isolation check runs before `canSubscribe`. |
| As a side effect of those `canSubscribe` calls, a wildcard leaf subject could load the delivery deny filter (`c.mperms`) of the new leaf. Some of the leaf's own subscriptions (`$GR.`, `_GR_.`) skip the check that would load it. | An isolated hub-side leaf with subscribe denies loads the deny filter in the snapshot. The filter only blocks deliveries that the deny rules already block, so this is the same as upstream or stricter. |
| `updateLeafNodesEx` walked all leaves for each leaf `LS+`/`LS-` and locked each one, only to skip the isolated ones. | Each account keeps `sharedLeafs`, the leaves in `lleafs` that are not isolated, in the two places that change `lleafs` (`addClient`, `removeLeafNode`). When it is empty, leaf interest returns early. The isolation flag has an atomic copy (`leaf.isolatedHint`); isolation can only be turned on. A leaf that requests isolation in its CONNECT leaves the set. |
| `addLeafNodeConnection` searched for a previous connection from the same remote by walking all leaves under the server lock. | An index by (remote server, remote cluster, account, remote account) under the server lock, next to `s.leafs`. Each candidate is checked with the original condition. If a remote changes these fields after they were captured (an INFO to the accept side, or a second CONNECT, possibly into another account; both abnormal), the connection is marked before the change, the server logs a notice, and the check uses the full walk while that connection is open. |
| `client.Debugf` and `client.Tracef` formatted the message before the level check. | They check the level first, as `Server.Debugf`/`Tracef` do. |

## 5.3 Optional: coalesced source and mirror check

Upstream calls `checkInternalSyncConsumers` on the readloop of every leafnode
connect (hub side) and of every INFO that a solicited leafnode receives. It
locks every stream of the account that has a mirror or sources, and for each
disconnected or stale source it cancels the backoff and schedules a new setup.
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
  `client.loadIsolatedLeafDenyFilter`, and the `sharedLeafs` helpers.
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
  deny filter; randomized set consistency; benchmark) and
  `server/leafnode_dupindex_test.go` (randomized index against the upstream walk;
  fallback on identity and account change, and its end),
  `server/leafnode_synccheck_test.go` (config, reload, coalescer bounds and
  ordering, shutdown) and `server/jetstream_leafnode_synccheck_test.go` (a leaf
  connect cancels a long source backoff, with and without the option). Upstream tests `TestLeafNodeIsolatedLeafSubjectPropagation*`,
  `TestLeafNodeLoopDetectedDueToReconnect` and
  `TestLeafNodeHubRejectDuplicateRemotes` cover the unchanged behavior.

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
  always on but sends the same interest as upstream; its only visible
  difference is that an isolated leaf with subscribe denies always gets its
  delivery deny filter. Its coalesced source/mirror check is off unless
  `sync_consumers_check_interval` is set. An unconfigured server behaves like
  upstream.
- Features 1, 2 and 4 keep their logic in dedicated files (`server/authverify/`,
  `server/soo-changes.go`, `server/auth_xpermissions.go`, and
  `server/auth_xpermissions_compile.go`) with minimal, stable hooks in upstream
  files, to minimize merge conflicts when rebasing onto a newer upstream release.
- When upgrading the fork to a new upstream release, cherry-pick the custom commits
  forward and re-run the feature tests:

  ```sh
  # Features 1, 2, 4 and 5
  go test -run 'AuthVerify|RequestInfo|ClientInfoForRequest|SharesRequestUserInfo|XPermissions|LeafNodeIsolated|LeafNodeSharedLeaf|LeafNodeNonLeafSubs|LeafNodeRequestedIsolation|LeafNodeDuplicateIndex|LeafNodeSyncCheck' \
      ./server ./server/authverify ./test -count=1
  ```
