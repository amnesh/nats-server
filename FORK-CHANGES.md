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

Features 1 and 2 are documented in full below. Feature 3 is summarized at the end.

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
| Pub/Sub **allow** | **intersection** — only subjects within *both* the JWT-allow and the override-allow survive. A disjoint override keeps the base allow (an empty allow list would mean "allow all", which would be an escalation). |
| Response `max` / numeric limits | effective = **smaller** (`-1` = unlimited) |
| Response `ttl` | effective = **shorter** |

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
  `NarrowExpiry`, `NarrowCount`) on `jwt` types; never imports `server` (carries a
  vendored copy of the subject subset-match).
- `server/authverify/req.go` — wire types (`AuthVerifyRequest`,
  `AuthVerifyResponse`), constants, `ParseAuthVerifyResponse`.
- `server/auth_verification.go` — config gating (`AuthVerifyInScope`,
  `authVerificationApplies`), the SYS transport (`processAuthVerification`),
  request building (`buildAuthVerifyRequest`, `clientTLSInfo`), and override
  application (`applyAuthVerifyOverride`).
- `server/opts.go` — `Options.AuthVerification bool` + the `auth_verification`
  config key.
- `server/auth.go` — one hook in the `processClientOrLeafAuthentication` deferred
  block.
- Tests: `server/authverify/*_test.go` (narrowing engine, escalation regression,
  capstone) and `server/auth_verification_test.go` (scope, config, response parse,
  and operator-mode integration: admit / reject / narrow / fail-closed-on-timeout).

---

# 2. Request Info Stamping (userinfo on all requests)

## 2.1 What it is

When enabled, the server stamps a **`Nats-Request-Info` header** containing the
requesting client's identity onto **every inbound request message** (any
CLIENT/LEAF publish that carries a reply subject). Downstream subscribers — typical
request/reply services — can then read *who* sent the request (account, user,
name, kind, language, host, RTT) directly from the message header, without any
application-level convention or extra round-trip.

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
detailed fields (JWT, issuer key, tags, server/cluster, start time):

| JSON field | Meaning |
|---|---|
| `acc` | account name / public key |
| `user` | user id (raw auth user) |
| `name` | client `name` from CONNECT |
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
  service-import security model).
- The **`reply`** field of the forwarded header is **preserved**, because chained
  service-import response routing across the leaf boundary depends on it.

## 2.7 Performance & caching

- **Disabled (default):** one atomic load, then return. No allocation.
- **Enabled:** the marshaled header for a connection is **cached** on the client
  (`client.ciStampHdr`) and reused across requests, since the identity is stable
  for the life of the connection. The cache is invalidated when identity-affecting
  state changes (account swap on reload, re-register, close).
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

# Maintenance notes

- All three features are gated **off by default**; an unconfigured server behaves
  exactly like upstream.
- Features 1 and 2 keep their logic in dedicated files (`server/authverify/`,
  `server/soo-changes.go`) with minimal, stable hooks in upstream files, to
  minimize merge conflicts when rebasing onto a newer upstream release.
- When upgrading the fork to a new upstream release, cherry-pick the custom commits
  forward and re-run the feature tests:

  ```sh
  # Feature 1 (authverify) + Feature 2 (request info stamping)
  go test -run 'AuthVerify|RequestInfo|ClientInfoForRequest|SharesRequestUserInfo' \
      ./server ./server/authverify ./test -count=1
  ```
