# Grant mode: an in-process authorization hook

**Status:** implemented in this fork.
**Owner decisions (2026-10-23):** fork changes allowed; design approved (Sections 1–2 of the NCDL
session-grants design, `/work/amnet/next/ncdl/.audit/authz-redesign/10-sections-1-2-draft.md`).
**Repository:** `/work/github/nats-server`, branch `release/v2.15.1`.
**Consumer:** NCDL runtime (`local.go/ncdl/runtime/authverify`) and NCDL `runtime/topology`, which
embed this server in process. They are NOT part of this task.

The implementation follows the fork rules in `CLAUDE.md`: one squashed, signed-off
commit for the feature; feature logic in dedicated files with the smallest hooks in upstream files;
off by default; update `FORK-CHANGES.md` and add the design spec under `docs/superpowers/specs/`;
follow `locksordering.txt`; test-name prefixes select CI shards.

---

## 1. Why this work exists

Today a connection's permissions come from its signed user JWT (or the scoped signing-key
template). The `auth_verification` callout can only reject or NARROW them, once, at connect
(`server/authverify/authverify.go:35-82`). So every grant must exist when the JWT is signed. The
product (NCDL, a contract toolchain, and AMNET, which embeds this server in its controller) needs:

- grants decided at connect from run-time facts (for example the shard that a reservation centre
  chose for a device);
- grants for families of resources whose names are known only later (`KV_device-config-<id>`),
  which NATS whole-token wildcards cannot express;
- grants that change on a live connection (an entitlement turned on or off);
- conditional denies that apply only while an entitlement is active.

Grant mode solves these: for accounts in grant mode, an in-process Go hook supplies the complete
permission set of each connection, and the host can replace it on a live connection.

Trust model (owner decisions): the hook is in-process code; only code linked into the broker can
grant. There are no verifier keys and no signatures. offsec (the offline root of trust) controls
which accounts are in grant mode through the operator-signed account JWT. There is no offline
limit on what the hook grants. This intentionally differs from ADR 0019 (narrow-only) in the
consumer workspace; the ADR update is the consumer's task.

## 2. Scope

In scope (this repository only):

1. Account mode block in the account JWT (`static` | `grant`).
2. User mode block in identity-signed user JWTs (`static` only).
3. `Options.AuthGrant` hook: `Verify` at connect, `Closed` at close.
4. Grant semantics G1–G9.
5. Token-prefix allow rules.
6. `Server.UpdateClientGrant` (live update) and `Server.DisconnectClient` (planned close with a code).
7. New close reasons and the two reject codes.
8. Reload keeps the grant.
9. Tests, `FORK-CHANGES.md`, design spec.

Out of scope: CONNZ changes; in-place grant update for LEAF connections (they close and reconnect);
deny-side prefix rules; any per-subject authorization callback; the `$SYS.REQ.USER.VERIFY` path
(unchanged); NCDL, AMNET, offsec code; tags, releases, pushes.

## 3. Types (package `server/authverify`, pure: imports only `nats-io/jwt/v2` and stdlib)

```go
// RejectCode classifies a reject or a planned close.
type RejectCode int

const (
    CodeDenied        RejectCode = iota // default; the client sees 'Authorization Violation'
    CodeResourceLimit                   // no resource for this connection here; use another server
)

// GrantRequest describes one verified connection of a grant-mode account.
type GrantRequest struct {
    Server    jwt.ServerID          // same content as AuthVerifyRequest.Server
    UserNkey  string
    Account   string                // account public key
    Client    jwt.ClientInformation // same filling as fillClientInfo (auth_callout.go:471-488): id, name, tags, kind, …
    Connect   jwt.ConnectOptions    // same filling as fillConnectOpts (auth_callout.go:492-515); includes the user JWT
    TLS       *jwt.ClientTLS
    Issuer    string // key that signed the user JWT
    ScopeRole string // jwt.UserScope.Role of that scoped signing key (G9 guarantees it is set)
}

type Grant struct {
    Pub, Sub SubjectGrant
    Resp     *jwt.ResponsePermission
}

type SubjectGrant struct {
    Allow       []string // standard subjects; '*' and '>' keep their meaning
    AllowPrefix []string // token-prefix rules (section 6); allow only
    Deny        []string // standard subjects
}

type GrantVerdict struct {
    Reject     bool
    Code       RejectCode // used only when Reject
    Reason     string     // server log only; never sent to the client
    Generation uint64     // first grant of a connection; must be >= 1
    Expires    int64      // unix seconds; 0 = keep the JWT expiry
    Grant      Grant
    Done       func(applied bool) // may be nil on a reject; else called exactly once (G7)
}

type GrantUpdate struct {
    ClientID   uint64
    Account    string // must equal the connection's account public key
    UserNkey   string // must equal the connection's user nkey
    Generation uint64 // must be greater than the stored generation
    Expires    int64
    Grant      Grant
}

// GrantHook is implemented by the embedding host.
type GrantHook interface {
    // Verify decides one connection. Synchronous; must not block and must not do I/O.
    // A nil verdict is a reject with CodeDenied.
    Verify(req *GrantRequest) *GrantVerdict
    // Closed reports the close of a connection whose Done(true) was called. Must not block.
    Closed(serverID string, clientID uint64)
}
```

`server` package additions:

```go
type Options struct {
    // ...
    AuthGrant authverify.GrantHook `json:"-"` // code only; no config-file key; nil = off
}

func (s *Server) UpdateClientGrant(u authverify.GrantUpdate) error
func (s *Server) DisconnectClient(clientID uint64, code authverify.RejectCode) error

var (
    ErrUnknownClient    = errors.New("unknown client")
    ErrStaleGeneration  = errors.New("stale grant generation")
    ErrNotGrantMode     = errors.New("connection is not in grant mode")
    ErrGrantRejected    = errors.New("grant rejected")
)
```

## 4. JWT blocks

Account JWT (operator-signed), parsed from the verified raw account JWT in the same way as
`xpermissions` (`server.go:2187,2265-2273`, `accounts.go` `verifyAccountClaimsWithXPermissions`):

```json
"nats": { "...": "...", "authverify": { "mode": "grant" } }
```

- `mode` is `"static"` or `"grant"`. Absent block = `static`.
- Strict: unknown fields, a wrong type, or an unknown value reject the account claims (fail closed).
- A grant-mode account that also configures auth callout (`authorization` in the account JWT,
  `acc.hasExternalAuth()`) is rejected.
- Store the mode on `Account`. An account claims update that changes the mode closes every
  non-internal connection of that account with reason `AuthModeChanged`. Internal
  JetStream, account, and system clients remain active. Put this beside the existing
  xpermissions-change handling (`accounts.go:3585-3593,4062-4082`).

User JWT, parsed from the verified raw user JWT only when the account is in grant mode.
Static accounts ignore the user block without parsing or enforcing it:

```json
"nats": { "...": "...", "authverify": { "mode": "static" } }
```

- Honored only when the account identity key signed the user JWT: `juc.Issuer == account public
  key` (no scoped or plain signing key).
- The block on a JWT signed by any other key: reject the connection.
- Any value other than `"static"`, unknown fields, wrong type: reject the connection.
- A static user in a grant-mode account is handled exactly as in static mode (its JWT permissions;
  the existing `auth_verification` callout when enabled and `AuthVerifyInScope` is true).

## 5. Connect rules for a grant-mode account

Hook point: the deferred block of `processClientOrLeafAuthentication` (`auth.go:704-720`), next to
the existing `authVerificationApplies` branch. For a connection of a grant-mode account, take the
grant branch and do NOT run the v1 callout. Keep the upstream file change to one small call; put
the logic in a new file (for example `server/auth_grant.go`).

- **G1 Scope.** Grant branch applies to an authorized JWT user of kind CLIENT (including
  in-process) or LEAF, not bound to the system account, and not a static user (section 4). Other
  connections are unchanged. Note: `AuthVerifyInScope` (`auth_verification.go:32-37`) excludes
  in-process; the grant scope does not. Use a new scope function.
- **G9 Scoped only.** In the grant branch, the user JWT must be signed by a scoped signing key of the
  account (`acc.issuerScopeAndXPermissions(juc.Issuer)`, `accounts.go:3359`, used at `auth.go:1068`).
  Otherwise reject (CodeDenied). Reject an empty scope role before calling `Verify`.
  Put the scope's non-empty `Role` into `GrantRequest.ScopeRole`.
- **G2 Mandatory.** `Options.AuthGrant == nil`: reject. Hook panic: recover and reject. Nil verdict:
  reject. `Reject: true`: reject with `Code`. `Generation == 0` or an admit with `Done == nil`: reject.
- **G3 Grant only.** Effective permission lists are exactly the verdict's `Grant`.
  Grant connections have no built-in exception for MQTT subjects, service-import replies,
  JetStream acknowledgements, or gateway-routed replies: each needs a grant. Reason: these
  exceptions let a leaf publish, for example, `$JS.ACK` for another consumer in its account
  and acknowledge or terminate messages that it never received. Ignore the user JWT
  permissions, the scoped template permissions, `xpermissions`, and the account default
  permissions. Limits, allowed connection types, bearer, proxy, and expiry still apply. Build the
  internal `NkeyUser` with the grant permissions and register it, as `applyAuthVerifyOverride` does
  (`auth_verification.go:245-270`). The user must not be marked `defaultPerms`.
- **G4** (consumer side, informative): NCDL emits each scoped template of a grant-mode account with
  `pub.deny [">"]` and `sub.deny [">"]`, so a server without grant mode gives nothing. G3 ignores it.
- **G5 Empty means nothing.** Build every grant list as a non-nil list (`Publish.Allow`,
  `Subscribe.Allow` non-nil even when empty), so an empty allow means "allow nothing".
  The grant installer creates both empty allow sublists explicitly. Upstream subscribe permissions use a length check, so non-nil alone is insufficient. Do NOT convert
  through `jwt.Permissions` (`buildPermissionsFromJwt`, `accounts.go:4141-4171`, turns empty into
  "no restriction").
- **G6 Expiry.** Effective expiry = the sooner of the JWT expiry and `Expires` (when non-zero).
  Grant state owns its expiration timer separately from the initial authentication timer.
  Replacement invalidates obsolete callbacks, and connection teardown cancels the grant timer.
- **G7 Done.** The installation under the client lock is the admission point. Call `Done(true)` exactly when the grant was installed and
  `processClientOrLeafAuthentication` returns authorized. On every other path after an admit verdict
  (install error, later rejection in the same authentication, client closed during authentication)
  call `Done(false)`. Never call `Done` twice. `Closed` is called later only for connections that
  got `Done(true)`.
- **G8 Reload.** Store the last installed grant, generation, and expiry on the client. On re-auth
  during config reload, reinstall the stored grant without calling the hook (same pattern as the v1
  cached verdict, `auth_verification.go:73-89`, `client.go:344`).

Reject behavior:

- `CodeDenied`: today's path: `-ERR 'Authorization Violation'`, closed state
  `AuthenticationViolation`.
- `CodeResourceLimit`: send `-ERR 'maximum connections exceeded'` and use the new closed state
  `ResourceLimit`. Reason: pinned nats.go v1.53.1 closes the connection permanently on an unknown
  `-ERR` text (`nats.go:4329-4336`), but on `maximum connections exceeded` it reconnects to the
  next server in its pool (`nats.go:4317-4318`). The server log and the `$SYS` disconnect event show
  `ResourceLimit`.

## 6. Token-prefix allow rules

A rule is a subject where one or more tokens have the form `<prefix>*` with a non-empty `<prefix>`
that contains no `*`, `>`, or `.`. Every rule has at least one such token. Other tokens are
standard (literal, `*`, `>`).

Matching a literal token `t` against `<prefix>*`: `strings.HasPrefix(t, prefix) && len(t) > len(prefix)`.

- **Publish** (`pubAllowedFullCheck`, `client.go:4294-4340`): when the standard allow sublist has no
  interest, check the prefix rules; the deny list still applies after an allow. Store the result in
  the existing publish cache as today.
- **Subscribe** (`canSubscribeInternal`, `client.go:3431`): a subscription subject is allowed by a
  rule only if every subject it can match is matched by the rule: at each prefix position the
  subscription token must be a literal with the prefix (a `*` or `>` there is not allowed by the
  rule); at other positions use the normal subset semantics. Queue names are not restricted by a
  rule.
- **Leaf swap:** swap the pub and sub rule sets together with the lists for an accepted leaf, at
  `leafnode.go:2428-2433`.
- **Budget:** at most 4096 entries per rule list (the same budget as `maxPermTemplateSubjectExpansions`,
  `auth.go:475`). A larger list is a reject (connect) or `GrantRejected` (update).
- **Validation:** an invalid rule or subject in any list rejects the verdict (connect) or the update.
- Keep the matcher in a dedicated file; add only a small hook to the client permission struct and
  the two check functions.

Example: rule `$JS.API.STREAM.INFO.KV_device-config-*` allows publish to
`$JS.API.STREAM.INFO.KV_device-config-d501` and not to `$JS.API.STREAM.INFO.KV_other`.
Rule `$KV.device-config-*.>` allows subscribe `$KV.device-config-d1.>` and denies `$KV.*.>`.

## 7. Live update and planned close

`UpdateClientGrant(u)`:

1. Find the client: `s.clients[u.ClientID]` or `s.leafs[u.ClientID]` (client IDs are not reused while
   the server runs). Not found: `ErrUnknownClient`. Not a grant-mode connection: `ErrNotGrantMode`.
   Account or nkey mismatch: `ErrUnknownClient`. `u.Generation <= stored`: `ErrStaleGeneration`.
2. Validate the grant (section 6). Invalid: close the connection with `GrantRejected` and return
   `ErrGrantRejected`. Never keep the old grant, because it can contain rights that were removed.
3. CLIENT (including in-process): under the client lock, install the new permissions and rules
   (a new permission struct clears the publish cache), keep the reply tracking when `Resp` did not
   change (the pattern of `updateDefaultPermissions`, `client.go:1096-1132`), store grant,
   generation, and expiry (G6, G8), and set the expiration timer. Release the client lock, then call
   `c.processSubsOnConfigReload(nil)` (`client.go:6232`); it removes each subscription that is no
   longer allowed and sends a permissions-violation error for each one. Return nil.
4. LEAF: close the connection with the new reason `AuthorizationChanged` and return nil. The leaf
   reconnects and gets a new verdict. (An in-place update would need `LS-`/`LS+` interest resync;
   `reloadAuthorization` has no such path, `reload.go:2254-2440`.)

`UpdateAccountClaims` retains the current auth mode and `xpermissions` under the account
claims-update lock. Typed claims cannot carry these raw JWT extensions. Raw signed account
JWT updates can replace them.

`DisconnectClient(id, code)`: find the client as above (`ErrUnknownClient`), reject a non-grant
connection with `ErrNotGrantMode`, and close a grant connection with:
`CodeDenied` → reason `GrantRejected`, `-ERR 'Authorization Violation'`;
`CodeResourceLimit` → reason `ResourceLimit`, `-ERR 'maximum connections exceeded'`.

Both methods are safe to call from any goroutine, but must not be called while the caller holds a
lock that `Closed` also takes (consumer rule). Lock order: take the server lock only for the lookup,
release it, then take the client lock (`reloadMu -> Server -> client -> Account`,
`locksordering.txt`).

## 8. Closed callback

In the close path (`closeConnection`, `client.go:6290+`), for a connection that got `Done(true)`,
call `AuthGrant.Closed(serverID, clientID)` asynchronously exactly once, after `Done(true)` returns, after the client is removed from the
server maps and after all server and client locks are released. Never call it with a lock held.
Recover and log panics in `Done` and `Closed`.
A panic in `Done(true)` closes the connection with `GrantRejected`, because the host may not
have recorded the session. A panic in `Done(false)` preserves the admission rejection.
Decide under the client lock that a notification is due, after both `Done(true)` and teardown
finish, then deliver it with no lock held. Delivery starts a short tracked goroutine at close
time, so an open grant connection costs no goroutine of its own. During shutdown the server
starts no tracked goroutines, so the host is called directly and still receives the notification
before `Shutdown` returns. That direct call can run on the goroutine that called
`Server.Shutdown`. So a host must not hold a lock that its `Closed` takes while it calls
`Shutdown`. Host callbacks must not block, including waiting for server shutdown.

## 9. New close reasons

Add to the `ClosedState` enum (and its `String()`): `AuthorizationChanged` ("Authorization
Changed"), `GrantRejected` ("Grant Rejected"), `AuthModeChanged` ("Authorization Mode Changed"),
`ResourceLimit` ("Resource Limit"). Append at the end of the enum so existing values do not change.

## 10. Tests (prefix `TestAuthGrant`, which falls into the `srv_pkg_non_js_tests` shard)

Run with `-race`. Add `AuthGrant` to the fork feature-test regex in `CLAUDE.md` and `FORK-CHANGES.md`.

- Account block: valid `static`/`grant`; unknown field, wrong type, unknown value rejected; grant +
  auth callout rejected; mode change closes the account's connections with `AuthModeChanged`.
  Admission rechecks the mode after account registration to catch changes that occurred before
  the connection became visible to the account's disconnect snapshot.
- User block: honored for an identity-signed user (gets its JWT permissions, no hook call); a scoped
  user with the block is rejected; an unknown value is rejected.
- G9: an identity-signed user without the block in a grant account is rejected; a plain
  (non-scoped) signing key is rejected; `ScopeRole` equals the scope's role.
- G2: nil hook, panicking hook, nil verdict, `Generation 0` all reject.
- Reject codes: `CodeDenied` gives `Authorization Violation`; `CodeResourceLimit` gives
  `maximum connections exceeded` and closed state `ResourceLimit`; a nats.go client with two servers
  in its pool moves to the second server. A leaf remote with two URLs: record what it does
  (unverified today) and assert the observed behavior.
- G3: a grant ignores JWT permissions, a scoped template with `deny ">"`, `xpermissions`, and account
  default permissions (each in its own case).
- G5: an empty allow list allows nothing (publish and subscribe).
- G6: the sooner expiry wins.
- G7: `Done(true)` once on success; `Done(false)` on install error and when the client closes during
  authentication; `Closed` only after `Done(true)`.
- G8: config reload reinstalls the stored grant and does not call `Verify` (count calls).
- Prefix rules: publish match and non-match; deny wins over a rule; subscribe with literal prefix
  token allowed, with `*`/`>` at the prefix position denied; leaf swap; budget overflow rejected;
  invalid rule rejected.
- `UpdateClientGrant` CLIENT: a new allow works without reconnect; a removed allow is denied at once
  even if the subject was in the publish cache; a subscription that lost permission is removed and
  the client gets the error; resp tracking kept when unchanged; stale generation; unknown client;
  account/nkey mismatch; invalid grant closes with `GrantRejected`.
- `UpdateClientGrant` LEAF: closes with `AuthorizationChanged`; the leaf reconnects through `Verify`.
- `DisconnectClient` both codes.
- `Closed` is called once, without locks held (a test hook that calls back into
  `UpdateClientGrant` for another client must not deadlock).
- Static mode and the v1 callout behave exactly as before (run the existing `AuthVerify` tests).

## 11. Documentation

- `FORK-CHANGES.md`: a new feature section "Grant mode (in-process authorization hook)" with the
  blocks, API, rules, code map, and test command; update "Changes at a glance".
- This design is maintained at `docs/superpowers/specs/2026-10-23-grant-mode-design.md`.
- The consumer workspace copy (`/work/amnet/next/docs/reference/nats-fork-changes.md`) is updated by
  the consumer, not here.

## 12. Acceptance

- `go build ./...` and `go vet ./...` pass; the linter rules of `CLAUDE.md` hold (no `fmt.Print*`).
- The fork feature-test command (with `AuthGrant` added) passes under `-race`; the `jwt_tests` and
  `srv_pkg_non_js_tests` shards that touch auth pass.
- An unconfigured server (no `AuthGrant`, no grant-mode account) behaves exactly as before.
- One squashed, signed-off commit on `release/v2.15.1` with code, tests, `FORK-CHANGES.md`, and the
  spec. Do not push. Do not create or move tags. Report the commit hash and the test output.
- Leave the untracked files that are already in the repository (`AUTHZ-REPORT.md`, `report*.md`,
  and others) untouched.


## Implementation notes

The scoped-signing-key checks run before grant admission. Grant users retain the
template's non-permission limits but skip permission and xpermissions expansion.
Reauthentication retains the active permissions while rebuilding identity, then
reinstalls the latest stored grant under the client lock. It never exposes JWT or
account default permissions between those steps. Reinstallation also rebuilds
active subscription deny filters before releasing the lock.

The timer stores a version checked under the client lock. Replacing a grant stops
the old timer and invalidates callbacks that already started. A second CONNECT
for the same identity refreshes the JWT expiry cap. Changing the identity of a
grant connection requires a new connection.

Grant leaf interest is projected per source. Ordinary subscriptions, mapping
sources, and service-import subjects contribute their intersections with the
standard publish allows and the wildcard wire forms of prefix rules. Fully
denied rows are removed; partial deny overlaps retain delivery-time enforcement.
An empty standard allow remains deny-all. Ordinary and virtual source ownership
are separate, including when their projected rows collide. Queue weights are
summed once per source row. Mapping and service-import notifications reconcile
current account inventory under the client-before-account lock order.

The existing INFO Import and Export values retain their wire representation.
A grant hub adds optional `export_grant` with exact `allow`, `deny`, and
`allow_prefix` lists. `allow` has no omission tag. A solicited spoke consumes
that field without entering grant mode and merges its local DenyExports.
Missing or null `allow` means an empty allow. Invalid field types, subjects,
or prefix rules close the link without falling back to Export. Older spokes
ignore the field and receive the projected standard interest. Both peers need
the new revision for exact local rejection inside prefix wildcard supersets.

An exact-export spoke accepts the hub's LS+ rows. Message forwarding requires
the exact publish grant or a plain literal hub row for that wire subject.
The literal-row exception excludes loop detection, wildcard and queue rows,
and retains denies on both the raw and gateway-stripped permission subject.
The hub advertises a response's literal interest before delivering the request.
Its response budget, expiry, and final leaf message enforcement do not change.

After its full permission check, including response allowance, an accepted grant
leaf drops unauthorized literal LS+ without registering or propagating interest,
sending an error, or closing the link. One bool tracks whether the connection has
already logged its warning; subsequent drops use debug logging. Wildcard LS+,
static subscription violations, and unauthorized LMSG handling remain unchanged.
No import_grant field or spoke filter is added. The hub correction works with
older spokes. Public UpdateClientGrant already reconnects every leaf, so a Sub
widening obtains the new authoritative grant and replays dropped interest.
The ReverseMatch traversal includes descendants below single-token wildcard nodes.
Broad leaf interest such as `in.>` therefore sees an `in.*.>` permission while
retaining the one-or-more-token semantics of `>`.

A live internal grant reinstall restores accepted-leaf permission orientation,
refreshes INFO, and sends only differences in the aggregate source projection.
Transport denies merged by CONNECT and JetStream survive permission replacement
in their live directions. Retained transport state never includes old grant denies.
The public UpdateClientGrant leaf path still closes and reconnects. Initial
installation remains swapped once by the existing CONNECT path.


Scoped user JWTs must still pass upstream scoped-signer validation. Explicit
user permission or limit fields are invalid for that JWT form and reject before
`Verify`. Grant replacement applies after this identity-validation prerequisite.


## Verification

The implementation was checked with `go build ./...`, `go vet ./...`, and
`GOARCH=386 go build ./...`. Grant and fork feature tests ran under `-race`.
The `jwt_tests` and `srv_pkg_non_js_tests` shards also ran under `-race`.
The non-JS shard's first run stopped at `TestAccountImportCycle` with no responders;
ten focused repetitions passed in both the implementation checkout and the
checkout preceding lifecycle integration, and the full shard passed on retry.
No unrelated test change was made.

Full golangci-lint reports one existing goimports formatting issue in
`server/opts_test.go:4627`. The same formatting difference exists at the base
commit. That file is unchanged by this feature.

Transport tests establish that resource-limit rejection moves both a nats.go
client and a leaf with two configured URLs to the second server. Actual leaf
request/reply tests cover empty and unrelated nonempty publish allow lists.
Independent reviews checked reload permissions, callback ordering, timer
replacement, prefix subset and overlap matching, leaf wire projections, and
delivery deny filters. Regression tests cover the issues found during review.
