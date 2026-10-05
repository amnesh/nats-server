# Scoped Resource Permission Groups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace whole-entry JetStream resource permission macros with the approved signed `template.xpermissions` grouped schema while preserving ordinary scoped-template permissions, limits, deny precedence, and both scoped authentication paths.

**Architecture:** Parse and strictly validate the raw, already verified account JWT into an immutable signer-keyed extension map, then swap it atomically with the typed signing scopes on the `Account`. Compile a scoped user's permissions from copied standard permission slices plus generated grouped subjects, using the existing subject bundles as the single source of truth. Keep parsing and compilation in dedicated fork files and limit upstream hooks to account claim ingestion, account scope lookup/update, and the two scoped-user authentication call sites.

**Tech Stack:** Go, `encoding/json`, `encoding/base64`, existing `github.com/nats-io/jwt/v2` and `nkeys`, NATS server account/authentication code, Go unit and integration tests.

## Global Constraints

- Implement only in `/tmp/nats-server-xpermissions-Dt142g`; do not change NATS clients, `nats-io/jwt`, or another repository.
- Implement exactly the approved schema in `docs/superpowers/specs/2026-09-18-xpermissions-grants-design.md`: nonempty `kv`, `obj`, `stream`, and `consumer` arrays plus optional boolean `jsinfo`.
- `jsinfo: false` is valid alone and adds or removes nothing; `true` emits the three local `$JS.API` info subjects. Domain-specific info remains ordinary `pub.allow`.
- Standard `pub`, `sub`, `resp`, limits, bearer/proxy flags, and connection types retain their typed JWT meaning. Generated subjects are additive allows; standard denies always remain effective.
- Reject legacy resource macro calls in all four standard subject lists during signed account claim ingestion, even when `xpermissions` is absent. Preserve ordinary value substitutions.
- Strictly reject duplicate JSON object fields, duplicate signing-key entries, unknown extension/group-entry fields, wrong types, bad operations/selectors, null/empty extension objects, and empty supplied resource arrays.
- Preserve the 4096 generated-subject budget independently per permission list, deterministic `kv` → `obj` → `stream` → `consumer` → `jsinfo` order, entry/value order, Cartesian expansion, and first-seen deduplication.
- Copy standard permission slices before appending generated subjects; never mutate a shared `jwt.UserScope.Template` or a previously installed account generation.
- Use `Account.mu`; add no lock and do not change `locksordering.txt` unless implementation proves a new lock is unavoidable.
- Keep the work buildable through each phase. Produce one final signed-off fork feature commit; do not create intermediate commits, push, or rewrite history.
- Baseline at `933a25206` already passed: `go test -run 'AuthVerify|RequestInfo|ClientInfoForRequest|SharesRequestUserInfo|TemplateMacro' ./server ./server/authverify ./test -count=1 -timeout=15m`.

---

## File map

- Create `server/auth_xpermissions.go`: extension structs, strict raw JWT payload parsing, raw-to-typed scope correlation, schema validation, and legacy macro rejection.
- Create `server/auth_xpermissions_compile.go`: selector resolution, bounded Cartesian expansion, subject profile bundles, additive compilation, stable deduplication, and fail-closed bookkeeping.
- Delete `server/auth_perm_macros.go` after moving its subject bundle constants and profile emission logic into `auth_xpermissions_compile.go`; retain only a small legacy-call detector in `auth_xpermissions.go`.
- Modify `server/accounts.go`: store immutable extensions beside `signingKeys`, atomically retrieve scope plus extension, swap/compare both generations, and invalidate clients on extension-only changes.
- Modify `server/server.go`: verify and parse raw account JWTs before mutation; carry extensions through first load, system-account load, update, and stored-JWT refresh.
- Modify `server/auth.go` and `server/auth_callout.go`: pass the atomically retrieved extension to the shared scoped-template compiler.
- Rename and migrate `server/auth_perm_macros_test.go`, `server/auth_perm_macros_admin_test.go`, `server/auth_perm_macros_consumer_test.go`, `server/auth_perm_macros_domain_test.go`, and `server/auth_perm_macros_wildcard_test.go` to `auth_xpermissions*_test.go`. Preserve every existing `TestJWTTemplateMacro*` behavior assertion under `TestJWTXPermissions*` and add parser/lifecycle coverage.
- Modify `server/jwt_test.go` and `server/auth_callout_test.go` only for account-load/update and auth-callout scenarios that belong with their existing harnesses.
- Modify `FORK-CHANGES.md`, `CLAUDE.md`, and the three permission design specs to document the grouped wire format, new test selector, implementation status, and historical supersession.

## Interfaces to implement

Use unexported, immutable-after-parse types. Exact field types may use named string enums, but the external shape and function boundaries are fixed:

```go
type xPermissions struct {
    KV       []xBucketPermission
    Obj      []xBucketPermission
    Stream   []xStreamPermission
    Consumer []xConsumerPermission
    JSInfo   *bool // nil=absent, false=valid no-op, true=local info set
}

type accountXPermissions map[string]*xPermissions // scoped signer public key -> extension

func decodeAccountXPermissions(claimJWT string, ac *jwt.AccountClaims) (accountXPermissions, error)
func validateNoLegacyPermissionMacros(ac *jwt.AccountClaims) error
func (s *Server) verifyAccountClaimsWithXPermissions(claimJWT string) (*jwt.AccountClaims, accountXPermissions, string, error)
func (a *Account) issuerScopeAndXPermissions(issuer string) (jwt.Scope, *xPermissions, bool)
func processUserPermissionsTemplate(lim jwt.UserPermissionLimits, xp *xPermissions, ujwt *jwt.UserClaims, acc *Account) (jwt.UserPermissionLimits, error)
```

Keep the existing `verifyAccountClaims(claimJWT) (*jwt.AccountClaims, string, error)` unchanged and make the new wrapper call it first. The wrapper preserves that verified raw-string return and adds only `accountXPermissions`, minimizing caller churn. Add one extension parameter to the private account construction/update path instead of changing unrelated public APIs:

```go
func (s *Server) buildInternalAccount(ac *jwt.AccountClaims, xp accountXPermissions) *Account
func (s *Server) updateAccountClaimsWithRefresh(a *Account, ac *jwt.AccountClaims, xp accountXPermissions, refreshImportingAccounts bool)
```

`UpdateAccountClaims(a, ac)` remains typed-only and calls the private updater with `nil`, which clears any stored extension. Raw JWT ingestion paths must call `verifyAccountClaimsWithXPermissions` and pass its map. `issuerScopeAndXPermissions` returns pointers into an immutable generation replaced under `Account.mu`; callers must not mutate them.

---

### Task 1: Implement and integrate scoped resource permission groups

**Files:** All files in the file map above.

**Interfaces:**
- Consumes: verified `jwt.AccountClaims`, raw signed account JWT strings, typed `jwt.UserScope.Template`, verified user claims and existing account tag/name state.
- Produces: the exact interfaces listed above, an atomically installed signer-keyed extension map, and compiled `jwt.UserPermissionLimits` used by both scoped authentication paths.

#### Phase A — Strict signed-account parser

- [ ] **Step 1: Rename the existing macro test files and test functions without deleting assertions**

Use `git mv` for all five `auth_perm_macros*_test.go` files. Rename `TestJWTTemplateMacro*` to `TestJWTXPermissions*` and keep every existing exact-subject and end-to-end assertion. Add a raw fixture helper that encodes a valid typed account claim, decodes its JWT payload, inserts the supplied `template.xpermissions` under the intended scoped signer, serializes it, and re-signs the compact JWT with the operator key. Parser/compiler unit tests may pass that verified fixture directly through `verifyAccountClaimsWithXPermissions`; resolver-backed end-to-end tests must install the signed JWT through the normal resolver path in Phase C.

- [ ] **Step 2: Add failing strict-parser table tests**

Add `TestJWTXPermissionsRawSchema` cases covering:

```text
valid: each group/op, all groups, jsinfo true, jsinfo false alone,
       jsinfo false with groups, extension absent
invalid: null, {}, grants alias, unknown top-level field, empty group,
         non-array group, unknown/case-variant op, missing/extra entry field,
         non-string selector/domain, non-bool jsinfo, wildcard domain,
         duplicate JSON member at every extension nesting level,
         duplicate raw signing-key entry, raw/typed key or kind mismatch
```

Add four direct verification-wrapper cases proving valid legacy macro calls in `pub.allow`, `pub.deny`, `sub.allow`, and `sub.deny` are rejected without `xpermissions`, while ordinary `events.{{tag(team)}}.>` remains accepted. Phase C adds the normal resolver-ingestion assertion.

- [ ] **Step 3: Run the parser tests and record the expected red state**

Run:

```bash
go test ./server -run '^TestJWTXPermissionsRawSchema$' -count=1 -timeout=10m
```

Expected: FAIL because `template.xpermissions` is ignored and legacy macros still install.

- [ ] **Step 4: Implement strict parsing in `server/auth_xpermissions.go`**

Decode the compact JWT payload with `base64.RawURLEncoding` only after `verifyAccountClaims` succeeds. Walk JSON tokens before map unmarshalling to reject duplicate object member names without imposing a closed schema on unrelated account-claim fields. Read `nats.signing_keys` as raw array elements, reject repeated string/object signer keys, and correlate each `kind: user_scope` object and `key` with `ac.SigningKeys[key]` and its `*jwt.UserScope`.

Parse only `template.xpermissions` with strict allowed fields. Track field presence so absent differs from an empty array and `JSInfo` distinguishes absent/false/true. Validate group-specific fields and ops exactly:

```text
kv,obj:       ro|rw|admin + bucket + optional domain
stream:       ro|admin    + stream + optional domain
consumer:     ro|admin    + stream + consumer + optional domain
jsinfo:       bool
```

Reject a null or empty extension and every present empty resource group. Accept `jsinfo: false` alone. Validate literal selectors at ingestion; defer user-dependent template results to authentication. Scan every typed user scope's four standard lists for any mustache operation using the eleven legacy resource names and reject it regardless of extension presence or argument validity.

- [ ] **Step 5: Add the verification wrapper and rerun parser tests**

Implement `verifyAccountClaimsWithXPermissions` as `verifyAccountClaims` followed by legacy-list validation and raw extension parsing. It returns before any account mutation on error.

Run the Step 3 command. Expected: PASS.

#### Phase B — Additive compiler and complete test migration

- [ ] **Step 6: Convert the migrated exact-subject tests to grouped entries and verify red**

Represent all eleven existing powers through ten group/op pairs plus `jsinfo: true`. Name pure table/compiler cases `TestJWTXPermissionsCompile*`; obtain their extension input from a signed fixture parsed by the verification wrapper without requiring an installed `Account`. Preserve local/domain subject expectations, wildcard cautions, KV versus Object Store behavior, consumer ACK/flow-control coverage, and admin sets. Migrate the existing resolver-backed legacy/new nats.go assertions under `TestJWTXPermissionsEndToEnd*`, but run them after lifecycle wiring in Phase C. Add compiler tests that:

```text
jsinfo false alone emits nothing;
jsinfo false does not remove overlapping pub.allow or stream-admin INFO;
stream/consumer/jsinfo do not change an untouched subscribe direction;
KV/OBJ add their data subscribe allow but no _INBOX permission;
standard denies override generated allows;
resp and all limits remain byte-for-byte equivalent;
the source UserScope.Template slices remain unchanged across two compilations.
```

Run:

```bash
go test ./server -run '^TestJWTXPermissionsCompile' -count=1 -timeout=15m
```

Expected: FAIL until the grouped compiler replaces macro expansion.

- [ ] **Step 7: Implement `server/auth_xpermissions_compile.go` and remove macro expansion**

Move the existing read/write/admin/info/consumer subject arrays and domain-specific emission logic unchanged into named profile data used by grouped operations. Resolve ordinary selector operations (`name`, `subject`, account variants, tag variants) inside selector strings, preserving left-to-right and tag order. Required selectors that resolve empty or invalid are authentication errors; only a literal whole-field `*` is allowed for bucket/stream/consumer, never domain or a resolved value.

Use overflow-safe multiplication and charge candidate generated subjects to a 4096 budget separately for `pub.allow` and `sub.allow` before deduplication. Process standard entries first, then groups in fixed order, entries in array order, and selector tuples in stable order. Deduplicate first-seen subjects.

At compiler entry, copy all four standard permission slices before expansion/appending:

```go
lim.Permissions.Pub.Allow = append(jwt.StringList(nil), lim.Permissions.Pub.Allow...)
lim.Permissions.Pub.Deny = append(jwt.StringList(nil), lim.Permissions.Pub.Deny...)
lim.Permissions.Sub.Allow = append(jwt.StringList(nil), lim.Permissions.Sub.Allow...)
lim.Permissions.Sub.Deny = append(jwt.StringList(nil), lim.Permissions.Sub.Deny...)
```

Combine ordinary and grouped allows before applying the existing synthetic `deny >` rule. Never confuse an explicit deny with that guard. Delete macro expansion code after its subject bundles and retained legacy detector have moved.

- [ ] **Step 8: Finish selector, ordering, cap, and concurrency regression tests**

Migrate the existing missing-tag, injection, Cartesian, wildcard, invalid-name, direction, and 4096-cap tests. Add multi-operation embedded selectors, deterministic output despite shuffled JSON object keys, stable dedup, candidate-budget-before-dedup, arithmetic overflow preflight, and a parallel compile test against one shared scope template for `go test -race`.

Run the Step 6 command. Expected: PASS with every prior behavior assertion represented; no `TestJWTTemplateMacro` functions remain.

#### Phase C — Atomic account lifecycle and both authentication paths

- [ ] **Step 9: Add failing lifecycle tests around real account JWT updates**

Add tests that load an account with extensions on first resolver fetch and system-account setup, then publish/subscribe with a normally scoped user. Add an extension-only account JWT update with an identical typed scope and prove the affected connected client receives `AuthenticationViolation`; reconnect must receive the new permissions. Add an invalid update and prove the old scope/extension generation and client remain usable. Add removal and typed-only `UpdateAccountClaims` cases proving stale extensions clear.

Exercise the incomplete-account stored-JWT refresh path and an operator auth-callout scoped response. Both must use the same extension generation as normal authentication. User JWT/auth-callout payload attempts to inject `xpermissions` must have no effect. Install an account JWT containing a legacy resource macro and no extension through the normal resolver update path; assert rejection before mutation and continued use of the old generation.

- [ ] **Step 10: Run lifecycle tests and record the expected red state**

Run:

```bash
go test ./server -run '^TestJWTXPermissions(AccountLifecycle|AuthCallout|EndToEnd)' -count=1 -timeout=20m
```

Expected: FAIL because `Account` does not retain or invalidate on extensions and authentication does not retrieve them.

- [ ] **Step 11: Carry one immutable extension generation through account lifecycle**

Add `xpermissions accountXPermissions` next to `Account.signingKeys`. Update `fetchAccountClaims`, `fetchAccount`, `SetSystemAccount`, `buildInternalAccount`, `updateAccountWithClaimJWT`, and the incomplete-import refresh inside `updateAccountClaimsWithRefresh` to use the verification wrapper and carry the parsed map. Resolver/event updates already converge through `updateAccountWithClaimJWT`; keep those hooks unchanged unless a test proves otherwise.

Inside the existing `Account.mu` signing-key update section, snapshot old scopes/extensions, install the new scope and extension maps together, and compare both. An extension-only difference sets `signersChanged` and adds that signer to `alteredScope`, reusing existing client eviction. Public typed-only `UpdateAccountClaims` passes `nil` and therefore clears extensions.

Implement `issuerScopeAndXPermissions` with one read lock. Return an immutable extension pointer from the same generation as the scope. Do not change general `hasIssuer` callers.

- [ ] **Step 12: Integrate both scoped authentication call sites**

In `processClientOrLeafAuthentication` and `processClientOrLeafCallout`, replace the separate `hasIssuer` lookup with `issuerScopeAndXPermissions`, keep `scope.ValidateScopedSigner` first, then call:

```go
processUserPermissionsTemplate(uSc.Template, xp, userClaims, account)
```

A compilation error fails authentication without mutating the scope template or installed account state.

Run the Step 10 command, then:

```bash
go test ./server -run '^TestJWTXPermissions(Compile|EndToEnd)' -count=1 -timeout=20m
```

Expected: both commands PASS, including every migrated end-to-end assertion.

#### Phase D — Documentation, compatibility cleanup, and final gates

- [ ] **Step 13: Remove legacy implementation residue and update fork documentation**

Ensure production contains no macro expansion hook or accepted macro syntax. Update:

```text
FORK-CHANGES.md: grouped raw JWT schema, migration, mixed-version warning, code/test map
CLAUDE.md: replace TemplateMacro test selector and auth_perm_macros.go example
new spec: status Implemented
old v1/v2 specs: status Historical/Superseded by the 2026-09-18 grouped spec
```

Do not add a config knob, compatibility mode, JWT dependency change, client change, global domain inference, or fallback deny policy.

- [ ] **Step 14: Run focused and race gates**

Run:

```bash
go test ./server -run '^TestJWTXPermissions' -count=1 -timeout=20m
go test -race ./server -run '^TestJWTXPermissions' -count=1 -timeout=30m
go test -run 'AuthVerify|RequestInfo|ClientInfoForRequest|SharesRequestUserInfo|XPermissions' ./server ./server/authverify ./test -count=1 -timeout=20m
```

Expected: all PASS and race reports no data race.

- [ ] **Step 15: Run JWT shard, build, lint, and 386 gates**

Run:

```bash
./scripts/runTestsOnTravis.sh jwt_tests
go build ./...
GOARCH=386 go test ./server -run '^TestJWTXPermissions' -count=1 -timeout=20m
GOARCH=386 go build ./...
golangci-lint run --timeout=5m --config=.golangci.yml
git diff --check
```

Expected: every command exits zero. Do not repeat passed gates unless a later edit affects them.

- [ ] **Step 16: Perform whole-feature review before commit**

Request one code review over the complete diff against the approved spec. Resolve every material finding, rerun only the affected focused tests plus any invalidated final gate, and confirm:

```bash
git status --short
git diff --stat
git diff --check
```

Only the planned feature/test/doc files may be present.

- [ ] **Step 17: Create the single signed-off fork feature commit**

Stage only the reviewed feature files and commit once:

```bash
git add server/auth_xpermissions.go server/auth_xpermissions_compile.go \
  server/accounts.go server/server.go server/auth.go server/auth_callout.go \
  server/auth_xpermissions*_test.go server/jwt_test.go server/auth_callout_test.go \
  FORK-CHANGES.md CLAUDE.md docs/superpowers/specs/2026-09-17-permission-template-macros-design.md \
  docs/superpowers/specs/2026-09-17-permission-template-macros-v2-design.md \
  docs/superpowers/specs/2026-09-18-xpermissions-grants-design.md
git add -u server/auth_perm_macros.go server/auth_perm_macros_test.go \
  server/auth_perm_macros_admin_test.go server/auth_perm_macros_consumer_test.go \
  server/auth_perm_macros_domain_test.go server/auth_perm_macros_wildcard_test.go
git commit -s -m "feat(auth): add scoped resource permission groups"
```

Do not amend, push, or rewrite the resulting commit. Report its SHA and the completed verification gates to the coordinator.
