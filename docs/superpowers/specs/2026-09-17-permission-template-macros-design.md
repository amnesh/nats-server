# Design: Permission Template Macros for KV and Object Store buckets

- **Date:** 2026-09-17
- **Status:** Historical; superseded by `2026-09-18-xpermissions-grants-design.md`.
- **Component:** Removed whole-entry macro implementation
- **Author/driver:** chezgi (with Claude Code)
- **Origin:** `AUTHZ-REPORT.md` (not committed), approach 1 / phase 1

---

## 1. Problem

A user needs about a dozen distinct subjects to use one JetStream KV bucket:
the data subject `$KV.<b>.>`, plus JetStream API subjects that embed the stream
name `KV_<b>` (stream info, direct get, consumer create/delete, flow control,
...). Because the bucket name appears both as a stream name token and as a data
subject token, no single wildcard can grant a *subset* of buckets. A user JWT
that lists the subjects for 40 buckets is 10–13 KB.

Scoped signing keys already move permissions out of the user JWT: the account
JWT holds a `UserScope.Template`, the user JWT holds only tags, and the server
expands `{{tag(kv)}}` at connect time. What is missing is a vocabulary for
"everything needed to use a bucket", so a template still needs one entry per
subject per role.

## 2. Goals and non-goals

Goals:

- One template entry per bucket role: `{{kvrw(tag(kv))}}` expands into every
  subject a real client needs, for every `kv:<bucket>` tag on the user.
- Strictly additive. Templates without macros are processed exactly as upstream.
  No JWT schema change, no config knob, no new dependency.
- Keep the user's nkey and JWT signature chain authoritative (constraint from
  `AUTHZ-REPORT.md`). Expansion uses only the verified account JWT and the
  verified user JWT.
- Fail closed in the same way upstream templates do.
- Small hook in upstream code; all logic in a dedicated file.

Non-goals:

- Bucket management (create/update/delete buckets).
- JetStream domains or imported JS APIs with a custom prefix.
- Multi-role users (`AUTHZ-REPORT.md` phase 2) — separate change.
- Macros for plain streams. The design makes adding one trivial, but a stream's
  publish subjects are not derivable from its name, so it is left out until
  there is a concrete need.

## 3. Syntax

```text
{{<macro>(<argument>)}}
```

| Macro | Stream prefix | Data subject prefix | Grants writes |
|---|---|---|---|
| `kvro` | `KV_` | `$KV` | no |
| `kvrw` | `KV_` | `$KV` | yes |
| `objro` | `OBJ_` | `$O` | no |
| `objrw` | `OBJ_` | `$O` | yes |

The argument is one of the existing value-producing template operations
(`tag(key)`, `account-tag(key)`, `name()`, `subject()`, `account-name()`,
`account-subject()`) or a literal bucket name. Macro names and tag keys are
case-insensitive, as upstream ops are. Whitespace inside the braces is trimmed.

The user asked for the short spellings (`kvrw`); `AUTHZ-REPORT.md` sketched
`kv-rw`. Only the short form is implemented; there is no alias.

A macro token must be the entire entry. Embedding it in a longer subject is an
error because the expansion is a *set of subjects of different shapes*, not a
value that can be substituted into a template.

## 4. Expansion

`{stream}` = stream prefix + bucket, `{data}` = data subject prefix + `.` + bucket.

Publish lists, read set (11 subjects):

```text
$JS.API.STREAM.INFO.{stream}
$JS.API.STREAM.MSG.GET.{stream}
$JS.API.DIRECT.GET.{stream}
$JS.API.DIRECT.GET.{stream}.>
$JS.API.CONSUMER.CREATE.{stream}
$JS.API.CONSUMER.CREATE.{stream}.>
$JS.API.CONSUMER.INFO.{stream}.>
$JS.API.CONSUMER.DELETE.{stream}.>
$JS.API.CONSUMER.MSG.NEXT.{stream}.>
$JS.FC.{stream}.>
$JS.FC.*.*.{stream}.>
```

Publish lists, write macros add (2 subjects):

```text
{data}.>
$JS.API.STREAM.PURGE.{stream}
```

Subscribe lists, every macro: `{data}.>`.

### 4.1 Why this set (from nats.go v1.51.0 source)

The report's sketch listed six subjects. Reading the client code showed it is
too tight for real clients:

- `jsm.go` `upsertConsumer`: when the filter subject is empty or `>` the
  create subject is `CONSUMER.CREATE.<stream>.<name>` (no filter token), so
  `CONSUMER.CREATE.{stream}.*.{data}.>` would break multi-key watches. Older
  clients use the legacy `CONSUMER.CREATE.<stream>` endpoint.
- The `jetstream` package uses **pull** ordered consumers for some paths
  (`CONSUMER.MSG.NEXT`), the legacy API and the new KV watcher use **push**
  ordered consumers with flow control (`$JS.FC.`). The server has a v2 flow
  control reply format (`$JS.FC.<domain>.<accHash>.<stream>.<consumer>.*`)
  behind the `js_ack_fc_v2` feature flag; both formats are covered.
- `GetRevision` uses `DIRECT.GET.<stream>` with a body, `Get` uses
  `DIRECT.GET.<stream>.<subject>`; both are needed. Buckets without
  `allow_direct` and the legacy Object Store meta lookup use `STREAM.MSG.GET`.
- KV `PurgeDeletes` and Object Store `Put`/`Delete` call `STREAM.PURGE`, so a
  read/write macro without it breaks real clients.

Every subject is bound to the bucket's own stream, so the extra breadth costs
nothing in isolation between buckets. The mutation check during development
(removing `STREAM.PURGE` and `STREAM.MSG.GET`) made five end-to-end assertions
fail, which confirms the test guards the set.

## 5. Semantics and failure modes

Mirrors upstream tag handling:

| Situation | Allow list | Deny list |
|---|---|---|
| Argument resolves to no value | emit nothing | error (auth fails) |
| Value is not a valid bucket name (must be one or more of `A-Z a-z 0-9 _ -`) | skip that value | error |
| Unknown macro name / malformed argument | error (upstream "not defined") | error |
| Macro not the whole entry | error | error |
| Expansion exceeds `maxPermTemplateSubjectExpansions` (4096) | error | error |

An allow list that was non-empty before expansion and is empty afterwards gets
the upstream compensating `deny >`. This is why the hook runs **after** the
`subAllowWasNotEmpty`/`pubAllowWasNotEmpty` bookkeeping; placing it before would
turn "user has no tags" into "allow everything" for subscribe lists.

## 6. Code shape

- `server/auth_perm_macros.go`
  - `permMacros` table, `permMacroReadPubSubjects`, `permMacroWritePubSubjects`.
  - `parsePermMacro(op)` — is this `{{...}}` token a macro call?
  - `permMacroArgValues(arg, ujwt, acc)` — resolve the argument to bucket names.
  - `expandPermMacroList(list, isSub, failOnBadSubject, ujwt, acc)` — one list.
  - `expandPermissionMacros(lim, ujwt, acc)` — all four lists with the right
    (isSub, failOnBadSubject) pairs.
- `server/auth.go`, `processUserPermissionsTemplate`: four lines after
  `var err error`, calling `expandPermissionMacros` and returning its error.
  Both callers (operator-mode scoped signers in `auth.go`, and the auth callout
  in `auth_callout.go`) go through this function.

Macro output contains no `{{`, so the upstream `applyTemplate` pass leaves it
alone; non-macro entries reach upstream unchanged. Account lock use is the same
`acc.mu.RLock()` pattern upstream uses for `account-tag`/`account-name`.

Alternatives considered:

- Adding a list-kind parameter to the upstream `applyTemplate` closure: touches
  four upstream call sites plus the signature; the pre-pass needs one hook.
- A config knob to enable macros: rejected, the account JWT is the opt-in and
  upstream servers already reject the syntax, so there is no path where a macro
  grants more than intended.
- Accepting both `kvrw` and `kv-rw`: rejected as needless surface.

## 7. Security

- No new trust: expansion input is the verified account JWT template and the
  verified user JWT tags.
- Read-only macros allow consumer creation on the bucket's stream (required for
  watch), not data writes or purges.
- Bucket names are restricted to `A-Z a-z 0-9 _ -`, the rule official clients
  enforce for bucket names. The first implementation used the server's looser
  stream name rule; review found that a tag value such as `kv:{{tag(y)}}` with
  `y:*` passed it, was pasted into the emitted subjects, and was then expanded
  by the upstream template pass into `$KV.*.>` and `KV_*` API subjects. The
  strict character set closes that: no braces, wildcards, separators or `$`.
  `TestJWTTemplateMacroRejectsTemplateInjection` is the regression test.
- Old servers fail authentication for users whose template uses a macro; they
  never grant a superset.

## 8. Testing

`server/auth_perm_macros_test.go` (`TestJWTTemplateMacro*`, jwt_tests shard):

- Exact subject sets for `kvro`, `kvrw`, `objro`, `objrw` in publish and
  subscribe lists, allow and deny.
- Multiple tag values, passthrough of plain and `{{tag()}}` entries.
- All argument forms including literal and case-insensitive tag keys.
- Missing values fail closed (allow) or error (deny); invalid bucket names;
  template injection through tag values (`kv:{{tag(y)}}`, `kv:{{name()}}`).
- Whole-entry rule; unknown operation still hits the upstream error.
- Expansion cap.
- `TestJWTTemplateMacroKVObjectStoreEndToEnd`: operator mode, JetStream, a
  scoped signing key with all four macros; the scoped user exercises put / get /
  update / create / history / keys / watch / delete / purge / purge-deletes and
  Object Store put / get / list / delete through both the legacy and the
  `jetstream` nats.go APIs; read-only buckets reject writes; an untagged bucket
  is unreachable; raw subscribe is allowed only on the read/write bucket; a
  bucket without `allow_direct` exercises `STREAM.MSG.GET`.

## 9. Status

Implemented in one commit on `release/v2.14.7`: `server/auth_perm_macros.go`,
`server/auth_perm_macros_test.go`, the hook in `server/auth.go`, this spec,
`FORK-CHANGES.md` §4 and the `CLAUDE.md` fork test command.
