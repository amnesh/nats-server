# Design: Permission Template Macros v2 (complete macro set)

- **Date:** 2026-09-17
- **Status:** Approved by the fork owner. Implementation in progress, see §11.
- **Supersedes:** `2026-09-17-permission-template-macros-design.md` (v1: `kvro`,
  `kvrw`, `objro`, `objrw` only). Everything in v1 that is not restated here
  still holds: hook placement, fail-closed rules, whole-entry rule, no config
  knob, template-injection guard.
- **Component:** `server/auth_perm_macros.go`, hook in `processUserPermissionsTemplate`
- **Author/driver:** chezgi (with Claude Code)

---

## 1. Goal

One template entry per JetStream resource role. A scoped signing key template
in the account JWT names the role and the resource, the user JWT carries only
tags, and the server expands the full subject set at connect time. The set
must be complete for the nats.go legacy and `jetstream` APIs, must not grant
anything outside the named resource, and must stay simple to explain.

## 2. Decisions recorded

| # | Question | Decision |
|---|---|---|
| 1 | Consumer-level macro | Yes: `jsconsumer` (use) and `jsconsumeradmin` (own) |
| 2 | Multi-argument syntax | Positional arguments, cartesian product when several resolve to lists |
| 3 | Admin set | Small set plus `SNAPSHOT` and `RESTORE` |
| 4 | Key/subject scoped macros | Not now |
| 5 | JetStream domain support | Yes, as a trailing `domain=` argument on every macro, no new macros |
| 6 | `jswrite` | No. Stream publish subjects are ordinary template entries |
| 7 | Read set | One 16-subject read set shared by buckets and streams |
| 8 | Read-only users and consumers | Keep consumer create/delete in the read set, document it, offer `jsconsumer` for isolation |
| 9 | "All buckets" / "all streams" | `*` accepted as a literal argument only, never from a tag; bucket wildcards grant the API of every stream (§3) |

## 3. Grammar

```text
{{ MACRO ( ARG [, ARG] [, domain=ARG] ) }}
```

- `MACRO` is one of the names in §4, matched case-insensitively.
- `ARG` is one of: `tag(key)`, `account-tag(key)`, `name()`, `subject()`,
  `account-name()`, `account-subject()`, or a literal. Tag keys are matched
  case-insensitively. Whitespace around every part is trimmed.
- Arguments are split on commas at parenthesis depth zero. Positional
  arguments come first, then the optional named argument `domain=`. Any other
  named argument, a wrong number of positional arguments, or a missing
  argument is an error of the upstream form `template operation in %q: %q is not defined`.
- Every argument resolves to a list of values. The macro expands once per
  element of the cartesian product of all lists. Tags produce lists, the
  other forms produce one value.
- Every value must match `[A-Za-z0-9_-]+`. This is the bucket-name rule of the
  official clients and it is stricter than the server's stream name rule on
  purpose: the emitted subjects pass through the upstream template pass
  afterwards, so a value must not carry `{{`, a wildcard, or a separator.
- Tag values are used as they appear in the JWT. `nsc` and the `jwt` library
  lowercase tags on add, and stream names are case-sensitive, so a resource
  with an uppercase name can only be named by a literal argument.
- The literal `*` is accepted as a positional argument and means every
  resource of that kind: `{{jsread(*)}}`, `{{kvrw(*)}}`,
  `{{jsconsumer(orders, *)}}`. It is a template author's decision, so `*`
  from a tag or any other value operation is still rejected. NATS wildcards
  match whole tokens, so the stream token becomes `*` and the data subject
  becomes `$KV.*.>` or `$O.*.>`. A bucket wildcard therefore grants the
  JetStream API of **every stream in the account**, not only of buckets,
  because the bucket name lives inside the stream token (`KV_*` is a literal,
  not a wildcard). `jsread(*)` and `jsadmin(*)` are exact. Prefix forms such
  as `team-*`, and `>`, are rejected. `*` is not accepted for `domain=`.
- The macro token must be the whole entry. Two macro tokens, or a macro
  inside a longer subject, is an error.
- Missing values (a tag with no match, or an invalid value) emit nothing in
  an **allow** list and are an error in a **deny** list, as upstream tags do.
  The upstream compensating `deny >` for an allow list that becomes empty
  still applies, because the hook runs after that bookkeeping.
- The total per list is capped by the upstream `maxPermTemplateSubjectExpansions` (4096).

## 4. Macro table

`b` bucket, `s` stream, `c` consumer. Levels are cumulative. "error" in the
subscribe column means the macro is rejected in `sub.allow` / `sub.deny`,
because the resource has no derivable data subject.

| Macro | Positional args | Stream | Publish list | Subscribe list |
|---|---|---|---|---|
| `kvro(b)` | 1 | `KV_b` | read | `$KV.b.>` |
| `kvrw(b)` | 1 | `KV_b` | read + write | `$KV.b.>` |
| `kvadmin(b)` | 1 | `KV_b` | read + write + admin | `$KV.b.>` |
| `objro(b)` | 1 | `OBJ_b` | read | `$O.b.>` |
| `objrw(b)` | 1 | `OBJ_b` | read + write | `$O.b.>` |
| `objadmin(b)` | 1 | `OBJ_b` | read + write + admin | `$O.b.>` |
| `jsread(s)` | 1 | `s` | read | error |
| `jsadmin(s)` | 1 | `s` | read + purge + admin | error |
| `jsinfo()` | 0 | none | info | error |
| `jsconsumer(s, c)` | 2 | `s` | consumer use | error |
| `jsconsumeradmin(s, c)` | 2 | `s` | consumer use + consumer admin | error |

Every macro also accepts `domain=`. See §6.

## 5. Subject sets

Placeholders: `{api}` is `$JS.API` without a domain and `$JS.<domain>.API`
with one. `{dom}` is `*` without a domain and the domain name with one.
`{stream}` and `{consumer}` are the resolved names with the bucket prefix
applied. `{data}` is `$KV.b` or `$O.b`.

### 5.1 read (16 subjects)

```text
{api}.STREAM.INFO.{stream}
{api}.STREAM.MSG.GET.{stream}
{api}.DIRECT.GET.{stream}
{api}.DIRECT.GET.{stream}.>
{api}.CONSUMER.CREATE.{stream}
{api}.CONSUMER.CREATE.{stream}.>
{api}.CONSUMER.DURABLE.CREATE.{stream}.>
{api}.CONSUMER.INFO.{stream}.>
{api}.CONSUMER.NAMES.{stream}
{api}.CONSUMER.LIST.{stream}
{api}.CONSUMER.DELETE.{stream}.>
{api}.CONSUMER.MSG.NEXT.{stream}.>
$JS.ACK.{stream}.*.*.*.*.*.*
$JS.ACK.{dom}.*.{stream}.*.*.*.*.*.>
$JS.FC.{stream}.*.*
$JS.FC.{dom}.*.{stream}.*.*
```

The ack and flow-control patterns use exact token counts. The v1 ack subject
has 9 tokens with the stream name third; the v2 ack subject has 11 or more
tokens with the stream name fifth (`$JS.ACK.<domain>.<account hash>.<stream>.<consumer>.<delivered>.<sseq>.<cseq>.<ts>.<pending>`).
A pattern with a trailing `>` for one format could match the other format
for another stream, for example `$JS.ACK.*.*.7.>` matches v1 acks of every
stream whose delivered count is 7. Exact counts make the two formats unable
to cross-match, without any server state. Flow control v1 has 5 tokens and
v2 has 7, with the same reasoning.

### 5.2 write

```text
{api}.STREAM.PURGE.{stream}
<data publish subject>            # buckets only, see below
```

Data publish subject: `$KV.b.>` for KV, `$O.b.>` for Object Store. With a
domain, KV becomes `$JS.<domain>.API.$KV.b.>` (§6). Object Store stays `$O.b.>`.

### 5.3 admin (7 subjects)

```text
{api}.STREAM.CREATE.{stream}
{api}.STREAM.UPDATE.{stream}
{api}.STREAM.DELETE.{stream}
{api}.STREAM.MSG.DELETE.{stream}
{api}.STREAM.SNAPSHOT.{stream}
{api}.STREAM.RESTORE.{stream}
{api}.INFO
```

`{api}.INFO` is included because nats.go calls account info before it creates
a bucket. `jsadmin` is read + `STREAM.PURGE` + admin (no data subject).

### 5.4 info (3 subjects)

```text
{api}.INFO
{api}.STREAM.NAMES
{api}.STREAM.LIST
```

### 5.5 consumer use (7 subjects)

```text
{api}.STREAM.INFO.{stream}
{api}.CONSUMER.INFO.{stream}.{consumer}
{api}.CONSUMER.MSG.NEXT.{stream}.{consumer}
$JS.ACK.{stream}.{consumer}.*.*.*.*.*
$JS.ACK.{dom}.*.{stream}.{consumer}.*.*.*.*.>
$JS.FC.{stream}.{consumer}.*
$JS.FC.{dom}.*.{stream}.{consumer}.*
```

The user can bind to and consume from that one consumer. The user cannot
create, change, or delete it, so a filter set by the administrator holds.

The v2 ack pattern pins the consumer token, so it has one `*` less than the
read set pattern of §5.1: a v2 ack subject has 11 tokens, the consumer token
is the sixth, and the trailing `>` matches the last one.
`TestJWTTemplateMacroConsumerEndToEnd/ack_v2` proves the pattern.

### 5.6 consumer admin (adds 7 subjects)

```text
{api}.CONSUMER.CREATE.{stream}.{consumer}
{api}.CONSUMER.CREATE.{stream}.{consumer}.>
{api}.CONSUMER.DURABLE.CREATE.{stream}.{consumer}
{api}.CONSUMER.DELETE.{stream}.{consumer}
{api}.CONSUMER.PAUSE.{stream}.{consumer}
{api}.CONSUMER.UNPIN.{stream}.{consumer}
{api}.CONSUMER.RESET.{stream}.{consumer}
```

The user owns that one consumer and chooses its filter. This level isolates
users from each other; it does not restrict data.

### 5.7 Sizes and capacity

| Macro | Publish subjects | Buckets or streams per user under the 4096 cap |
|---|---|---|
| `kvro`, `objro`, `jsread` | 16 | 256 |
| `kvrw`, `objrw` | 18 | 227 |
| `kvadmin`, `objadmin` | 25 | 163 |
| `jsadmin` | 24 | 170 |
| `jsconsumer` | 7 | 585 |
| `jsconsumeradmin` | 14 | 292 |

## 6. Domains

Without `domain=`, the macro covers the server's own domain. The server adds
account mappings `$JS.<local domain>.API.<x>` to `$JS.API.<x>` and
`$JS.<local domain>.API.$KV.>` to `$KV.>` (`generateJSMappingTable`), and the
parser applies mappings before the publish permission check
(`parser.go` mapping, then `client.go` `pubAllowedFullCheck`). So a local
client that sets the API prefix to the local domain is already covered.

`domain=NAME` is for a client that targets a **remote** domain, for example a
spoke client calling the hub through a leaf node. Those subjects are not
mapped locally, so the permission check sees the prefixed subject. With
`domain=hub` the macro emits the same set with:

- `{api}` = `$JS.hub.API`.
- `{dom}` = `hub` in the v2 ack and flow-control patterns. The account hash
  stays `*`, because the hub may register the account under another name.
  v1 patterns have no domain token and do not change.
- KV data publish subject `$JS.hub.API.$KV.b.>`. This is what nats.go publishes
  to when an API prefix is set (`kvSubjectsPreDomainTmpl`), and the hub maps
  it back to `$KV.b.>`. Reads keep `$KV.b.>` inside direct-get and
  consumer-create subjects, because those name the stream's real subjects.
- Object Store data publish subject stays `$O.b.>`. nats.go does not prefix
  it, and the server has no working domain mapping for `$O`.
- Subscribe lists stay `$KV.b.>` and `$O.b.>`.

`domain=` accepts a literal or a value operation, so `domain=tag(dom)` gives
one set per domain tag. A user who needs a resource both locally and in a
remote domain gets two entries. Domain values follow the `[A-Za-z0-9_-]+` rule.

## 7. Read-only users and consumers

Reading a stream always goes through a consumer, except direct get. So the
read set must include consumer creation. Consequences for a read-only user on
the resource's stream:

- Can create any consumer: push or pull, ephemeral or durable, any filter.
- Can get info and list names.
- Can delete any consumer on that stream, including consumers other users created.
- Can pull from and ack on any consumer on that stream, including consumers
  other users created. This can take messages away from another user, or ack
  messages that user did not process.

The last two points are inherent to per-stream permissions. Consumer names
are one token, so no subject pattern can express "only consumers this user
created". Push consumers deliver to an inbox chosen by the creating client,
so they are not exposed this way; pull consumers are, because `MSG.NEXT` is
addressed by consumer name.

KV and Object Store clients use ephemeral push consumers only today. A
smaller bucket read set without pull and ack subjects would work today, but
nats.go plans to move KV watch to pull-based ordered consumers, and that
would silently break read-only users. The read set therefore stays shared.
Users who must not interfere with each other get `jsconsumer` or
`jsconsumeradmin` instead of a stream-wide read macro.

## 8. Security

- No new trust. Expansion input is the verified account JWT template and the
  verified user JWT tags.
- Every emitted subject is bound to the named stream, and for consumer
  macros also to the named consumer. The server enforces the stream name in
  consumer create requests (`streamName != req.Stream`).
- Names are restricted to `[A-Za-z0-9_-]+`, which blocks template injection
  through tag values (v1 finding, regression test `TestJWTTemplateMacroRejectsTemplateInjection`).
- Exact-token ack and flow-control patterns prevent cross-stream acks (§5.1).
- Old servers reject templates that use macros, so they never grant more.

## 9. Code shape

`server/auth_perm_macros.go` stays the only feature file; the four-line hook
in `server/auth.go` does not change.

- `permMacro` describes one macro: `streamPrefix`, `subjectPrefix`,
  `dataViaAPI` (the data publish subject of a remote domain goes through that
  domain's API prefix, which is true for KV only), `args` (positional count:
  0, 1 or 2), and level flags `write`, `admin`, `info`, `consumer`,
  `consumerAdmin`.
- Subject groups are `[]string` templates with the placeholders of §5,
  expanded by `strings.ReplaceAll`.
- `parsePermMacro(op)` returns the macro, the positional argument strings and
  the optional domain argument string. It splits on depth-zero commas.
- `permMacroArgValues(arg, ujwt, acc)` is unchanged from v1 and returns the
  value list of one argument.
- `expandPermMacroList` resolves all arguments, validates every value, forms
  the cartesian product, and emits one subject set per tuple, with the cap
  check per tuple.
- Ordering of emitted subjects is deterministic: groups in the order read,
  write, admin; tuples in argument order.

## 10. Tests

All tests are `TestJWTTemplateMacro*` in `server/auth_perm_macros_test.go`
and new `server/auth_perm_macros_*_test.go` files, so they run in the
`jwt_tests` shard. Upstream test files are not modified.

Unit tests: exact subject sets for every macro and level, in publish and
subscribe lists, allow and deny; argument forms; cartesian products; missing
and invalid values; whole-entry rule; unknown macros; wrong argument counts;
unknown named arguments; the cap; template injection; domain forms.

End-to-end tests, operator mode with a scoped signing key and real nats.go
clients (legacy and `jetstream` APIs), with negative cases that assert a
permission violation was seen:

1. Buckets read/write (exists): `TestJWTTemplateMacroKVObjectStoreEndToEnd`.
2. `kvadmin`, `objadmin`, `jsread`, `jsadmin`, `jsinfo`: create/delete
   buckets, seal an object store, consume a stream with a durable pull
   consumer and ack, purge and update a stream, list streams. Run once with
   the default ack format and once with `feature_flags { js_ack_fc_v2: true }`
   so both ack patterns are exercised.
3. `jsconsumer` and `jsconsumeradmin`: an administrator creates a filtered
   durable; a `jsconsumer` user fetches and acks but cannot delete or
   recreate it; a `jsconsumeradmin` user creates, uses and deletes its own
   consumer; neither can touch a third consumer.
4. `domain=`: a hub server and a spoke server with different JetStream
   domains connected by a leaf node; a spoke client with `nats.Domain("hub")`
   uses a hub bucket through `kvrw(..., domain=hub)`; the same template
   without `domain=` fails.

## 11. Implementation plan

Four commits on `release/v2.14.7`, each with tests and doc updates
(`FORK-CHANGES.md` §4):

1. Shared read set with exact-token ack patterns, admin set, `kvadmin`,
   `objadmin`, `jsread`, `jsadmin`, `jsinfo`, subscribe-list rule, zero-argument macro. **Done.**
2. Argument list parsing, cartesian product, `jsconsumer`, `jsconsumeradmin`. **Done.**
3. `domain=` argument. **Done.**
4. Literal `*` argument. **Done.** Implemented as a positional-only
   exception before value resolution, so `*` from tags and for `domain=`
   still fails the name rule. Note that `*` stays invalid for `domain=` (§3), so
   the literal wildcard exception must apply to positional arguments only.
