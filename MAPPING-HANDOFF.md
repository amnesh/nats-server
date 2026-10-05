# Connection-Scoped Inbound Mapping: Design Handoff

**Status:** investigation handoff, not an approved specification.

**Date:** 2026-09-18.

**Inspected baseline:** `release/v2.14.7` at
`e4ca104943d9d26075a01bdbc53c41c740f80c8a`.

`NATS-NEW-CHANGES.md` describes an older v2.14.1 baseline. Source links and
behavior in this handoff refer to the v2.14.7 worktree above.

No connection-scoped mapping or exclusion implementation exists at this
baseline. All connection-overlay behavior below is proposed unless explicitly
identified as existing account-mapping behavior.

This document preserves the full mapping discussion for the next maintainer or
agent. It labels accepted direction, current requirements, recommendations,
superseded ideas, and unresolved questions separately. Do not implement from
this handoff until the open semantics are approved and written as a design spec.

## Contents

1. [First question to resolve](#first-question-to-resolve)
2. [Purpose and current direction](#purpose-and-current-direction)
3. [Decision record](#decision-record)
4. [Illustrative wire shape](#illustrative-wire-shape)
5. [Current server behavior](#current-server-behavior)
6. [Why shared account mutation is unsafe](#why-shared-account-mutation-is-unsafe)
7. [Recommended connection overlay](#recommended-connection-overlay)
8. [Exclusions](#exclusions)
9. [Validation and grammar](#validation-and-grammar)
10. [Authorization and verifier trust](#authorization-and-verifier-trust)
11. [Admission, lifecycle, and compatibility](#admission-lifecycle-and-compatibility)
12. [Leaf interest and topology](#leaf-interest-and-topology)
13. [Performance and verification](#performance-and-verification)
14. [Required test matrix](#required-test-matrix)
15. [Open decisions and continuation](#open-decisions-and-continuation)

## First Question to Resolve

The latest proposal adds per-connection source exclusions such as:

```jsonc
["evt.*.UI.>", "tlm.log.>"]
```

The next discussion must answer:

> When an exclusion matches the original concrete wire subject, should the
> traffic remain deliverable under its original subject, or be blocked from
> crossing the leaf?

The current recommendation is **bypass ingress mapping and deliver unchanged**,
but the user has not approved it. Blocking is a distinct authorization feature.
Skipping only the account fallback is another distinct interpretation.

## Purpose and Current Direction

Every device publishes owner-local subjects such as `evt.health.changed`. The
hub needs a source-qualified form such as `dev.42.evt.health.changed`, but an
account mapping cannot derive a different device prefix for each leaf link.

The intended feature removes the need for:

- device-side republish streams;
- a relay process;
- reach-form subjects in device applications;
- JetStream as a prerequisite for ordinary events and telemetry.

The external authentication-verification service returns concrete mappings for
an admitted leaf, for example:

```text
evt.> -> dev.42.evt.>
tlm.> -> dev.42.tlm.>
```

The verifier owns identity interpretation, names, sources, and destinations.
The broker validates, compiles, and applies the rows. It does not need a device
ID model, claim-selection option, template language, or uniqueness registry.

The existing verification request already carries authenticated user, account,
JWT/connect, client, and TLS context for the external policy to construct those
concrete rows:
[server/authverify/req.go:25-55](server/authverify/req.go#L25-L55).

In the NCDL design that motivated the proposal:

- bridge transport publish grants move to the original wire form;
- the generated mapping catalog becomes verifier-policy input;
- source events and telemetry no longer require device-side mapping machinery;
- sink subjects can continue using ordinary owner account mappings where those
  are sufficient.

Request-info stamping and optional origin identity are independent concerns.
They are not required to implement subject mapping or publish provenance.

## Decision Record

### Accepted direction

- Hub authorization relies on the authenticated device/leaf identity. A mapped
  namespace is a verifier-policy label derived after authentication; the
  subject prefix is not itself proof of identity.
- Local user origin is optional audit information, default-off if ever added.
- V1 is LEAF-only.
- V1 is prefix-insertion-oriented, not the full generic transform language.
- The example `evt.>` to `dev.<id>.evt.>` was accepted in principle.
- Verifier mappings stay fixed until reconnect; reconnecting for policy changes
  is acceptable.
- Existing NATS leaf duplicate and loop behavior remains authoritative.
- Repeated mapped namespace names are allowed; there is no singleton, fencing,
  or broker dedup registry.

The exact prefix grammar still needs approval. Exact subjects, `*` sources,
tail placement, and literal-prefix constraints have not all been specified.

### Current requirement

- The external verifier returns fully populated `src` and `dest` rows.
- The external verifier owns device-name and subject construction policy.
- The broker has no required `DeviceID` representation.
- The broker validates and installs connection-local routing behavior.

### Recommendation awaiting approval

Use a connection-owned logical overlay:

1. Match an exclusion on the original concrete wire subject.
2. If matched, return a terminal `bypass` result that retains the original
   subject and cannot fall through to account mapping.
3. Otherwise, apply the first matching connection mapping.
4. Otherwise, consult the live account mapping table.
5. Rewrite at most once at this ingress stage.

Alternative exclusion meanings remain open:

- skip only verifier mappings, then allow account fallback;
- skip only account mappings, while still allowing a verifier mapping;
- bypass both layers and deliver the original subject unchanged;
- deny the message;
- delete overlapping mapping rows instead of matching concrete subjects.

### Superseded ideas

These were discussed, then replaced by verifier-owned concrete mappings:

- `ConnIDInJWT` and the later name `LeafConnIDInJWT`, using JWT `name` or
  signed `x.XUID`;
- the name `LeafDeviceIDClaim`;
- `LeafDeviceIDTemplate`;
- inline identity templates such as
  `evt.> -> dev.{{name()}}.evt.>`;
- broker `name`, `tag`, or `claim` macros for mapping identity expansion;
- a broker mapping-template registry;
- a broker device-ID value model;
- a device-ID uniqueness registry.

This history does not supersede or modify the fork's existing permission
template macros. Those remain supported and are outside this mapping design.

Earlier Change 2 proposed live re-verification and live mapping replacement.
The accepted current lifecycle supersedes that mapping portion: verifier rows
remain fixed until the physical connection reconnects. Existing account mapping
reload behavior is separate and remains an open interaction described below.

## Illustrative Wire Shape

This is a discussion aid, not an approved schema:

```jsonc
{
  "request_nonce": "...",
  "permissions": {
    "pub": { "allow": ["evt.>", "tlm.>"] }
  },
  "expires": 0,
  "mappings": [
    { "src": "evt.>", "dest": "dev.42.evt.>" },
    { "src": "tlm.>", "dest": "dev.42.tlm.>" }
  ],
  "exclude_mappings": ["evt.*.UI.>", "tlm.log.>"]
}
```

Open wire details:

- exclusion spelling (`exclude_mappings`, `exclude-mappings`, or other);
- bypass, block, or account-only exclusion semantics;
- row-count and encoded-byte caps;
- duplicate and overlap rules;
- capability negotiation.

The response currently contains only nonce, reject, reason, permissions, and
expiry: [server/authverify/req.go:55-64](server/authverify/req.go#L55-L64).

`ParseAuthVerifyResponse` uses ordinary `json.Unmarshal`, so an older broker
silently ignores unknown mapping fields:
[server/authverify/req.go:69-79](server/authverify/req.go#L69-L79).

That is unsafe when policy requires mappings. Capability behavior is therefore
a correctness requirement, not optional polish.

## Current Server Behavior

### Parser and permission order

For CLIENT and LEAF messages, the parser maps after reading the complete message
and before dispatch:
[server/parser.go:505-540](server/parser.go#L505-L540).

The current helper delegates directly to the shared account:
[server/client.go:4346-4353](server/client.go#L4346-L4353).

When mapping changes a subject:

- `c.pa.subject` holds the destination;
- `c.pa.mapped` retains the original wire subject.

CLIENT publish permission is checked on the already mapped subject:
[server/client.go:4363-4543](server/client.go#L4363-L4543).

LEAF processing calls `leafMsgAllowed` after parser mapping:
[server/leafnode.go:3298-3378](server/leafnode.go#L3298-L3378).

`leafMsgAllowed` deliberately checks `c.pa.mapped`, the original wire subject:
[server/leafnode.go:3384-3432](server/leafnode.go#L3384-L3432).

This asymmetry is load-bearing:

- CLIENT: mapped-subject permission.
- LEAF: original-wire-subject permission.

V1 remains LEAF-only. Extending mapping to CLIENT would reopen a provenance
problem: permission to publish a destination can also permit the client to spell
that destination directly without using the mapping.

### Mapping does not directly change accounts

`processInboundLeafMsg` matches the mapped subject against `c.acc.sl` and sends
gateways for the same account. Mapping changes the subject namespace inside the
bound account; it does not select another account or identity.

Existing service imports can move a message later. `processServiceImport` also
consults the destination account's mappings:
[server/client.go:4861-5164](server/client.go#L4861-L5164).

Therefore:

- one ingress rewrite forbids connection-to-account chaining in the parser;
- later service-import transformations remain a distinct stage;
- connection exclusions are not automatically inherited across an import;
- service-import interactions require explicit tests.

### Existing account selection

`selectMappedSubject` scans account rows in slice order and returns the first
exact or subset match; it does not choose most-specific:
[server/accounts.go:950-1027](server/accounts.go#L950-L1027).

This is useful implementation precedent, but the connection wire contract must
define whether response order is authoritative or overlaps are rejected.

## Why Shared Account Mutation Is Unsafe

`Account.AddMapping` delegates to `AddWeightedMappings`:
[server/accounts.go:788-909](server/accounts.go#L788-L909).

The method holds `Account.mu` while it validates and compiles a complete row,
then publishes the row into the shared slice before unlocking. Compilation
timing is not the isolation problem; publication into the account-wide table is.
If the same source exists, the method replaces that shared row. The table carries
no connection owner or lease.

Counterexample:

```text
Leaf A: evt.> -> dev.A.evt.>
Leaf B: evt.> -> dev.B.evt.>
```

If both responses call `Account.AddMapping`:

1. A installs the shared `evt.>` row.
2. B replaces it with the `dev.B` row.
3. A, B, normal clients, and future leaves now map to `dev.B`.
4. A's exclusions cannot reconstruct the overwritten `dev.A` row.
5. Removing B's row removes the only shared `evt.>` entry.

Different-source rows are also wrong because they outlive the admitting
connection and become visible to connections whose verifier never returned them.

The mutex makes this memory-safe. It does not make the policy connection-local.

### Shared ordering and removal

`RemoveMapping` swaps the final row into the removed slot:
[server/accounts.go:912-938](server/accounts.go#L912-L938).

With overlapping patterns, removal of an intervening unrelated row can change
which surviving row appears first. The connection contract must not accidentally
inherit unstable shared ordering.

### Do not borrow the account slice

Internal mappings contain destination slices and a cluster-keyed destination
map: [server/accounts.go:773-784](server/accounts.go#L773-L784).

Current code builds a new object before publishing its pointer under the lock,
but that is private implementation, not a public snapshot contract. Compile and
own a dedicated immutable connection representation. Do not retain or shallow
copy `a.mappings` outside its lock.

## Recommended Connection Overlay

Conceptual connection state:

```text
connMappings       immutable ordered compiled rows
mappingExclusions  immutable compiled source filters
hasConnMappingData atomic/read-safe admission presence
```

Selection must return an explicit tri-state result:

```text
no_match  no connection policy decided the subject; account fallback may run
mapped    a connection row produced a destination; selection is terminal
bypass    an exclusion retained the original subject; selection is terminal
```

Recommended selection, pending exclusion approval:

```text
original = wire subject

if exclusion matches original:
    return bypass(original)

if first connection row matches original:
    return mapped(connection transform(original))

return no_match

caller:
    result = select connection policy(original)
    if result is bypass:
        return original unchanged       // MUST NOT consult account mappings
    if result is mapped:
        return result.subject
    if account row matches original:    // only no_match reaches this branch
        return account transform(original)

return original, unchanged
```

Invariants:

- Match every layer against the original wire subject.
- Never feed one ingress result into the other ingress table.
- Own verifier rows on one connection.
- Keep verifier rows and exclusions fixed until reconnect.
- Preserve account mappings as a separate administrative layer.

### Worked selection example

Assume one leaf connection has:

```text
connection mapping: evt.> -> dev.A.evt.>
exclusions:          evt.*.UI.>, tlm.log.>
account mapping:     tlm.> -> shared.tlm.>
```

Under the recommended bypass-both tri-state semantics:

| Original wire subject | Connection result | Delivered subject |
|---|---|---|
| `evt.sensor.changed` | mapped | `dev.A.evt.sensor.changed` |
| `evt.panel.UI.open` | bypass | `evt.panel.UI.open` |
| `tlm.temperature` | no_match, account fallback | `shared.tlm.temperature` |
| `tlm.log.line` | bypass | `tlm.log.line` |

The final row is the important guard: `bypass` is not `no_match`, so
`tlm.log.line` must not fall through to the `tlm.>` account mapping.

### Live account fallback versus snapshot

Recommendation:

- verifier rows and exclusions are immutable for the connection;
- account fallback remains live across config/account-JWT reload;
- existing administrative mapping semantics remain intact.

The entire effective view is therefore not frozen; only the verifier layer is.

Snapshotting account mappings remains open but is not recommended because it:

- ignores later administrative removal and reload;
- retains or copies private transform structures;
- differs from current NATS operational expectations;
- complicates weighted and cluster-scoped destinations.

## Exclusions

Evaluate exclusions against the concrete original wire subject, not the mapping
row string.

Example:

```text
mapping:   evt.> -> dev.42.evt.>
exclusion: evt.*.UI.>
concrete:  evt.phone.UI.clicked
```

The exclusion decides behavior for the concrete publication. It should not
delete the entire `evt.>` definition merely because the patterns overlap.

Subject semantics matter:

- `>` matches one or more tokens, not zero.
- `evt.>` does not match bare `evt`.
- `evt.*.UI.>` needs one `*` token and at least one token after `UI`.

Reuse existing subject matching rather than inventing a similar matcher.

### Bypass is not deny

Under the current recommendation, an exclusion leaves the original subject
deliverable. That is routing control, not authorization.

If policy means “must not cross the leaf,” use LEAF publish permissions or
design an explicit deny feature. Do not let a mapping control silently revoke
transport rights.

### Account-only exclusion remains a real alternative

Bypassing all ingress mapping can skip operational account mappings, including
JetStream domain aliases generated by the server:
[server/jetstream.go:801](server/jetstream.go#L801).

This is why account-only exclusion must be evaluated explicitly. It must not be
silently chosen either.

More precisely, skip-verifier-only preserves account mappings such as
JetStream domain aliases. Skip-account-only can still apply a verifier mapping
but suppresses those aliases. Bypass-both suppresses both layers, including the
account aliases.

The four principal choices must stay separate during review:

| Exclusion meaning | Verifier mapping may run? | Account mapping may run? | Delivery |
|---|---:|---:|---|
| skip verifier only | no | yes | mapped by account or original |
| skip account only | yes | no | mapped by verifier or original |
| bypass both | no | no | original subject |
| deny | no | no | rejected/dropped per approved authorization semantics |

## Validation and Grammar

The generic compiler is broader than the accepted v1 direction:
[server/subject_transform.go:81-204](server/subject_transform.go#L81-L204).

Non-strict transforms support wildcard substitution, partition, random, split,
slice, left/right extraction, and omission of source wildcard tokens. Runtime
transformation is here:
[server/subject_transform.go:456-635](server/subject_transform.go#L456-L635).

Generic edge cases are unsuitable as implicit API semantics:

- empty source is treated as `>`;
- empty destination returns `(nil, nil)`;
- non-strict transforms can be non-invertible;
- weighted/cluster destinations are broader than the accepted v1 discussion.

Use a dedicated validator before compilation. It must enforce:

- nonempty source and destination;
- valid NATS subject syntax;
- the approved prefix-insertion relationship;
- no unapproved transform functions;
- deterministic duplicate/overlap handling;
- bounded row count and response bytes;
- all-or-none installation;
- complete compilation before admission.

Numeric caps remain open and should follow measurement, not guesswork.

`ValidateMapping` and `NewSubjectTransform` are precedent, but do not alone
enforce the v1 subset:
[server/sublist.go:1271-1310](server/sublist.go#L1271-L1310).

## Authorization and Verifier Trust

The existing feature is documented as narrow-only:
[FORK-CHANGES.md:28-31](FORK-CHANGES.md#L28-L31),
[FORK-CHANGES.md:192-216](FORK-CHANGES.md#L192-L216).

`NarrowPermissions` ensures the result cannot exceed the freshly validated JWT
or scoped-signer baseline. It unions denies and narrows allow/response behavior;
when nonempty base and override allow lists are disjoint, it preserves the base
because an empty allow list would mean unrestricted. An unrestricted base is a
different case:
[server/authverify/authverify.go:36-75](server/authverify/authverify.go#L36-L75).

Current override application only handles permissions and expiry:
[server/auth_verification.go:245-270](server/auth_verification.go#L245-L270).

Verifier mappings add a distinct authority:

- the leaf is already authenticated;
- the original wire subject must pass LEAF publish permission;
- the verifier chooses where that allowed message routes inside the account;
- the destination need not appear in the leaf's wire publish allow list.

This is routing authority, not direct JWT authority. It does not mint a user,
change the authenticated account, or grant permission to spell the destination
on the wire. It can still reach sensitive same-account services, and existing
imports/exports may move the message later.

Documentation must stop claiming a compromised verifier can only over-restrict.
If the external service is intentionally the mapping-policy authority, state
that trust and secure its system-account credentials accordingly.

Reserved destination prefixes should not be blanket-banned without a policy
decision. Legitimate operational mappings may use them. Add explicit positive
and negative tests for sensitive destinations.

## Admission, Lifecycle, and Compatibility

### Scope and feature gate

Existing authentication verification runs only when enabled and after verified
JWT authentication. It covers CLIENT and LEAF while excluding the system
account, in-process connections, and accounts delegated to external auth:
[server/auth_verification.go:28-55](server/auth_verification.go#L28-L55).

V1 connection mappings narrow that scope further to authenticated LEAF
connections. A supporting server that recognizes mappings or exclusions must
reject the response when mapping support is disabled, the connection kind is
wrong, or the connection is otherwise outside mapping scope. It must not
silently ignore recognized policy fields.

### Choose one reply before mutation

`processAuthVerification` currently parses, applies, and caches a response before
the nonblocking first-reply channel send decides whether that callback wins:
[server/auth_verification.go:109-183](server/auth_verification.go#L109-L183),
especially lines 120-130 and 151-158.

With multiple responders or a late duplicate, a losing callback can mutate
connection state before its channel send is dropped. This was derived from
source inspection, not reproduced at runtime.

Recommended lifecycle:

1. Reply callbacks validate and offer immutable candidates.
2. The waiting auth path selects exactly one candidate.
3. It stages every component, then commits permissions, expiry, mappings,
   exclusions, and cache binding all-or-none before signaling success.
4. Timeout or rejection installs nothing.
5. Late callbacks, including a callback already in flight when timeout wins,
   cannot mutate the connection.

### Same-buffer visibility

The read loop snapshots account mapping presence once per socket read:
[server/client.go:1554-1561](server/client.go#L1554-L1561).

CONNECT and the first LMSG can be in one already-read buffer. Verification may
install connection mappings while CONNECT is processed; waiting for the next
read can let the first message bypass them.

The parser processes CONNECT synchronously before continuing through that input
buffer, and client/leaf authentication runs inside that path:
[server/parser.go:950-975](server/parser.go#L950-L975),
[server/client.go:2389-2405](server/client.go#L2389-L2405).

Install a fully compiled immutable pointer before admission resumes and publish
presence through parser-visible atomic/read-safe state. The parser condition must
consider account and connection mapping presence independently.

Because verifier rows are fixed until reconnect, no post-admission table swap is
needed. Account mappings remain dynamic separately.

### Cached verdict and second CONNECT

The cache currently retains only permissions and expiry:
[server/auth_verification.go:58-103](server/auth_verification.go#L58-L103).

Reload reauthentication starts from a newly validated JWT/scoped-signer
baseline and reapplies the cached override; it does not snapshot final effective
permissions. A second CONNECT can also change account registration in current
client handling:
[server/client.go:2381-2405](server/client.go#L2381-L2405).

Open lifecycle requirements:

- bind cached mapping state to verified identity, raw JWT, and account as needed;
- define second-CONNECT behavior explicitly;
- retain exactly one admitted table on one physical connection;
- a new physical reconnect invokes the verifier again;
- re-registration must not clear, duplicate, or transfer a table accidentally.

### Capability negotiation

Unknown response fields are ignored by old servers. Safe behavior requires:

1. Mapping-capable servers advertise an explicit capability in the request.
2. The verifier sends required mappings only when that capability is present.
3. If mappings are required and capability is absent, the verifier uses the
   already understood `reject` field.
4. A supporting server rejects mapping fields when support is disabled, rather
   than silently admitting unmapped policy.

Version alone is unreliable because fork features can be cherry-picked.

The feature remains off by default. A capability gate is not the superseded
device-ID/template configuration.

## Leaf Interest and Topology

Leafs send only for advertised interest. Destination interest does not reverse
automatically into the mapping source.

`initLeafNodeSmapAndSendSubs` adds actual subscriptions, service-import sources,
and every account mapping source:
[server/leafnode.go:2448-2609](server/leafnode.go#L2448-L2609).

Account mapping sources are advertised even without a current destination
subscriber. Existing behavior favors correctness over minimum bandwidth.

Connection mapping sources must be added only to the owning leaf's `smap`.
Because verifier rows are fixed until disconnect:

- validate and compile the complete connection policy before initial `smap`
  construction and LS+ emission;
- add owners during that connection's `smap` initialization;
- discard them when the connection closes;
- do not update every leaf in `Account.lleafs`;
- do not use a live verifier-row LS+/LS- path.

Existing leaf permissions and isolation rules still gate which interest may be
advertised. Mapping policy does not override those controls.

### Negative interest is not expressible

Leaf interest is positive. It cannot express:

```text
evt.> minus evt.*.UI.>
```

A partial exclusion still requires broad `evt.>` interest for non-excluded
traffic. Excluded UI messages may cross the link and bypass mapping locally.
That is correct under bypass semantics but costs bandwidth. A whole-row
exclusion can omit the synthetic owner; a partial overlap cannot precisely
prune the wildcard.

The positive LS+/LS- protocol is emitted and processed here:
[server/leafnode.go:2888-2918](server/leafnode.go#L2888-L2918),
[server/leafnode.go:3085-3130](server/leafnode.go#L3085-L3130).

Even a fully covered exclusion may omit only this connection mapping's
synthetic owner. Genuine subscriptions, imports, account mappings, and other
owners of the same key must remain.

### Interest ownership must balance

The same source can be owned by a real subscription, service import, account
mapping, connection mapping, or queue-qualified key.

`forceAddToSmap` only ensures nonzero; it does not increment an existing count:
[server/leafnode.go:2768-2782](server/leafnode.go#L2768-L2782).

`forceRemoveFromSmap` decrements and sends LS- at zero:
[server/leafnode.go:2785-2804](server/leafnode.go#L2785-L2804).

Derived hazard, not runtime-reproduced:

1. A connection source contributes count 1.
2. An account mapping with the same source force-adds but does not increment.
3. Account removal decrements to zero.
4. False LS- is sent although the connection owner remains.

Use explicit owner accounting or recomputation. Keep queue keys distinct.

### Namespace collisions and duplicate links

The broker does not interpret prefixes as unique identities. External policy
owns collisions.

- Same names in one account intentionally merge subjects.
- Same names in different accounts remain isolated.
- Cross-connection publication order is not total.
- Independent duplicate publications are not deduplicated.

Leaf transport duplicate detection remains based on remote server, cluster,
bound account, and remote account—not mapping names:
[server/leafnode.go:1963-2146](server/leafnode.go#L1963-L2146).

Multiple URLs in one remote are failover choices, not parallel links:
[server/leafnode.go:691-876](server/leafnode.go#L691-L876).

Clustered spoke servers may each hold active uplinks. Existing routing suppresses
topology-loop duplicates for one routed publish; two independent publishers still
produce two messages. No fencing or dedup belongs in v1.

## Performance and Verification

### Performance design targets

These are targets for the unimplemented feature, not measured/current
guarantees.

Unconfigured fast-path targets:

- constant-time presence gating over both connection policy and existing
  account mapping state, without promising a precise check count;
- no JWT parsing or macro expansion per message;
- no verifier lookup;
- no feature allocation.

Mapped-path targets:

- compile once at admission;
- scan a bounded immutable row set;
- tokenize no more than necessary;
- transform once at ingress;
- preserve current account fallback on a miss.

Measure disabled, zero-row, exact/wildcard hit and miss, exclusion hit and miss,
account fallback, row-count scaling, allocations, throughput, CPU, median/tail
latency, admission compile latency, retained bytes per connection and per row at
large connection counts, and link bytes under partial exclusions.

`BenchmarkCoreRequestReply` is a useful synchronous baseline:
[server/core_benchmarks_test.go:31-97](server/core_benchmarks_test.go#L31-L97).

`BenchmarkPublish` is asynchronous and lacks a timed flush suitable for clean
attribution without adjustment:
[server/benchmark_publish_test.go:25-185](server/benchmark_publish_test.go#L25-L185).

No mapping measurement exists yet. Do not borrow unrelated request-stamping
numbers as mapping evidence.

### Existing verification performed

Command:

```sh
rtk go test ./server \
  -run '^(TestLeafNodeServerReloadSubjectMappings|TestLeafNodeLMSGPermissionsUseWireSubjectNotMapped)$' \
  -count=1 -timeout=3m
```

Result: `Go test: 2 passed in 1 packages`, exit code `0`.

These validate existing account behavior only:

- source-interest propagation/reload:
  [server/leafnode_test.go:9478-9533](server/leafnode_test.go#L9478-L9533);
- original-wire LEAF permission with mapped delivery:
  [server/leafnode_test.go:10884-10956](server/leafnode_test.go#L10884-L10956).

No feature code, feature test, race run, full suite, benchmark, or 32-bit run has
been performed.

Graph evidence used project `work-github-nats-server`, full generation
`2026-09-17T10:27:24Z`. Relevant files reported `metadata_match` and
`no_recorded_issue`. This is best-effort, not proof of completeness; material
source was read directly.

## Required Test Matrix

### Admission and compatibility

- No mapping fields preserve current behavior.
- Valid rows install atomically and preserve approved order.
- Invalid/empty source or destination rejects admission.
- Unsupported transform syntax rejects admission.
- Duplicate and overlap behavior matches approved rules.
- Row/byte caps fail closed.
- Mixed valid/invalid lists install nothing.
- Disabled feature is behaviorally unchanged.
- Required mappings reject when capability is absent.
- A supporting server rejects fields when support is disabled.
- Recognized mappings/exclusions reject on CLIENT, system, in-process,
  external-auth, and every other out-of-scope connection.
- Old-server compatibility cannot silently admit required unmapped policy.

### Selection and isolation

- First connection match follows approved order.
- Connection miss uses live account fallback.
- Connection hit does not chain into account mapping.
- Account result does not chain into connection mapping.
- Two leaves use the same source with different destinations.
- One leaf cannot alter another leaf or normal client.
- Disconnect cleanup cannot remove another connection's row.
- Account reload interaction matches live-fallback decision.
- Connection mappings work when the account has no mappings at admission.
- Removing the account's last mapping does not disable a remaining connection
  mapping or its parser-presence signal.

### Exclusions

- Match the concrete original wire subject.
- Hit follows approved bypass/block/account-only semantics.
- Miss allows connection mapping and then account fallback.
- `>` bare-prefix boundary is tested.
- Partial wildcard exclusion retains correct positive interest.
- Broad exclusion interaction with JetStream domain aliases is explicit.
- An exclusion-only policy works correctly when account mappings exist.
- Alternating bypass and mapped messages in one parser buffer preserve the
  tri-state result for each message independently.

### Authorization and downstream routing

- Allowed wire source reaches destination.
- Disallowed wire source remains denied.
- Direct mapped form on the wire is denied unless independently granted.
- Sensitive same-account destinations have positive and negative tests.
- Mapping does not change account identity.
- Service imports, routes, gateways, and JetStream interactions are explicit.

### Interest, lifecycle, and concurrency

- Only the owning leaf receives connection-source synthetic interest.
- Destination-only local interest receives mapped messages.
- No-watcher behavior matches conservative-interest documentation.
- Subscription/import/account/connection owners share a source safely.
- Owner removal never emits false LS-.
- Adding and removing an account mapping with the identical source preserves
  the connection owner's interest throughout.
- Queue-qualified keys remain distinct.
- CONNECT plus first LMSG in one buffer maps correctly.
- Timeout/reject install nothing.
- Double/late replies cannot mutate after selection.
- Reload and second CONNECT follow approved cache binding.
- A second CONNECT that changes user principal or account cannot inherit the
  prior principal/account's mapping table.
- Reconnect obtains a fresh table.
- Close releases connection policy state.
- Race detector covers account reload with mapped leaf traffic.
- Multi-hop leaf/route ingress documents and tests whether a message can be
  transformed again at a later ingress boundary; one rewrite applies per
  defined stage, not silently once for the message's entire lifetime.

### Performance and platform

- Disabled-path regression is measured.
- Hit/miss/exclusion/fallback benchmarks cover row counts.
- Allocations, CPU, throughput, and tail latency are recorded.
- Partial-exclusion leaf-byte overhead is measured.
- Relevant race, Linux 386, and Windows compile gates pass.

## Open Decisions and Continuation

### Open decisions

1. Does exclusion bypass mapping and deliver unchanged, or block?
2. Does it bypass both layers, skip verifier mappings only, or skip account
   mappings only?
3. What is the exact v1 prefix grammar?
4. Are overlaps ordered or rejected?
5. Are duplicate sources rejected?
6. What are row-count and response-byte caps?
7. What is the final exclusion field spelling?
8. How is capability advertised and enabled default-off?
9. How are mappings bound into cached verification state?
10. What does second CONNECT do?
11. Is live account fallback approved?
12. Are reserved operational destinations allowed?
13. Which service-import and JetStream interactions are v1-supported?
14. What observability reports validation and use without leaking policy?

### Continuation order

1. Resolve bypass versus block.
2. Resolve bypass-both versus verifier-only versus account-only exclusion.
3. Specify the exact v1 grammar with accepted and rejected examples.
4. Decide duplicate, overlap, and row-order rules.
5. Decide capability negotiation and default-off configuration.
6. Decide cache binding and second-CONNECT lifecycle.
7. Confirm connection overlay plus live account fallback.
8. Specify balanced source-interest ownership.
9. Write an approved design under `docs/superpowers/specs/`.
10. Obtain user review of that spec.
11. Only then write an implementation plan and code.

Completion means every open decision has one explicit answer, every invariant has
a corresponding test, and verifier rows never physically mutate the shared
`Account.mappings` table unless the user deliberately rejects this recommendation
after reviewing the counterexample.

## Final Guardrails

- This is a handoff, not approval.
- The verifier owns concrete names and rows.
- Broker identity templating is outside the current requirement.
- Verifier rows remain connection-owned and fixed until reconnect.
- LEAF authorization remains on the original wire subject.
- Ingress rewrites at most once.
- Account fallback and later service-import mapping are separate stages.
- Interest ownership is explicit and balanced.
- Unconfigured behavior remains off and cheap.
- Mapping-dependent policy fails closed when capability is absent.
- Implementation waits for approved exclusion and grammar semantics.
