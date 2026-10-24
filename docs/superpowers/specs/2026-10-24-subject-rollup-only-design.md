# Subject-only rollup

Status: implementation and local verification.

## Constraint

The NCDL owner permits fork changes and rejects a new authorization hook for
each message. A KV writer with an allowed key subject can currently send
`Nats-Rollup: all` and remove foreign keys. The server must reject that operation
without a principal lookup or a new callback.

## Policy

Add `FeatureFlagJsSubjectRollupOnly`, with the key `js_subject_rollup_only`.
The default is `false`. Set one immutable value on `jetStream` at startup.
Feature flag changes require restart under the existing reload rule.

When enabled, reject `Nats-Rollup: all` in the existing validation paths for
ordinary, atomic-batch, and fast-batch client publications. Use the existing
rollup error, `JSStreamRollupFailedF`. Permit `Nats-Rollup: sub` under the current
stream rules. Keep stream purge API permissions unchanged.

Apply the policy to all streams. A rule based on a KV stream name or subject
prefix can miss a custom stream or a subject transform. The global policy also
covers streams created after startup. Every cluster peer must use the same
policy.

Preserve committed Raft application, recovery, and trusted source or mirror
replay. A source can retain a historical stream-rollup header. Every publishing
origin that accepts key-scoped writers must enforce the policy. The flag does
not provide a local rejection rule for trusted source replay.

## Integration

NCDL generates a required flag when an account role or bundle has a key-scoped
KV write. NCDL topology refers directly to the exported fork constant. An older
linked fork must fail to build, because an unknown flag string alone is silently
ignored by the broker. A separately configured broker must enable the policy
before it accepts these credentials.

## Verification

`TestJetStreamSubjectRollupOnly` covers normal writes, subject rollup, rejected
stream rollup, retained foreign data, and privileged API purge. It covers memory
and file storage, standalone and clustered streams, and all three publish paths.
The default-policy cases prove that an unconfigured server keeps upstream
behavior.

`TestJetStreamSubjectRollupOnlyLifecycle` covers restart, failed reload,
subject transforms, a changed stream leader, and historical source replay.
