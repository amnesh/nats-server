# Native inbox capture policy

## Policy and startup value

`FeatureFlagJsRejectInboxCapture` names `js_reject_inbox_capture`. The default is false.
JetStream captures the option in `jetStream.rejectInboxCapture` at startup. Every policy check reads this retained value.
A feature flag change requires restart. All cluster peers and ingress servers must clear forwarded origin markers before enforcement starts.
Enable the flag on every peer and every origin that accepts ordinary stream-manager credentials.

When the policy is enabled, an ordinary stream create, update, or restore cannot capture `_INBOX.>`.
The API returns `JSStreamInvalidConfigF`, code 10052, with `ErrJSStreamInboxCapture` text.
This feature adds no generated error code, API subject, authorization callback, or publication hook.

## Origin proof

The exemption requires an authenticated `CLIENT` with `iproc` true and no publish or subscribe allow or deny tree.
An explicit `>` tree remains a restriction. A grant session uses its current installed authority.
The check takes the client lock when it reads these facts.

`ClientInfo.InProcessUnrestricted` carries the result. The first service import into the system account sets this field for both detailed and minimal request metadata.
A chained service import clears the field. Leaf identity replacement cannot set it.

| Path | Marker rule |
|---|---|
| CLIENT or LEAF ingress | Clear caller-supplied marker before delivery or forwarding. Preserve the payload and update parser sizes after a header rewrite. |
| Fresh system service import | Set from the authenticated client and its current authority. |
| Chained import | Clear the marker. |
| ROUTE or GATEWAY transit | Retain verified peer metadata. |
| API queue and callback | Read the queued header with `getRequestInfo`. |
| Proposal or advisory | Clear the marker. |
| Assignment snapshot | Retain only its existing minimal fields. |
| Restore transfer, Raft apply, or recovery | Never read the marker. |

The admission exemption is exactly `ci != nil && ci.InProcessUnrestricted && ci.Service == ""`.
The callback client, connection kind alone, caller headers, static mode, and permission list lengths do not establish authority.
Optional request stamping still skips `$JS.` and supplies no exemption proof.

## Config fields and admission

`checkStreamCfg` normalizes the proposed config before the predicate runs.
This includes the stream-name subject default when no subject, source, or mirror is declared.
The predicate uses `SubjectsCollide` with `_INBOX.>` in this fixed order:

1. Each effective `Subjects` entry.
2. `Mirror.External.DeliverPrefix`, checked as the prefix plus `.>`.
3. `Mirror.Consumer.DeliverSubject`.
4. Each source in index order, with its external prefix before its consumer delivery subject.

Create checks after the mirror-direct check. Update checks after the stream-name check.
Restore checks after the path-separator check and normalization.
Each check runs before limits, cluster handoff, proposal, and storage.
An update checks the complete proposed config. A rejected update leaves the old config intact.

## Restore completion

`restoreInboxGate` freezes the admission exemption and a private deep copy of the normalized admitted config.
A transfer never reads `ClientInfo` to decide exemption again.
The meta leader records the frozen exemption in `streamAssignment.RestoreInboxExempt` before proposal.
The stream leader captures the gate before any assignment field is cleared or replaced.
The bit has the same lifetime as `Restore`. An absent bit fails closed.

The private legacy and V2 restore paths check the final normalized config before the stream accepts messages.
The legacy path also checks the snapshot metadata config before it installs the stream.
An ordinary transfer rejects each new inbox-capturing field and subject pair that is absent from the admitted config.
A trusted transfer retains its exemption after a leader handoff and stripped `ClientInfo`.
Public request-free restore methods retain their existing recovery behavior.

## Source and mirror response delivery

The server captures `want := req.Config.DeliverSubject` after it builds each consumer-create request and before it sends it.
In the non-durable response branch, `DeliverSubject` must equal `want` byte for byte before `subscribeInternal` runs.
A mismatch wraps `ErrJSSourceDeliverSubjectChanged` in the existing mirror or source ConsumerSetupFailed error.
Source setup checks equality before it starts the shared worker or copies response identity and sequence state.
The retry regression rejects sequence 100, then requires genuine messages 1–3 from an unchanged valid response with initial sequence zero.
Setup retries and creates no interest on the response subject.

The durable branch uses the declared `Consumer.DeliverSubject`, which admission already checks.
Trusted declared inbox prefixes and durable subjects remain supported.
A response payload or ACK filter cannot replace this subscription check.

## Existing streams and exclusions

Request-free recovery and Raft apply remain unchanged. A stream admitted while the flag was off, or by a trusted host, recovers after a restart.
An ordinary later update or restore must pass the full admission check.

A source filter and a subject transform select stored data. They do not create a capture subscription.
Republish destinations and plain consumer delivery subjects publish outgoing data.
An ordinary push consumer can still deliver to the caller's own inbox.
KV and object store creation retain their normal behavior.

## Native proof and release

The dedicated `TestJetStream...InboxCapture...` and `TestJetStreamCluster...InboxCapture...` tests cover predicate fields, API admission, origin proof, restore completion, response delivery, and lifecycle controls.
The affected race gate also covers grant authority, verification, request metadata, rollup, and account limits.
The execution report records exact source hashes, dirty-file digests, raw output, and final log digests.

The feature co-lands with these tests and `FORK-CHANGES.md` in one signed-off commit.
Publication requires passing native checks from the clean committed tree.
The owner then fast-forwards `release/v2.15.2` and creates annotated `v2.15.3-amnesh.1` at the tested commit.
The existing `v2.15.2` tag remains unchanged. Agents do not publish refs.
