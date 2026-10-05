# JWT Tags in Request Info Design

## Goal

When `stamp_request_info` is enabled, include the authenticated connection's
JWT user tags in the trimmed `ClientInfo` serialized into the
`Nats-Request-Info` header. A direct JWT client tagged `role:org-admin` must
deliver that tag to the responder.

## Source and trust boundary

JWT authentication already validates the user claim and stores `juc.Tags` in
`client.tags` under the client lock. Request-info stamping will copy that
authenticated value into `ClientInfo.Tags`; it will not decode the JWT again or
accept tags supplied in a request header.

For requests received over a leaf connection, the existing replacement rule
still applies: the receiving server discards forwarded identity and rebuilds it
from the authenticated leaf transport. The rebuilt header therefore carries
the receiving leaf connection's JWT tags, not the original caller's tags. The
forwarded `reply` field remains the only preserved field.

## Implementation and cache

Both trimmed constructors in `server/soo-changes.go` will copy `client.tags`
while holding `client.mu`: the cached snapshot used by
`stampRequestInfoHeaderIfNeeded`, and `getClientInfoForRequest`. Tags remain part
of the existing `client.ciStampHdr` cache, so repeat requests reuse the same
pre-marshaled bytes and existing invalidation behavior remains unchanged.

The feature remains off by default. When enabled, non-empty tags add their JSON
encoding to each stamped request header; empty tag lists remain omitted by
`omitempty`.

## Verification

- A direct JWT client tagged `role:org-admin` sends two requests; the responder
  observes that tag on both, covering the cache miss and cache hit paths.
- A request carrying a distinct, untrusted forwarded caller tag crosses a leaf
  authenticated by a JWT with transport tags; the responder observes only the
  receiving leaf transport tags. The direct JWT case separately proves that
  authenticated client JWT tags are extracted into the stamped header.
- Focused unit coverage checks empty tags, trimmed construction, leaf identity
  replacement, and cached serialization.
