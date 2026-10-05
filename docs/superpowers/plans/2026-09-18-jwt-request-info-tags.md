# JWT Tags in Request Info Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Include authenticated JWT user tags in opt-in `Nats-Request-Info` headers, including the existing leaf identity replacement behavior.

**Architecture:** Reuse the JWT tags already authenticated into `client.tags`. Copy them under `client.mu` into both trimmed `ClientInfo` constructors so the existing JSON cache and leaf replacement path keep their current structure.

**Tech Stack:** Go, `github.com/nats-io/jwt/v2`, NATS request/reply and leaf-node test helpers.

## Global Constraints

- `stamp_request_info` remains disabled by default.
- Preserve `client.ciStampHdr` caching and its current invalidation behavior.
- A receiving leaf replaces forwarded caller tags with its authenticated transport JWT tags.
- Keep production changes confined to `server/soo-changes.go`.
- Do not commit until independent review is complete.

---

### Task 1: Stamp authenticated JWT tags

**Files:**
- Modify: `server/soo-changes.go`
- Test: `server/soo-changes_test.go`
- Modify: `FORK-CHANGES.md`
- Create: `docs/superpowers/specs/2026-09-18-jwt-request-info-tags-design.md`

**Interfaces:**
- Consumes: authenticated `client.tags` (`jwt.TagList`) populated by `processClientOrLeafAuthentication`.
- Produces: `ClientInfo.Tags` in the trimmed request-info JSON and cached `client.ciStampHdr`.

- [x] **Step 1: Add failing unit and end-to-end tests**

  Extend the trimmed constructor and stamp/cache assertions with literal tag
  values. Add operator-mode JWT request/reply coverage in which a direct caller
  tagged `role:org-admin` sends twice, and leaf coverage in which untrusted
  forwarded caller tag `source:original-client` is replaced by transport tag
  `source:receiving-leaf`.

- [x] **Step 2: Verify the new tests fail for the missing field**

  Run:

  ```bash
  go test -race -run 'Test(GetClientInfoForRequest|StampRequestInfo.*JWT)' ./server -count=1
  ```

  Expected: tag assertions fail with an empty `ClientInfo.Tags`.

- [x] **Step 3: Implement the minimal production change**

  Under the existing `client.mu` critical sections, assign `Tags: c.tags` in the
  cached snapshot and `ci.Tags = c.tags` in `getClientInfoForRequest`. Update the
  nearby trimmed-field comment to include tags and continue excluding JWT,
  issuer, server/cluster, and start time.

- [x] **Step 4: Document wire and leaf semantics**

  Update `FORK-CHANGES.md` to list `tags`, state their authenticated source,
  describe leaf transport replacement, and call out the per-request header-byte
  increase for non-empty tag lists.

- [x] **Step 5: Format and verify**

  Run `gofmt` on changed Go files, then run the focused race test, the repository
  fork-feature regression command, `go build`, and the configured linter when
  available. Record exact commands, results, red/green evidence, and any limits
  in `/tmp/nats-jwt-stamp-tags-implementation-report.md`.

  Completed with focused race tests, fork-feature regressions, and the build
  passing. The installed v2 linter reports `0 issues` when scoped with
  `--new-from-rev=933a252061f3c78f1d79f2fb11eb3c2720d109cd`; the unscoped run's sole
  finding is in `server/opts_test.go`, which Git confirms is identical to that
  base revision.

- [x] **Step 6: Prepare for review without committing**

  Inspect the scoped diff and working tree, confirm protected unrelated files
  remain untouched, and hand the uncommitted change to the coordinator for
  independent review.
