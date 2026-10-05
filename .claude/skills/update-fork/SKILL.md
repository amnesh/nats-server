---
name: update-fork
description: Use this skill whenever the user wants to update a forked Git repo to a newer upstream release while preserving their custom patches via cherry-pick. Triggers on phrases like "update the fork", "sync with upstream", "rebase onto new release", "upgrade nats-server to v2.x", or any request to bring a fork's custom commits forward onto a newer upstream release branch. Defaults to chezgi/nats-server's release-branch workflow but works for any fork that maintains custom commits on top of an upstream `release/vX.Y.Z` branch.
---

# Update fork to latest upstream release

This skill brings a forked Git repository up to a newer upstream release while preserving the user's custom commits, by cherry-picking them onto a fresh branch based on the new upstream release tag.

Defaults to `/work/github/nats-server` with `origin = chezgi/nats-server` and `upstream = nats-io/nats-server`, but the same workflow applies to any fork where custom commits sit on top of upstream `release/*` branches.

## Mental model

A maintained fork has two kinds of commits on each `release/vX.Y.Z` branch:

1. **Upstream commits** — everything inherited from `upstream/release/vX.Y.Z`.
2. **Custom commits** — what the user added on top (often just 1–3 commits).

To move to a new release `vA.B.C`:
- Start from the new upstream branch `upstream/release/vA.B.C`.
- Cherry-pick *only* the custom commits from the old fork branch.
- Push and tag.

The custom commits are exactly the output of `git log upstream/release/vX.Y.Z..origin/release/vX.Y.Z`. That set is the source of truth — do not infer from author name or message; the range query is authoritative.

## When to use this skill

Use when the user says any of:
- "Update the nats-server fork", "sync the fork", "upgrade to v2.12.6", "rebase my patches onto the new release"
- "Bring my changes forward to the new upstream version"
- "Cherry-pick my custom commits onto release/vX"

Do **not** use this skill for:
- Initial fork creation (the original notes' "fork" section is one-time setup, already done).
- Updating `go.mod` in a *downstream* project that consumes the fork — that happens in the consuming repo, not here.
- Routine merges of `main`. This skill is specifically for `release/*` branches.

## Required preconditions — verify these before doing anything destructive

1. **Working tree is clean.** Run `git status --porcelain`. If output is non-empty, stop and tell the user. Don't stash silently — the user's uncommitted work matters.
2. **Both remotes exist.** `git remote -v` must show `origin` (the fork) and `upstream` (the source). If not, stop and ask.
3. **You know the target version.** Either the user named it, or you have to ask. Don't guess "latest" without confirming — they may want a specific patch release.

Skipping these is how you lose work. Always check.

## The workflow

### Step 1 — Confirm scope with the user

Before fetching, state what you're about to do in one short message: source branch (e.g. `release/v2.12.5`), target branch (e.g. `release/v2.12.6`), and that you'll cherry-pick custom commits. Wait for confirmation. The user may want to tweak (e.g. "also drop commit X this time").

If the user hasn't given a target version, ask. Don't assume "latest tag" — release candidates and main-line releases both create tags.

### Step 2 — Fetch both remotes

```sh
git fetch upstream --prune --prune-tags
git fetch origin   --prune
```

**Do not put `--prune-tags` on the origin fetch.** Tags live in one flat, shared namespace — they are not per-remote like `refs/remotes/<remote>/*`. `--prune-tags` deletes every local tag that the fetched remote does not have. Origin is the fork, so it always has fewer tags than upstream. Running it on origin deletes exactly the new upstream tags that the line above just fetched, including the target release tag. The mirror push below then has nothing to send, prints `Everything up-to-date`, and exits 0 — a silent no-op that hides for many release cycles.

`--prune-tags` on the **upstream** fetch is correct and stays: upstream sometimes deletes RC tags, and a stale local tag blocks re-tagging. Caution: it also deletes any local tag whose name upstream does not have. That is safe only while every fork tag reuses an upstream release name (the convention in Step 8). A fork-only name such as `v2.14.7-fork.1` would be deleted.

Next, delete upstream's copy of the **target** release tag. Upstream's `vA.B.C` points at upstream's release commit. Step 8 must create `vA.B.C` on the fork commit instead:

```sh
git tag -d vA.B.C
```

Skip this if the tag is not present. Without it you get two failures: the mirror push below publishes upstream's `vA.B.C` to origin, so `go get <fork>@vA.B.C` resolves to plain upstream code with none of the fork patches; and Step 8 then dies with `fatal: tag 'vA.B.C' already exists`.

Then mirror the remaining upstream tags to origin so Go module consumers can resolve older versions:

```sh
git push origin --tags
```

Use a **plain** push, not `--force` or `--force-with-lease`. A plain tag push only adds tags that origin lacks; it refuses to change a tag that already exists with different content. That is the protection you want, because the fork's own `vX.Y.Z` tags point at fork commits while upstream's tags of the same name point at upstream commits. Force semantics here would overwrite the fork's release tags with upstream's.

Verify the mirror really did something — this step failed silently in the past:

```sh
git ls-remote --tags upstream | grep -vc '\^{}'   # upstream tag count
git ls-remote --tags origin   | grep -vc '\^{}'   # origin tag count
```

After a successful mirror, origin must be short of upstream by at most the fork-named tags. If the two counts do not move closer together, the push did nothing — find out why before you continue.

### Step 3 — Identify custom commits on the old branch

```sh
git log --oneline upstream/release/vX.Y.Z..origin/release/vX.Y.Z
```

This lists exactly the commits the user added on top of upstream. Show the list to the user and ask them to confirm before cherry-picking. They may want to drop something, add a commit from another branch, or reorder.

If the output is empty, the fork has no custom commits on this release — there's nothing to cherry-pick, and you just need to retag. Tell the user and ask whether to proceed.

### Step 4 — Verify the new upstream branch exists

```sh
git rev-parse --verify upstream/release/vA.B.C
```

If this fails, the target version doesn't exist on upstream yet. Stop and tell the user — don't try to "fix" it by picking a different version.

### Step 5 — Create the new local branch from upstream

```sh
git checkout -b release/vA.B.C upstream/release/vA.B.C
```

Use a fresh local branch tracking from upstream. Do not branch from the old fork branch — that would carry forward old custom commits as their old SHAs, defeating the point.

If the local branch already exists from a prior attempt, ask the user: delete and recreate, or check it out and continue? Don't silently overwrite.

### Step 6 — Cherry-pick the custom commits

```sh
git cherry-pick <sha1> <sha2> ...
```

Use the SHAs from Step 3, in their original order (oldest first — that's the order `git log` showed them in reverse, so you usually want to reverse the list).

**On conflict:** stop and surface the conflict to the user with `git status`. Do not blindly resolve. The user wrote these patches; ask which side to keep, or ask them to resolve manually. After resolution, continue with `git cherry-pick --continue`.

**On empty pick** (the change is already in upstream): run `git cherry-pick --skip` and note it for the user — it's actually good news (their fix got merged upstream).

### Step 7 — Push the new branch to origin

```sh
git push -u origin release/vA.B.C
```

Use `-u` so the branch tracks origin. No `--force` here — this is a new branch on origin.

### Step 8 — Tag and push the tag

First make sure the name is free. If Step 2's `git tag -d vA.B.C` was missed, or something re-fetched upstream tags in between, the name is taken by upstream's tag and `git tag -a` fails:

```sh
git tag -l vA.B.C                 # must print nothing
git ls-remote --tags origin vA.B.C  # must print nothing
```

If the local name is taken by upstream's copy, delete it (`git tag -d vA.B.C`) and continue. If the name is taken **on origin**, stop — see the note below.

```sh
git tag -a vA.B.C -m "sync with upstream vA.B.C"
git push origin vA.B.C
```

Go modules resolve versions by tag, so this step is what actually makes the new release usable from downstream `go.mod` files. The tag must match the upstream release tag name exactly (e.g. `v2.12.6`, not `release/v2.12.6` or `v2.12.6-fork`).

If a tag with that name already exists on origin (from a previous attempt), stop and check with the user before deleting — overwriting tags breaks anyone who already pinned to the old one.

### Step 9 — Summarize what happened

Tell the user, briefly: which branch is now current, which commits were carried forward, which (if any) were skipped because they're upstream now, and the tag that was pushed. Mention if any post-step is needed in downstream consumers (typically: bump `go.mod` and run `go mod tidy` in the consuming project).

## Safety rails

- **Never** `git push --force` to a `release/*` branch. New branches get plain push; existing ones should not be force-overwritten by this skill.
- **Never** force-push tags (`--force` or `--force-with-lease` with `--tags`). The fork's `vX.Y.Z` tags and upstream's tags share names but point at different commits. Force semantics replace the fork's release tags with upstream's, which silently strips the fork's patches from every consumer that pins those versions.
- **Never** use `--prune-tags` on a fetch from `origin`. See Step 2 — it deletes the upstream tags you just fetched.
- **Never** `--no-verify` to skip hooks. The user's CI/sign-off requirements apply here too.
- **Never** delete branches the user didn't explicitly say to delete. The old `release/vX.Y.Z` branch stays — it's history.
- If cherry-pick fails and the user is unavailable to resolve, leave the repo in the conflicted state and explain. Aborting (`git cherry-pick --abort`) destroys the partial progress; only do it on user request.

## When the workflow doesn't fit

This skill assumes the upstream maintains `release/vX.Y.Z` branches and tags releases as `vX.Y.Z`. If the user's fork is for a project with a different release model (rolling main, semver tags but no release branches, calendar versioning), the steps will need adapting — surface this to the user rather than forcing the pattern.

For repos other than nats-server, the same workflow applies, but verify the remote names and branch-naming convention with the user first. Don't assume `upstream` is the right remote name everywhere.
