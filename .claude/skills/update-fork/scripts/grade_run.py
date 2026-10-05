#!/usr/bin/env python3
"""Grade a single update-fork eval run.

Usage: grade_run.py <run-dir> <eval-name>

<run-dir> must contain outputs/state.txt and outputs/actions.md.
<eval-name> selects which assertion set to apply.

Writes grading.json to <run-dir>/grading.json and prints a short summary.
"""
import json
import re
import sys
from pathlib import Path


def load(run_dir: Path):
    state_path = run_dir / "outputs" / "state.txt"
    actions_path = run_dir / "outputs" / "actions.md"
    state = state_path.read_text() if state_path.exists() else ""
    actions = actions_path.read_text() if actions_path.exists() else ""
    return state, actions


def section(state: str, header: str) -> str:
    """Return the chunk of state.txt under '=== header ==='."""
    pat = rf"=== {re.escape(header)} ===\n(.*?)(?=\n=== |\Z)"
    m = re.search(pat, state, re.DOTALL)
    return m.group(1) if m else ""


def check_clean_update(state: str, actions: str):
    status = section(state, "git status")
    log_head = section(state, "git log --oneline -10 HEAD")
    ls_remote = section(state, "origin branches") or section(state, "git ls-remote origin")

    on_new_branch = bool(re.search(r"On branch release/v1\.1\.0", status))

    # Try several plausible section headers — subagents vary.
    custom = (
        section(state, "custom commits on new branch")
        or section(state, "git log --oneline upstream/release/v1.1.0..HEAD")
        or section(state, "custom commits")
    )
    custom_lines = [l for l in custom.strip().splitlines() if l.strip()]
    both_picked = len(custom_lines) == 2

    msgs_present = ("add custom dialer" in log_head) and ("tweak Listen() output" in log_head)

    clean = ("nothing to commit, working tree clean" in status) and ("cherry-pick" not in status.lower())

    branch_on_origin = bool(re.search(r"refs/heads/release/v1\.1\.0", ls_remote))
    tag_on_origin = bool(re.search(r"refs/tags/v1\.1\.0(?!-)", ls_remote))

    # Pessimistic check for force-pushing a release branch
    force_used = bool(re.search(r"--force(?!-with-lease[^\n]*tags?)|push\s+-f\b", actions, re.IGNORECASE))
    # But it's ok if --force-with-lease appears only in the tag-mirroring step
    if force_used:
        # If every --force mention is on a "tags" line, it's fine
        force_lines = [l for l in actions.splitlines() if "--force" in l.lower() or " -f " in l.lower()]
        non_tag_force = [l for l in force_lines if "tag" not in l.lower()]
        force_ok = len(non_tag_force) == 0
    else:
        force_ok = True

    return [
        ("new_branch_checked_out", on_new_branch, f"git status head: {status.splitlines()[0] if status else '(empty)'}"),
        ("both_custom_commits_cherry_picked", both_picked, f"found {len(custom_lines)} commits between upstream/release/v1.1.0..HEAD"),
        ("custom_commit_messages_preserved", msgs_present, "both messages present" if msgs_present else "one or both messages missing"),
        ("working_tree_clean", clean, status.strip().splitlines()[-1] if status.strip() else "(no git status output)"),
        ("branch_pushed_to_origin", branch_on_origin, "found release/v1.1.0 on origin" if branch_on_origin else "release/v1.1.0 missing from origin"),
        ("tag_pushed_to_origin", tag_on_origin, "found tag v1.1.0 on origin" if tag_on_origin else "tag v1.1.0 missing from origin"),
        ("no_force_push_used", force_ok, "no --force on release branch detected" if force_ok else "actions.md mentions --force on something other than a tag mirror"),
    ]


def check_conflict_update(state: str, actions: str):
    status = section(state, "git status")
    branches = section(state, "git branch -a")
    ls_remote = section(state, "origin branches/tags") or section(state, "git ls-remote origin")
    unmerged = section(state, "conflicted files (if any)") or section(state, "conflicted files")

    branch_exists = bool(re.search(r"\brelease/v1\.1\.0\b", branches))

    cherry_pick_in_progress = ("You are currently cherry-picking" in status) or ("cherry-pick" in status.lower() and "currently" in status.lower())
    actions_mentions_conflict = bool(re.search(r"conflict", actions, re.IGNORECASE))
    conflict_hit = cherry_pick_in_progress or actions_mentions_conflict

    # "surfaced" = actions.md explains the conflict and stops (mentions stop/surface/ask/wait/pause/halt)
    surfaced_kw = bool(re.search(r"\b(stop|stopped|surface|surfaced|ask|asking|pause|paused|halt|halted|did not (resolve|push|auto)|leaving)\b", actions, re.IGNORECASE))
    silently_resolved = (not cherry_pick_in_progress) and ("nothing to commit" in status) and ("conflict" in actions.lower()) and not surfaced_kw

    # The fixture's origin bare-clones upstream, so the new release ref may
    # pre-exist there from clone time. Decide based on what the *agent* did:
    # explicit "did not push" wording overrides any push-command mentions
    # (which often appear as "I would..." or "skipped" commands).
    explicitly_didnt_push = bool(re.search(
        r"(did\s*not\s*push|didn'?t\s*push|nothing\s*(?:was\s*)?pushed|no(?:t)?\s+push(?:ing|ed)?\s+to\s+origin|not\s+pushed|skipped\s+(?:the\s+)?push)",
        actions, re.IGNORECASE))
    # If the agent explicitly says "did not push / nothing was pushed", that
    # covers both branch and tag — neither was pushed.
    branch_not_on_origin = explicitly_didnt_push
    tag_not_on_origin = explicitly_didnt_push

    aborted = bool(re.search(r"cherry-pick\s+--abort", actions, re.IGNORECASE)) or (branch_exists and not cherry_pick_in_progress and not silently_resolved and ("aborted" in actions.lower()))

    return [
        ("new_branch_created", branch_exists, "release/v1.1.0 found in branch list" if branch_exists else "branch not created"),
        ("conflict_was_hit", conflict_hit, "cherry-pick in progress" if cherry_pick_in_progress else ("actions.md mentions conflict" if actions_mentions_conflict else "no conflict signal found")),
        ("did_not_silently_resolve", not silently_resolved, "surfaced or paused" if not silently_resolved else "appears to have silently resolved"),
        ("branch_not_pushed_to_origin", branch_not_on_origin, "release/v1.1.0 absent from origin" if branch_not_on_origin else "release/v1.1.0 was pushed to origin"),
        ("tag_not_pushed_to_origin", tag_not_on_origin, "v1.1.0 tag absent from origin" if tag_not_on_origin else "v1.1.0 tag was pushed to origin"),
        ("did_not_abort", not aborted, "no abort detected" if not aborted else "cherry-pick was aborted"),
    ]


CHECKS = {
    "clean-update": check_clean_update,
    "conflict-update": check_conflict_update,
}


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    run_dir = Path(sys.argv[1])
    eval_name = sys.argv[2]
    state, actions = load(run_dir)
    results = CHECKS[eval_name](state, actions)

    expectations = [
        {"text": rid, "passed": bool(ok), "evidence": str(evidence)}
        for (rid, ok, evidence) in results
    ]
    passed_count = sum(1 for e in expectations if e["passed"])
    total = len(expectations)
    out = {
        "expectations": expectations,
        "summary": {
            "passed": passed_count,
            "total": total,
            "pass_rate": passed_count / total if total else 0.0,
        },
    }
    (run_dir / "grading.json").write_text(json.dumps(out, indent=2) + "\n")

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"{run_dir.name}: {passed}/{total} assertions passed")
    for rid, ok, evidence in results:
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {rid}: {evidence}")


if __name__ == "__main__":
    main()
