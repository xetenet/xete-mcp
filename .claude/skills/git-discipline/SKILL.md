---
name: git-discipline
description: Commit and branch discipline for all Xete repos, especially when Claude Code runs semi-autonomously via Remote Control. MUST be used for every commit in every session — atomic commits are the rollback granularity when an agent session goes sideways. Trigger whenever staging, committing, branching, or when a work session begins.
---

# Git Discipline

When agents write code unattended, commits are the save points. Big commits mean big rollbacks.

## Commit rules

- **Atomic**: one logical change per commit, target ~100 changed lines, hard ceiling ~300. If a diff exceeds the ceiling, split it before committing — not after review finds a problem.
- **Always green**: the repo compiles and tests pass at every commit. `cargo check` / `cargo test` (or the project's test command) runs before every commit, not just before push. A commit that breaks the build destroys its value as a save point.
- **Message format**: `<area>: <imperative summary>` plus, when applicable, `SPEC-<feature>: task N` and `DDR: reviews/DDR-<name>.md`. The message states WHY when the diff alone doesn't.
- **No mixed concerns**: formatting-only changes, dependency bumps, and logic changes are separate commits. A reviewer must be able to read a logic diff without whitespace noise.

## Branch rules

- Feature branches per SPEC: `feat/<spec-name>`. Contract work never lands directly on main.
- Agent sessions (Remote Control, owl-alpha bulk work) commit to their feature branch freely; merging to main requires the DDR verdict SHIP for contract paths.
- Rebase before merge; main stays linear. Force-push only on your own feature branches.

## Session start ritual (Remote Control especially)

1. `git status` — confirm clean tree before new work; stash or commit anything dangling with an explicit message.
2. `git log --oneline -5` — confirm you're building on what you think you are.
3. Confirm current branch matches the SPEC being executed.

## Recovery posture

- Prefer `git revert` over history rewriting on shared branches.
- Before any risky operation (rebase, reset, filter), note the current HEAD SHA in the session so it can be restored.
- If an agent session produced a tangle: branch from the last good commit and cherry-pick, rather than untangling in place.
