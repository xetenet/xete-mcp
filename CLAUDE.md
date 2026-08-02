# Xete Agent Operating Rules

These rules bind every agent session (Claude Code, Remote Control, owl-alpha, or any other model) working in Xete repositories. They are not suggestions. The pre-commit hook enforces the review gate mechanically; the rest are enforced by you, the agent, refusing to skip them.

## Hard rules

1. **No code before spec** for (a) any work touching protected paths and (b) any work handed between people or agent sessions. Use `skills/spec-and-plan/SKILL.md`. Exploratory work on a feature branch that stays in one head and off protected paths needs no spec — but the moment it's handed off or aimed at a protected path, write the spec before continuing.

2. **No contract-path commit without a DDR.** Any change under a protected path (see `.githooks/protected-paths`) requires a completed doubt-driven review (`skills/doubt-driven-review/SKILL.md`) with a staged `reviews/DDR-*.md` carrying `Verdict: SHIP`. The hook will block you; do not use `--no-verify` unless the human explicitly authorizes it in the current session, and record that authorization in the DDR.

3. **Security gates run inside the DDR** for any crypto, key-handling, or on-chain change. Use `skills/solana-security-hardening/SKILL.md`. Mark any unresolved item `OPEN-GATE` — the hook blocks commits containing open gates. Do not delete an OPEN-GATE marker; resolve it or escalate to the human.

4. **Every commit follows git discipline** (`skills/git-discipline/SKILL.md`): atomic, green, ~100 lines, spec-referenced. Run the session start ritual before your first change.

5. **Fresh-context doubt is real, not simulated.** When the DDR calls for adversarial review, spawn a subagent or instruct the human to open a fresh session. Reviewing your own reasoning inside the same context does not count and must be recorded as `self-review-only` in the DDR, which downgrades the verdict to BLOCK for contract paths.

6. **The agent runs the gates; the human reads verdicts.** Writing the spec, running the DDR loop, spawning the doubt subagent, filling the security checklist, and authoring `reviews/DDR-*.md` are all agent work, done without asking permission. The human's involvement is reading the finished DDR's doubts and verdict — not producing paperwork. If a gate turns a 10-minute task into an hour of ceremony for a non-contract change, the protected-paths patterns are miscalibrated: flag it to the human with a proposed pattern fix rather than suffering silently.

7. **The gate system audits itself.** At session start, check for an open issue labeled `gate-retrospective` — if present, running `skills/gate-retrospective/SKILL.md` is part of this session's work. Any friction event (false-positive block, redundant ceremony) or any shipped defect on a protected path triggers the same skill before session end. Improvement PRs are proposed autonomously; merging them is human-only. Never silently weaken a gate, never silently tolerate a broken one.

## Session checklist (run at start of every session)

- [ ] `git status` clean; `git log --oneline -5` read
- [ ] Active SPEC identified (or created) for the work at hand
- [ ] Protected-path awareness: will this session touch them? If yes, budget for DDR + security gates before promising completion
- [ ] Hooks installed: `git config core.hooksPath` returns `.githooks` (run `scripts/install.sh` if not)

## Escalation

- Model disagreement during cross-model doubt → surface to human, never silently pick one.
- Deadline pressure vs. gates → the gates win; surface the tradeoff to the human with a time estimate, do not quietly skip.
