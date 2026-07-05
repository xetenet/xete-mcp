---
name: gate-retrospective
description: Self-improvement loop for the gate system itself. MUST be used when an open issue labeled "gate-retrospective" exists in the repo, when a gate false-positives or blocks legitimate work, when a DDR verdict later proves wrong (a shipped bug on a protected path), or monthly if none of those occur. Turns weaknesses in the gates into concrete improvement PRs against xete-agent-skills instead of silent tolerance or silent weakening.
---

# Gate Retrospective

The gates review the code. This skill reviews the gates. A gate system that can't recognize its own failure modes decays into either theater (rubber-stamps) or friction (routed around) — both are silent.

## Triggers, in priority order

1. **A shipped defect on a protected path** — the gate's core failure. Run immediately.
2. **An open `gate-retrospective` issue** — the weekly audit found something. Run at session start.
3. **Friction event** — a gate blocked or slowed legitimate work in the current session (false-positive pattern, redundant ceremony). Run before session end; do not just note it.
4. **Monthly heartbeat** — if none of the above fired in ~30 days, run `scripts/gate-audit.sh` manually and retrospect on the output. Silence can mean health or mean routing-around; check which.

## The loop

### 1. Gather evidence
Read the audit report (issue or fresh `scripts/gate-audit.sh` run), plus:
- `git log --oneline -- reviews/` — DDR cadence and authorship
- The specific friction/defect event if one triggered this
- Time cost: roughly how long did gates add to the last 3 gated merges?

### 2. Diagnose against the known failure modes
| Failure mode | Evidence | Direction of fix |
|---|---|---|
| Theater | Near-duplicate or thin DDRs, reflexive SHIP | Strengthen review requirements OR trim protected paths — pick one, never both |
| Friction | False-positive patterns, gates on non-critical paths | Narrow patterns; move enforcement later (PR-level, not commit-level) |
| Holes | Ungated commits on main, zero gate activity during contract work | Widen patterns, check branch protection toggles, check hooksPath on clones |
| Drift | Repo layout changed, patterns didn't | Re-derive patterns from current tree |

### 3. Doubt the fix (meta-DDR)
Changes to the gate system are themselves protected-path-grade: run doubt-driven-review on the proposed change. Key doubts to always raise:
- Does this fix weaken the gate to relieve friction? (Weakening is sometimes right, but must be named as such, never smuggled in as "tuning.")
- Does this fix add ceremony to relieve anxiety? (Also a failure.)
- Will this change survive contact with an unattended agent session, or does it assume a human in the loop?

### 4. Ship the improvement
Open a PR against `xetenet/xete-agent-skills` containing: the change, the meta-DDR, and one line in the README changelog. Then re-run `install.sh` into affected repos (or note which repos need it in the PR body). Close or comment the triggering issue with a link.

## Hard rules

- **Never silently weaken.** Removing a pattern, downgrading a block to a warning, or relaxing a verdict rule requires an explicit "this weakens the gate because the cost exceeded the risk" statement in the meta-DDR, visible to the human.
- **Never silently tolerate.** Grinding through a false positive without proposing a fix is a rule-6 violation (CLAUDE.md).
- **One change per retrospective.** Batch fixes hide which change caused which effect. Smallest fix that addresses the diagnosed failure mode.
- **The human ratifies gate changes.** Improvement PRs to this repo are proposed autonomously but merged by Chef or Jo — the gate system's own merge boundary is human.
