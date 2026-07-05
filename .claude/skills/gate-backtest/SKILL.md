---
name: gate-backtest
description: Train and calibrate the gate system against a repo's real git history in an isolated sandbox. MUST be used when the user asks to backtest, replay, calibrate, or train the gates against history, and after installing gates into any repo with meaningful existing history. Uses real historical fixes as ground truth and converts each one into a permanent benchmarks/BM-*.md case that future DDRs are checked against.
---

# Gate Backtest

The repo's own history is a labeled dataset: every fix commit marks an earlier commit that introduced a real defect. This skill replays that history against the gates and converts each real defect into a permanent benchmark.

## Safety invariant

All work happens in the throwaway clone that `scripts/backtest.sh` creates — remotes stripped, nothing writable pointing at the real repo. Never run analysis inside an active working copy. Outputs (benchmarks, pattern proposals) land only in the xete-agent-skills repo via PR.

## Step 1: Mechanical replay

```sh
scripts/backtest.sh <path-or-url-to-repo>
```

Produces: recall (fraction of real defect-introducing commits the gate would have caught), friction (gated commits with no known defect), missed culprits with files, and suggested pattern additions.

## Step 2: Qualitative pass on every culprit (caught AND missed)

For each culprit commit in the report, answer three questions by reading the actual diff of the culprit and its fix:

1. **Which gate would have caught it?** Map the defect to a specific line of the solana-security-hardening checklist, or to a doubt class in doubt-driven-review. If NO existing gate item maps to it, that is a checklist gap — the fix becomes a new checklist line.
2. **Was it catchable at commit time?** Some defects are only visible with later context (spec changed, dependency behavior). Mark honestly: `catchable` or `hindsight-only`. Hindsight-only cases must not inflate the gate's claimed value.
3. **What is the doubt prompt?** Write the one question a fresh-context reviewer would have needed to ask to find it. Concrete, not generic: "what happens when the same commitment is submitted to two tabs?" not "is this secure?"

## Step 3: Author benchmark cases

One file per real defect: `benchmarks/BM-<short-name>.md`

```markdown
# BM: <defect in one line>
Source: <repo> culprit <hash> fixed by <hash>
Paths: <files/dirs involved>
Class: <overflow | replay | validation-gap | key-leak | logic | ...>
Catchable at commit time: yes | hindsight-only
Gate mapping: <checklist item or doubt class; NEW if it was a gap>
Doubt prompt: <the question that finds this bug>
Real solution: <what the actual fix did, 1-2 lines>
```

Benchmarks are append-only ground truth. They are never deleted when patterns change — they are what patterns are tested against.

## Step 4: Close the loop

- **Patterns**: propose additions from the missed-culprit paths; propose narrowing only where friction is high AND no benchmark lives on those paths. Meta-DDR required, as with all gate changes.
- **Checklist**: every `Gate mapping: NEW` benchmark adds a line to solana-security-hardening.
- **Re-score**: rerun `backtest.sh` with the proposed patterns file (second argument) and report before/after recall in the PR. A pattern change that doesn't improve recall or reduce friction against the benchmarks doesn't ship.

## Ongoing use (this is the training part)

The benchmarks are live at every future commit, not just during backtests:
- doubt-driven-review requires checking `benchmarks/` for cases whose Paths overlap the current diff; each matching benchmark's doubt prompt MUST be answered in the DDR.
- Every NEW real-world fix on a protected path gets a benchmark authored as part of its own DDR — the dataset grows with the project.
- gate-retrospective scores DDR quality against benchmark hit-rate: a DDR that missed a doubt its matching benchmark prescribes is a retrospective trigger.
