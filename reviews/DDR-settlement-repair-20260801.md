# DDR: the settlement repair round's fixes are sound, but this round was NOT self-reviewed to completion

Commit scope: `src/xete_mcp/settlement.py`, `src/xete_mcp/draft.py`, `src/xete_mcp/server.py`,
`test_settlement_robustness.py`

## Provenance — read this first

This work was produced by a repair agent that **died on an API error before committing it or
writing this DDR**. It was recovered from the worktree by the integrating session, verified, and
committed here rather than discarded. That means:

- The changes were **not** reviewed by the adversarial lens round (that round ran against the
  *previous* tip, `dd03750`, and its confirmed findings are what this work was closing).
- This DDR is therefore written by the integrator, not by a fresh context. Under CLAUDE.md rule 5
  that is **not** sufficient to carry a SHIP verdict on its own.

## Claim

The recovered work closes the settlement findings the three adversarial lenses confirmed against
`dd03750`, without weakening any existing security property.

## Assumptions

| Assumption | Status |
|---|---|
| `spendguard.py` is untouched (its zero-diff across tracks is load-bearing) | **Verified** — blob `72e416a`, byte-identical to `ee81682` |
| The AST tripwire still passes (gate present on every spending path, before any sign/submit) | **Verified** — 4/4 gate tests pass |
| The new tests genuinely exercise the fixes | **Verified by count and content** — 39 new test functions, named for the confirmed findings (chain-not-draft verification, fail-closed on unreadable chain, foreign account at the PDA, two-endpoint agreement, confusable names) |
| The suite is green | **Verified** — 188 passed vs 144 at the committed tip; +44 tests, zero failures |
| Each new test fails without its fix | **NOT verified** — the round died before it could demonstrate this, and the integrator did not re-derive it per-test |

## Doubts raised

1. **(integrator)** Is this partial work, left mid-edit by a dying process? — *Refuted with
   evidence:* the tree is syntactically valid, all modules import, and the full suite is green with
   44 more passing tests than the commit it sits on. A truncated edit would not produce that.
2. **(integrator)** Did the dying agent weaken a test to make something pass? — *Checked:* the
   diff to `test_settlement_robustness.py` is +688 lines and the pre-existing test count did not
   drop. No test was deleted or loosened. Not exhaustively line-audited.
3. **(integrator)** Was the memo's "188 passed at `dd03750`" accurate? — *Refuted:* it was not.
   `dd03750` alone is **144**. The memo measured the working tree including this uncommitted work
   and attributed it to the commit. Recorded because it is exactly the kind of error that makes a
   report look verified when it is not.

## Reconciliation

- Doubts 1–3: addressed above.
- The unverified assumption (each test fails without its fix) is **accepted as open**, not
  dismissed.

## Verdict: BLOCK  *(superseded — see the appended fresh-context review)*

Not because anything is known to be wrong — the evidence is good — but because this specific
change set has had **no independent review at all**, and it is on the money path. It needs one
fresh-context adversarial pass before it can carry SHIP. Do not flip this verdict without one.


---

## FRESH-CONTEXT REVIEW — appended 2026-08-01, verdict moved BLOCK -> SHIP

**The stated BLOCK reason was "this change set has had no independent review at all."** That is no
longer true: four fresh-context lenses attacked the merged tree, then four more attacked the repair
of their findings. Nothing in this change set survived unexamined.

### The open assumption, resolved honestly

This file listed one assumption as **NOT verified**: *each new test fails without its fix.* Its
status now, stated precisely rather than conveniently:

- **Discharged at the level that matters.** A dedicated test-integrity lens diffed every test file
  against `cb1ccb4`, adjudicated each changed or deleted assertion, and mutation-tested the
  security core. It found **no weakened assertion and no deleted coverage** — the one removed test
  was a rename whose body is byte-identical, retitled because the old title asserted a thing that
  was disproved.
- **What it found instead was three MISSING assertions**, all now closed with mutation-proven
  tests (`7f7c5eb`): the encryption core had no negative test at all, `_migrate_keystore`'s
  never-overwrite-the-backup guarantee was unasserted, and two of three match conditions in the
  spend-rollback were unasserted.
- **Not discharged:** the 39 recovered tests were *not* individually reverted one at a time. The
  claim that now holds is "the security core is mutation-proven to catch the defects it should",
  which is stronger in substance and weaker in literal coverage than the original wording.

### Method lesson worth more than the fix

Closing the backup-guarantee gap took **three attempts**, and the first two tests passed with the
guard deleted — one started from a keystore with no legacy secret (migration returns at line 1),
the other migrated the same file twice (an idempotency check returns early). Both looked
completely reasonable. *A regression test is not a test until you have watched it fail.*

## Verdict: SHIP
