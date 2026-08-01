---
name: doubt-driven-review
description: Adversarial fresh-context review of any non-trivial technical decision or code change. MUST be used before committing any change to smart contract code (xete-tab, Xete Swap), key handling (Black Knight), encryption logic (Xete Message, MCP server), or any irreversible/immutable deployment decision. Also trigger when the user asks to "stress-test", "doubt", "red-team", or "verify" a decision. Produces a review artifact in reviews/ that the pre-commit hook checks for.
---

# Doubt-Driven Review

Confidence is not evidence. This skill forces an adversarial second pass on decisions where being wrong is expensive or irreversible.

## When this is MANDATORY (enforced by pre-commit hook)

Any staged change touching:
- `programs/` or any Rust smart contract source
- Key generation, storage, signing, or policy logic (Black Knight)
- Encryption, key exchange, or nonce handling (x25519 / AES-256-GCM paths)
- Migration or deployment scripts for immutable contracts

## The loop: CLAIM → EXTRACT → DOUBT → RECONCILE

### 1. CLAIM
State the decision or change as a falsifiable claim. Not "improved the settlement logic" but "the commitment hash cannot be replayed across tabs because X is included in the preimage."

### 2. EXTRACT
List every assumption the claim rests on. For each: is it verified, inherited, or assumed? Assumptions inherited from docs or prior conversation are UNVERIFIED until checked against source.

### 3. DOUBT (fresh context)
Review the claim as if you had no investment in it being true. Concretely:
- **Benchmarks first**: check `benchmarks/BM-*.md` for cases whose `Paths` overlap this diff. Each matching benchmark's doubt prompt MUST be answered explicitly in the DDR — these are real bugs this codebase has already shipped once. Repeating a benchmarked bug because its prompt was skipped is the system's cardinal failure.
- In Claude Code: spawn a subagent (or open a fresh session) with ONLY the diff, the claim, and the assumption list. No conversation history. Instruct it: "Your job is to break this. Find the input, ordering, or state that falsifies the claim."
- Cross-model escalation: for contract logic, run the same doubt prompt through the secondary model (owl-alpha) AND Claude. Disagreement between models is a finding, not noise.
- The reviewer must produce at least one concrete attack attempt per assumption, even if it fails. "Looks good" is not a review.

### 4. RECONCILE
For each doubt raised: refute it with evidence (test, code reference, invariant), or fix the code, or explicitly accept the risk in writing. No silent dismissals.

## Required artifact

Write `reviews/DDR-<short-description>-<YYYYMMDD>.md` containing:

```markdown
# DDR: <claim, one line>
Commit scope: <files touched>
## Claim
## Assumptions (verified / inherited / assumed)
## Doubts raised (who raised: fresh-context Claude / owl-alpha / human)
## Reconciliation (per doubt: refuted-with-evidence | fixed | risk-accepted-by-<name>)
## Verdict: SHIP | BLOCK
```

Stage this file in the same commit as the change. The pre-commit hook rejects contract-path commits without a staged `reviews/DDR-*.md`.

If the change under review FIXES a real defect on a protected path, also author `benchmarks/BM-<name>.md` (format in skills/gate-backtest) in the same commit — every real bug becomes a permanent doubt prompt so it can never ship twice unexamined.

## Anti-rationalization table

| Rationalization | Reality |
|---|---|
| "It's a small change" | Small changes to immutable contracts are permanent small changes |
| "Tests pass" | Tests encode the same assumptions the author made |
| "We reviewed this pattern before" | The pattern was reviewed; this instance was not |
| "The other model agreed" | Agreement without an attack attempt is not review |
| "We're in a hurry for Breakpoint" | Deadline pressure is when this skill pays for itself |
