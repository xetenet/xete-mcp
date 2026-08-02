---
name: spec-and-plan
description: Spec-first workflow for any feature or change expected to exceed one atomic commit, and for all work handed between Chef, Jo, or agent sessions. MUST be used when starting a new feature, refactor, or integration (House Elf features, MCP server changes, relay work, x402 extensions) — write the spec BEFORE any code. Also trigger on "plan this", "break this down", "spec this out", or when a task will be executed by a different session/model than the one planning it.
---

# Spec and Plan

Code written without a spec optimizes for the first interpretation, not the right one. This skill front-loads the disagreement.

## Step 1: Spec (before any code)

Write `specs/SPEC-<feature>-<YYYYMMDD>.md`:

```markdown
# SPEC: <feature>
## Problem — what breaks or is missing today, in user/agent terms
## Non-goals — what this explicitly does NOT do (at least 2)
## Interface — exact function signatures, message formats, account layouts, or UI states. No prose where a type will do.
## Invariants — what must remain true after this ships (these become doubt-driven-review claims)
## Open questions — anything unresolved, each assigned to a person
```

Rules:
- A spec with zero non-goals or zero open questions has not been thought about hard enough. Add them or state why the task is genuinely trivial — in which case it doesn't need this skill.
- Interfaces are written in the target language (Rust types, JSON schemas), not English descriptions of them.
- The spec is the handoff unit. Jo or an agent session should be able to execute from the spec alone, without this conversation's history.

## Step 2: Plan

Append to the same spec file:

```markdown
## Plan
- [ ] Task 1 — <one atomic commit, ~100 lines max, independently verifiable>
- [ ] Task 2 — ...
## Verification per task — how each task is proven done (test name, manual check, or invariant)
```

Rules:
- Each task must be completable and verifiable in isolation. If a task can't be verified until three tasks later, restructure.
- Tasks touching contract paths inherit the doubt-driven-review + security-hardening gates automatically.
- Order tasks so the system compiles/runs after every commit. No "big bang" integration steps.

## Step 3: Execute against the plan

- Check off tasks in the spec file as commits land; the commit message references the spec (`SPEC-<feature>`: task N).
- Scope drift rule: work not in the plan gets added to the plan first (one line, with verification), then implemented. Undeclared drift is how immutable mistakes ship.
- When the plan is complete, the spec's Invariants section becomes the claim list for the final doubt-driven review.
