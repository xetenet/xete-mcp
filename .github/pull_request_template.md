## Spec
SPEC file: `specs/SPEC-________.md` (or "trivial — single atomic commit, no spec")

## Gates
- [ ] All commits atomic and green (git-discipline)
- [ ] Protected paths touched? If yes: `reviews/DDR-*.md` linked below with **Verdict: SHIP**
- [ ] Security gates section completed in DDR (no OPEN-GATE markers)
- [ ] Fresh-context adversarial review performed (subagent / second session / owl-alpha) — not self-review
- [ ] Scope drift: any work not in the original plan was added to the plan before implementation

DDR: `reviews/DDR-________.md`

## Invariants this PR must not break
<!-- copy from the SPEC's Invariants section -->
