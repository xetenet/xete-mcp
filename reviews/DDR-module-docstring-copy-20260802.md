# DDR: every docstring in the published package is swept for the copy directive, by AST walk rather than by a list of places to look

Commit scope: `src/xete_mcp/payment.py`, `src/xete_mcp/server.py` (module docstrings),
`test_copy_compliance.py`, `next-versions/xete-mcp.md`

## Claim

No docstring in any shipped module — module, class or function — asserts that sending a
message costs, could cost, or is free-for-now, with one named and escalated exception; and
the check that says so requires no maintained list of files or symbols, so it cannot go
stale when a module is added.

**Explicitly NOT claimed:** that `spendguard.py` complies. It does not, deliberately, and
the reason is a collision between two standing rules that is escalated rather than resolved.

**Also NOT claimed:** that this warrants a release. Module docstrings do not reach an MCP
tool picker.

## Assumptions

| # | Assumption | Status |
|---|---|---|
| A1 | Round 2 (source files + `.mcpb` + tool docstrings) completed the fix | **FALSIFIED** — module docstrings survived it. Third round of the same violation |
| A2 | The reviewer's report was the full extent | **FALSIFIED** — it found `server.py`'s; sweeping the INSTALLED wheel myself found `payment.py`'s, which is worse |
| A3 | An enumerated surface list can be completed | **FALSIFIED, and this is the finding** — see doubt 2 |
| A4 | Everything the wider sweep flags is a violation | **FALSIFIED** — one idiom. See doubt 3 |
| A5 | The fix can be applied uniformly across the package | **FALSIFIED** — `spendguard.py` is frozen. See doubt 4 |

## Doubts raised

1. **(s1 — A1/A2)** *The module docstring at the top of `server.py` still carries the
   claim.* Found by widening from tool docstrings to every docstring via AST.
   → **Fixed.** And re-sweeping the installed 0.1.6 wheel myself surfaced a second:
   `payment.py`'s module docstring said outright **"Sending a message costs SOL
   (anti-spam)"** — the most direct statement of the forbidden thing, shipped in the wheel,
   and absent from the reviewer's report. Two independent sweeps, each incomplete, each
   incomplete differently.

2. **(self, and the transferable one — A3)** *Why did this take three rounds?* Round 1 fixed
   `server.json` and `README`. Round 2 fixed the built `.mcpb` and the tool docstrings.
   Round 3 is module docstrings. Every round widened an **enumerated list of places to
   look**, and every round the list was incomplete in a way that was invisible from inside
   it.
   → **Mechanism changed rather than list extended.** The guard now walks every docstring in
   every module via AST. It needs no list, so it cannot go stale when a file is added — the
   failure mode that produced rounds 2 and 3. *"Complete surface list" is not a list anyone
   has ever finished writing.*

3. **(self — A4)** *Does the wider sweep over-refuse?* Yes: `_reject_confusable_name`'s
   docstring says confusable and messaging paths are *"free to render whatever the registry
   holds"* — an English idiom, not a price claim.
   → **Allow-listed explicitly, with the reason inline.** Not fixed by loosening the
   pattern, which would have silently re-admitted real violations; and the existing
   reachability test means this exemption fails the build if it ever stops matching.

4. **(self — A5) TWO STANDING RULES COLLIDE, AND I DID NOT PICK ONE.** `spendguard.py`'s
   module docstring says *"The amount charged for a message is quoted by the server being
   paid"*. That is a violation on a published surface. The file is also under a standing
   freeze — byte-identical to `ee81682` — because it is the money gate and every edit
   demands deliberate re-verification.
   → **Escalated to `next-versions/xete-mcp.md` with three options costed, not resolved.**
   Editing a docstring changes no behaviour, but it spends the byte-identity invariant that
   several checks and DDRs cite, and *"it was only a comment"* is exactly how a frozen file
   stops being frozen. `test_copy_compliance.py` excludes the file **by name, with a comment
   pointing at the escalation**, so the carve-out is a visible signpost rather than a silent
   hole.

## Reconciliation

- Doubts 1, 2, 3: **fixed**, guard extended by mechanism rather than by enumeration.
- Doubt 4: **escalated, unresolved by design.** Whichever way it goes is a decision about a
  money-path invariant and belongs to the person who set it.
- **Open, accepted:** the published 0.1.6 wheel contains the `payment.py` and `server.py`
  strings. Not worth a release on its own — module docstrings are not rendered by MCP
  clients, and the exposure is doc-ingesting directories reading the artifact. Rides the
  next release.

## Verification

- **838 tests pass** from a bare `pytest` (was 837).
- The violation was verified in the **INSTALLED 0.1.6 package from PyPI**, not the local
  tree, before anything was edited.
- `spendguard.py` byte-identical to `ee81682` (0 diff lines) — the freeze is intact, which
  is the point of doubt 4.
- 15 tools at runtime.

## Benchmark doubt prompts with overlapping Paths

- **BM-a-guard-satisfied-by-the-absence-of-what-it-searches-for** — answered. The new sweep
  cannot pass by finding nothing: the vacuity test asserts the matcher still fires on the
  strings that actually shipped, and the reachability test fails on any dead exemption.
- **BM-a-red-that-came-from-the-wrong-cause** — answered; the idiom in doubt 3 is precisely
  a hit for the wrong reason, and it is allow-listed with a stated cause rather than
  silenced by weakening the pattern.

## Verdict: SHIP

Third round of one violation, and the durable output is not the two corrected strings — it
is that the check stopped being a list.

Carry away: **two independent sweeps by two sessions were each incomplete, and differently
incomplete.** Neither of us could see our own missing surface from inside our own
enumeration. When a rule must hold across "everywhere", the mechanism has to enumerate
itself.
