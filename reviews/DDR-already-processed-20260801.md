# DDR: the one endpoint refusal that means the transaction LANDED is no longer reported as a clean failure

Commit scope: `src/xete_mcp/payment.py`, `src/xete_mcp/settlement.py`,
`test_already_processed.py`

## Claim

When a node refuses a submission with `AlreadyProcessed` / "this transaction has already
been processed", neither `settlement._send` nor `payment.pay_herd` reports an outcome that a
caller can read as "nothing moved, safe to retry". Every other preflight refusal still
reports exactly that, unchanged.

**Explicitly NOT claimed:** that the transaction succeeded. `AlreadyProcessed` says it
LANDED, not that it did what you wanted — it may have landed and errored. The verdict moves
from `failed` to `unconfirmed`, and the message says to check the signature. It does not
move to `sent`.

**Also NOT claimed:** that this fixes the general one-endpoint-verdict problem. A single
endpoint still licenses `failed` for every other rejection. That is the wider F2 finding and
it is NOT closed here — see Reconciliation.

## Assumptions

| # | Assumption | Status |
|---|---|---|
| A1 | `failed` is read by callers as retry-safe | **Verified in source** — `server.py` maps `outcome in ("failed","dropped")` to `"status": "failed"` at three tool sites, which is the string an agent acts on |
| A2 | One spelling of the marker is enough | **FALSIFIED** — the prose form and solders' enum form share no substring. Both are matched; the mutation dropping either goes red |
| A3 | Only `settlement` has this branch | **FALSIFIED** — `payment.pay_herd` grew the identical branch hours earlier in the F4 fix, by copying the settlement split, and inherited the defect with the design. See doubt 2 |
| A4 | Widening the ambiguous case is safe | **FALSIFIED by this repo's own history** — see doubt 3 |
| A5 | Each fix is load-bearing | **Verified by mutation, 4/4 red for the right reason** |

## Doubts raised

The finding originates with the independent session (its F2, against an earlier tree),
re-verified here by writing the test first and watching six cases fail.

1. **(s1, F2)** *A single endpoint's word becomes a definitive `failed` — including when its
   own message says the transaction already landed.* On the settlement path a retry is a
   SECOND ESCROW DEPOSIT of real lamports; on the payment path it pays twice.
   → **Fixed for the self-contradicting case.** The endpoint is not being trusted more here;
   it is being read correctly. A refusal whose stated reason is "I already have this" cannot
   simultaneously license "nothing moved".

2. **(self)** *Did the F4 fix I shipped three hours ago inherit this?* — **Yes.**
   `payment.pay_herd`'s `RPCException` branch was written by copying `settlement._send`'s
   two-branch split, so it copied the defect too, and its message says "nothing was paid" —
   flatly false when the transaction landed.
   → **Fixed in both, from ONE definition.** `says_already_processed` lives in `payment`
   because `settlement` imports from `payment` and not the reverse. Two parallel
   implementations diverging is what produced this doubt; a shared helper is the only fix
   that stays fixed.

3. **(self, from the repo's own record)** *Should the ambiguous case be widened further —
   should any refusal become "may be live"?* — **No, and there is a written reason.**
   `DDR-settlement-submit-receipt-20260801` D2 records a reviewer's blanket `except
   Exception` here as an over-correction that turned every deterministic rejection into MAY
   BE LIVE, telling an agent not to retry the very thing it should fix.
   → **Risk accepted deliberately, and pinned in the opposite direction.** Six tests assert
   that ordinary rejections (custom program error, insufficient rent, InstructionError)
   still report `failed`, and the mutation making the detector return `True` unconditionally
   turns all six red. The guard has a ceiling as well as a floor.

4. **(self)** *Is a substring match on endpoint-chosen text sound?* — It is
   attacker-influenceable: a hostile endpoint can put "already been processed" in any
   refusal and downgrade a `failed` to `unconfirmed`.
   → **Risk accepted, and the direction is right.** The downgrade costs the caller a chain
   read and refuses to conclude; the reverse error costs a duplicate deposit. A hostile
   endpoint can already force `unconfirmed` for free by simply not answering, so this grants
   it nothing it did not have. Fails toward "go look", which is the correct failure for
   money.

## Reconciliation

- Doubts 1, 2: **fixed**, mutation-proven in both modules.
- Doubts 3, 4: **risk-accepted in writing**, each with tests pinning the boundary.
- **OPEN, and explicitly not closed by this commit:** the general case of F2 — one endpoint
  licensing `failed` for an ordinary rejection. Routing every refusal through corroboration
  doubles RPC cost on the submit path and converts ordinary node lag into hard failure; the
  same trade was tried and reverted on the alias-read path, where it broke 15 tests for
  exactly that reason (`DDR-alias-freshness-20260801`). The self-contradicting case is the
  part that is unambiguously wrong, and it is the part fixed here. Logged to
  `next-versions/xete-mcp.md` rather than left implied.

## Verification

- **803 tests pass** from a bare `pytest` (was 791).
- **4 of 4 mutations red for the right reason** — drop each branch, narrow the detector to
  one spelling, and widen it to match everything. The harness fails any red arriving with a
  collection or import error.
- 12 tests written first; the six already-processed cases watched red before any source
  change, the six ordinary-rejection cases green throughout.
- Invariants: `spendguard.py` byte-identical to `ee81682`; 15 tools at runtime.

## Benchmark doubt prompts with overlapping Paths

- **BM-a-red-that-came-from-the-wrong-cause** — answered, and it is why every test here
  asserts `e.signature` (arrival at the submit branch) BEFORE asserting anything about the
  outcome. A `SettlementSubmitError` from argument validation would otherwise satisfy the
  whole file.
- **BM-a-guard-satisfied-by-the-absence-of-what-it-searches-for** — answered. Nothing here
  passes by finding nothing; the ordinary-rejection tests assert a positive verdict string.
- **BM-unprovable-state-treated-as-proven** — answered, and it is the defect itself: "the
  endpoint refused" was treated as proof the transaction does not exist, when in this one
  case the refusal is proof that it does.

## Verdict: SHIP

The self-contradicting refusal is closed in both modules from one definition, with the
opposite direction pinned so the fix cannot drift into the over-correction this repo already
made once. The wider one-endpoint-verdict question is left open in writing rather than
quietly folded in.

Carry away: **the fix I shipped three hours ago propagated this bug into a second module by
being copied.** Duplicating a correct design duplicates whatever is wrong with it, and
neither copy looks suspicious.
