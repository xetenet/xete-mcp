# DDR: a payment that may be live can no longer reach the caller as a clean failure, and the endpoint can no longer name our transaction

Commit scope: `src/xete_mcp/payment.py`, `test_payment_double_pay.py`,
`test_published_tools_regression.py`

## Claim

Every exit from `pay_herd` at or past `send_transaction` carries the signature this client
computed locally, and the confirmation loop and return value use that signature rather than
the one the endpoint replied with. So no reachable path tells a caller "the payment failed"
about a transaction that may be on the cluster, and no path hands back a signature the
endpoint chose.

**Explicitly NOT claimed:** that a double-pay is now impossible. A caller who ignores
`DO_NOT_RETRY_BLINDLY` and retries anyway still pays twice — `send_multi` mints a fresh
nonce per call, so the second payment is a genuinely different transaction and nothing on
this side can deduplicate it. What changed is that the caller is now TOLD, and given the
signature that lets them check. Idempotency would need a nonce the caller controls across
retries, which is a relay-side change and is not in this diff.

## Assumptions

| # | Assumption | Status |
|---|---|---|
| A1 | F3 (the tool flattening a submitted payment into `failed`) is still open | **FALSIFIED** — already fixed at this HEAD; the reviewer saw an older tree. But it was pinned by NOTHING, so removing the branch was silent. Now pinned |
| A2 | Wrapping the submit is safe as a blanket `except Exception` | **FALSIFIED by this repo's own history** — see doubt 2 |
| A3 | The existing payment tests pin the local-signature property | **FALSIFIED** — `test_payment_confirmation.py` returns the same value for both, so every assertion passed either way. The distinction was invisible |
| A4 | Each fix is load-bearing | **Verified by mutation, 3/3**, after the harness was corrected — see doubt 4 |
| A5 | The behaviour change breaks no existing test | **FALSIFIED, one test** — `test_a_submitted_transaction_that_errors_still_counts`. Updated, and the update is recorded in the test itself. See doubt 3 |

## Doubts raised

Round 1 is a **fresh-context adversarial review by s1**, an independently-running session
with its own clone and no shared history, delivered as findings F3/F4/F5 against `44ea473`.
Every finding was re-verified at this HEAD by writing the test first and watching it fail;
one did not reproduce, and that is recorded rather than quietly dropped.

1. **(s1, F4 — A2)** *`client.send_transaction` is unguarded, and the signature computed two
   lines above it — with a comment saying its whole purpose is to survive exactly this — is
   dead on that path.* A transport failure after the write reaches the wire is
   indistinguishable from one that never left.
   → **Fixed** with a two-branch split. Verified red before the fix.

2. **(s1, F4 caveat — A2)** *Do not blanket-wrap.* s1 pointed at this repo's own
   `DDR-settlement-submit-receipt-20260801` D2, which records a previous reviewer's blanket
   `except Exception` here as an over-correction: it turned every deterministic rejection
   into "MAY BE LIVE", telling an agent not to retry the very thing it should fix.
   → **Honoured.** `RPCException` (the node simulated it and refused to forward) is reported
   as the failure it is; everything else is "may be live". Both directions have their own
   test, and the mutation that collapses them into one is red. **A reviewer citing our own
   prior DDR back at us is the single most useful thing in this review** — without it the
   obvious fix would have re-introduced a defect this project had already paid for once.

3. **(s1, F5 — A3)** *The RPC endpoint gets to name our transaction.* `sig` came from the
   endpoint's reply and was what the loop polled and what the function RETURNED, while the
   messages quoted `sig_local`. `settlement.py` already refuses this and says why; this
   module was the second instance, not the counter-example an earlier report called it.
   → **Fixed**: mismatch is refused, and the poll and return use the local value. Note the
   consequence for testability, stated because it looks like a weakness and is not: past the
   refusal the two signatures are provably equal, so "the loop polls the local one" is no
   longer independently observable. The refusal is what makes it true, and the refusal is
   what is tested.

4. **(s1, F3 — A1)** *A durably-submitted payment reported as bare `failed` with no
   signature.* **Did not reproduce.** The `PaymentNotSettled` handler already precedes the
   generic one at this HEAD; s1 reviewed an older tree. I initially concluded this by
   READING the handler order, which was right by luck — the first version of the test failed
   for three unrelated harness reasons (wrong client method, missing payer, wrong invoice
   shape) before it could say anything about the code.
   → **Risk accepted as already-fixed, and pinned.** The ordering is load-bearing
   (`PaymentNotSettled` is a `RuntimeError` subclass) and nothing asserted it.

5. **(self)** *Is each fix load-bearing?* — The first mutation run reported all three red,
   and **one of those reds was worthless**: the mutation produced an `IndentationError`, so
   pytest reported `1 error` and the harness counted a non-zero exit as success.
   → **Fixed in the harness: a red accompanied by a collection error, `SyntaxError`,
   `IndentationError` or `NameError` is now reported as RED FOR THE WRONG REASON and fails
   the run.** This is s1's own lesson from an hour earlier — it lost two runs to a heredoc
   turning `\b` into a literal backspace, and wrote *"red is not evidence either"*. I had
   been auditing greens and treating reds as self-validating. Both of us reached the same
   place independently on the same afternoon.

## Reconciliation

- Doubts 1, 2, 3, 5: **fixed**, each with a test proven red for the right reason.
- Doubt 4: **risk-accepted as already-closed**, now pinned by a regression test.
- **One existing test updated**, `test_a_submitted_transaction_that_errors_still_counts`. It
  asserted a bare `TimeoutError` escaping `pay_herd` — which was the defect, not the
  contract. The property it exists for (submitted means charged; the spend is not released)
  is asserted unchanged, and two assertions were ADDED (the signature survives; the
  transport error stays reachable as `__cause__`). The reasoning is recorded in the test
  body, not only here, because "changed a test so my fix passes" is indistinguishable from
  weakening one unless the diff itself says which it is.
- **Open, deliberate:** retry idempotency. Stated under the claim above; it needs a
  caller-stable nonce and belongs to the relay, not to this client.

## Verification

- **773 tests pass** from a bare `pytest` (was 768).
- **3 of 3 mutations red for the right reason**, sources restored byte-identical.
- F3/F4/F5 each driven to failure before the fix existed.
- Invariants: `spendguard.py` byte-identical to `ee81682`; 15 tools at runtime.

## Benchmark doubt prompts with overlapping Paths

- **BM-a-guard-satisfied-by-the-absence-of-what-it-searches-for** — answered. No check here
  passes by finding nothing; every test drives real code and asserts a positive fact.
- **BM-the-one-site-that-produced-no-conflict** — answered, and it is doubt 5.
- **BM-unprovable-state-treated-as-proven** — answered, and it is the whole point: "the
  submit call raised" was being treated as proof the transaction does not exist. It is not
  proof of anything, and the code now says so.

## Verdict: SHIP

Three findings from an independent session, all reproduced by execution before any code
moved, all fixed, all mutation-proven. One finding did not reproduce and is written up as
not-reproduced rather than quietly closed.

The thing to carry away: the reviewer's most valuable contribution was not a defect. It was
**citing our own earlier DDR to stop the obvious fix**, which would have re-introduced an
over-correction this project had already diagnosed and written down once.
