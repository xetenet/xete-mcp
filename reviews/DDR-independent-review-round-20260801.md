# DDR: six findings from three commissioned independent reviews, all fixed rather than deferred

Commit scope: `src/xete_mcp/draft.py`, `src/xete_mcp/server.py`, `src/xete_mcp/txguard.py`,
`src/xete_mcp/alias_chain.py`, `test_draft_shape.py`, `test_txguard_prose.py`,
`test_alias_name_cf.py`, `test_settlement_robustness.py`

## Claim

`verify_draft` refuses every transaction that is not the exact instruction shape of an
honest deposit, and checks the durable-nonce account's IDENTITY against operator config
rather than against the draft. `txguard._rpc_call` cannot deliver attacker-chosen prose,
newlines or bidi into a message this client presents as its own. A `%name` cannot carry
invisible characters into `AliasChainError`.

**Explicitly NOT claimed:** that attacker text never appears inline in a refusal. It does —
see the residual under Reconciliation. What is closed is the STRUCTURAL vector: a flattened
single line cannot forge a tool-result block.

## Assumptions

| # | Assumption | Status |
|---|---|---|
| A1 | `draft.py` had been independently reviewed | **FALSIFIED** — never in scope, never read. The reviewer said so plainly when asked. See doubt 6 |
| A2 | Value-weighted checks cover the instruction set | **FALSIFIED** — a zero-lamport instruction contributes 0 and is filtered out of `destinations`, so it is invisible to every arithmetic check in the file. Four transactions certified `ok=True` on that basis |
| A3 | `scrub` was sufficient on the txguard raise sites | **FALSIFIED** — `scrub` is the CREDENTIAL sanitiser and leaves newlines and Cf intact by design |
| A4 | Both txguard raise sites were equally exposed | **FALSIFIED, and one was safe by ACCIDENT** — see doubt 4 |
| A5 | `normalize_name` rejects everything unprintable | **FALSIFIED** — Cf satisfies none of `isspace()`, `< 0x20`, `== 0x7F` |
| A6 | The shape whitelist does not kill the durable-nonce feature | **Verified — by the reviewer, not by me.** See doubt 7 |
| A7 | Each fix is load-bearing | **Verified by mutation, 11/11 red for the right reason** |

## Doubts raised

All six findings come from **three fresh-context adversarial reviews by s1**, an
independently-running session with its own clone and no shared history, commissioned
specifically because it had answered honestly that it had NOT covered these files. Every
finding was reproduced by execution against a hostile server or a real function call, never
by reading. Each was re-verified at this tree before any code moved.

1. **(s1 review A — A2)** *A zero-lamport, zero-space system `CreateAccount` is certified.*
   Decodes cleanly, moves nothing, and makes the RUNTIME reject the whole transaction
   because a 0-byte account is not rent-exempt. The human spends a signature and a fee and
   the escrow is never funded — the same harm class as the `[G12]` rent finding this file
   already carries a comment about.
   → **Fixed** by a shape whitelist.

2. **(s1 review A — the one with reach)** *An `AdvanceNonceAccount` for an ARBITRARY nonce
   account is certified.* The only finding with an effect OUTSIDE this transaction:
   advancing a durable nonce invalidates every transaction already queued against it, so a
   hostile drafter naming an account the depositor controls turns a deposit approval into
   the silent cancellation of an unrelated pending transaction of theirs, with nothing in
   the itemisation showing it.
   → **Fixed by IDENTITY, not by shape** — `expect_nonce_account`, supplied from
   `XETE_NONCE_ACCOUNT`, the operator's own config, never the draft. No shape check can
   tell an intended nonce account from an attacker-chosen one. **The asymmetry it exposed is
   the durable lesson:** `draft_deposit` reads the nonce account and refuses on an authority
   mismatch, so the BUILDER was careful about nonce identity while the VERIFIER — the half
   that exists to face a hostile builder — did not check it at all.

3. **(s1 review A)** *An `AdvanceNonceAccount` outside index 0, and a zero-lamport transfer
   to an attacker address, are both certified.* `draft_deposit`'s own comment says the nonce
   must be first or the runtime rejects it.
   → **Fixed by the same whitelist.** Chosen over patching `destinations` to stop filtering
   on `lamports > 0`, which fixes two of the four and leaves the ordering one alive. The
   reviewer's own note, which I am recording because it is a criticism of how this repo
   grows: **`txguard` already whitelists the shape and is strictly stronger than `draft.py`
   — the right pattern was next door, written here, before either of us said so.**

4. **(s1 review C — A3/A4)** *A hostile RPC writes ~200 characters of prose, with newlines,
   into the client's own refusal on the money path.* The guard is WORKING — the claim fails
   closed and no money moves — but `treasury_pubkey` re-raises the endpoint's text inside
   THIS CLIENT'S OWN SENTENCE, and `server.py` reports it deliberately untruncated. The live
   capture carried three real newlines and a forged `### TOOL RESULT` block.
   → **Fixed with both sanitisers, in order:** `scrub` (credentials) then `sanitize_text`
   (shape). **And writing the test found that one of the two sites was safe only by
   accident:** `str()` of a dict repr-escapes newlines, so the OBJECT form of a JSON-RPC
   error looked clean while nothing sanitised it. JSON-RPC does not require `error` to be an
   object and the hostile server picks the shape. Testing only that form would have produced
   a green that means nothing.

5. **(s1 review B — A5)** *A `%name` carries Cf characters into `AliasChainError`*, whose
   docstring promises "this client's own words, end to end" — the half a caller may present
   unattributed.
   → **Fixed at the guard, not at the three interpolations,** so the next site that
   interpolates `bare` inherits the guarantee instead of having to remember. The reviewer
   confirmed this is better than the fix it proposed, and that it preserves `bare` as exact
   bytes for `alias_pda`.

6. **(process, and the most important entry here)** *Three of these files had never been
   independently reviewed, and I nearly recorded that they had.* Asked to confirm coverage
   per artifact, the reviewer answered **two yeses, one partial and two noes** — and
   explicitly refused credit for one item: *"the claim-shape confirmation you cited is
   YOURS, not mine — citing me for it would be citing your own work under my name."*
   → **Risk closed by commissioning the missing reviews rather than rounding up.** Recorded
   in the reviewer's words because the failure mode needs a name: manufacturing independent
   review by attribution would have been **the sixth hollow control of the day and the first
   one written on purpose.**

7. **(s1, unprompted regression check)** *Did the shape whitelist kill the durable-nonce
   feature?* Its A2 probe used the LEGITIMATE nonce ordering, so a refusal was ambiguous
   between "identity caught it" and "the whitelist banned nonces outright" — and its own
   control covered only the no-nonce shape, so it could not have distinguished them.
   → **Verified alive**: legitimate nonce draft + correct expectation → `ok=True`; same
   draft + wrong expectation → `failures=['nonce_account']`; nonce draft with no expectation
   → `failures=['instruction_shape']` (fail-closed on config drift). **The distinction
   between shape and identity is the whole finding, and only this check proves the fix has
   both.** I did not think to run it.

## Reconciliation

- Doubts 1–5: **fixed**, each mutation-proven, each re-verified by the reviewer re-running
  its own PoCs against this tree rather than reading the commits.
- Doubt 6: **closed by commissioning the reviews.**
- Doubt 7: **verified**, and the check is now in `test_draft_shape.py` so it is not left as
  a one-time observation.
- **Open, accepted, 0.1.6 — attribution, not structure.** `sanitize_text` FLATTENS, it does
  not RELOCATE: ~200 characters of attacker text still sit inline and unlabelled in the
  `TransactionRejected` sentence. The structural vector is dead — a flattened single line
  cannot forge a block boundary — and it is mitigated by leading with `TRANSACTION REJECTED`
  and closing with "Nothing was signed". The proper fix is a `server_text` field on
  `TransactionRejected` mirroring `AliasChainError`, so it lands in `untrusted_server_text`.
  That is a refactor across every raise site, not a pre-publish change.
- **Open, cosmetic, logged:** `NONCE_ACCOUNT` is read at import time, which is the pattern
  the comment at `server.py:1945` calls out as a defect for `RPC_URL`. Harmless because
  draft and verify read the same constant and cannot disagree. Recorded so it is a known
  choice rather than an oversight.
- **Not covered, stated so it is not rounded up:** the reviewer did not fuzz the compact-u16
  parser, did not attack the compute-budget fee arithmetic beyond reading it, did not verify
  the ALT/v0 refusal empirically, and did not review `bounded_simulated_debit`.

## Verification

- **828 tests pass** from a bare `pytest` (was 813).
- **11 of 11 mutations red for the right reason** across the three fixes, including one that
  re-opens the credential leak while leaving the newline assertions green — that pair is the
  only thing distinguishing "composed both sanitisers" from "swapped one for the other".
- Every finding driven to failure before its fix existed; every control asserts an honest
  input still passes.
- Invariants: `spendguard.py` byte-identical to `ee81682`; 15 tools at runtime.

## Benchmark doubt prompts with overlapping Paths

- **BM-a-red-that-came-from-the-wrong-cause** — answered throughout. Every probe asserts it
  REACHED the guard under test before asserting anything, because the reviewer's own first
  probe was refused by `single_signer` (it had marked the attacker account as a signer) and
  was nearly written up as "the verifier catches this".
- **BM-a-guard-satisfied-by-the-absence-of-what-it-searches-for** — answered. The shape
  whitelist is a positive match against a closed set; unknown instructions get a kind that
  cannot match, so refusal is the default and the check never enumerates what is bad.
- **BM-unprovable-state-treated-as-proven** — answered. "Every program in this transaction
  is expected" was being treated as proof the transaction is what it claims; a zero-lamport
  instruction satisfies it and does damage anyway.

## Verdict: SHIP

Six findings across three commissioned reviews, all fixed rather than deferred, all
re-verified by the reviewer against this tree. The reviewer rated none a release blocker and
twice offered to record that it recommended shipping anyway; they were taken because every
one of them sits in the layer a human or an agent consults BEFORE committing money, and a
verifier that certifies transactions which cannot execute is failing at its only job.

Carry away: **the reviews existed because the reviewer said "I did not look at that" when
asked.** Three of these files would have merged with a fabricated claim of independent
coverage if it had rounded up, and the artifact would have looked identical.
