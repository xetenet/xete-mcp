# DDR: a settlement transaction that is or may be live on the cluster is never reported as a clean failure, and the signature — known locally before submission — is never thrown away

Commit scope:
- `src/xete_mcp/settlement.py` — the submit boundary, the returned-signature check, the
  corroborated `dropped` verdict, the commitment gate on an on-chain error (G9, G13, G15)
- `src/xete_mcp/server.py` — the optional receipt, signature carry-through in all three
  settlement tools' generic handlers, `determinate` in every `xete_settle_status` shape
  (G8, G19)
- `test_settlement_robustness.py` — 27 new tests; two fixtures recalibrated (see C7)

Input: `~/GATE-FINDINGS.md` findings **G8, G9, G13, G15, G19**, from an adversarial money-path
review of the settlement escrow lifecycle at integration tip `cb1ccb4`. Verdict on that lens:
**needs-work**. All five are one bug wearing five hats.

`src/xete_mcp/spendguard.py` was OFF LIMITS and is byte-for-byte unchanged —
`git diff ee81682 -- src/xete_mcp/spendguard.py` is empty, re-verified after the last edit.
No Solana transaction was built against a real cluster and none was submitted; every RPC in
every test is a fake.

---

## Claim

1. **(G8)** `xete_settle_claim` reports a CONFIRMED claim as claimed even when the balance read
   that measures the receipt fails. `received_sol` becomes null with a note; it is never divided.
   Either trigger — the pre-submit read or the post-submit read — is covered.
2. **(G8, second half)** All three settlement tools' generic `except Exception` carry a signature
   they already hold rather than emitting a bare failure. A signature exists in those handlers
   only because `settlement.deposit/claim/reclaim` RETURNED, which happens only on a durable
   confirmation, so `"failed"` is never the honest word there.
3. **(G9)** `client.send_transaction` is inside the guarded region and the "the transaction is or
   may be live" boundary comment sits above it. A transport failure on that call raises
   `SettlementSubmitError(outcome="unconfirmed")` carrying `str(tx.signatures[0])`, computed
   locally before submission, plus the deposit ticket.
4. **(G13)** The signature the endpoint returns is compared to the locally signed one. A mismatch
   refuses; polling uses the local `Signature` object regardless; no field an agent could lift a
   signature from ever carries the endpoint's.
5. **(G15)** `outcome="dropped"` requires a second, independently-configured endpoint to agree
   that it has no status for the signature AND that the blockhash is dead. Uncorroborated, the
   same observation is reported as `unconfirmed` with the evidence named — still early, so no
   responsiveness is lost.
6. **(G19)** Every response shape of `xete_settle_status` carries a real boolean `determinate`,
   including the two argument refusals and the read-failed branch. That is the field every
   unconfirmed-submit message tells the agent to read first.

---

## Assumptions (verified / inherited / accepted)

| # | Assumption | Status |
|---|---|---|
| A1 | `tx.signatures[0]` after `Transaction(signers, msg, bh)` is the id the cluster will index the transaction under, and is available before submission | **verified** — ed25519 over the signed message, computed by solders locally; the tests assert `_send`'s return value equals it on the happy path, and the recalibrated fakes echo it |
| A2 | `settlement.deposit/claim/reclaim` return only on a durable confirmation, so a signature in the tool scope means the money moved | **verified** — the only `return` out of `_send` is the `_DURABLE` branch of `_await_confirmation`; every other exit raises |
| A3 | `RPCException` (JSON-RPC error) means the endpoint answered and, with `skip_preflight=False`, did not forward; `SolanaRpcException`/transport errors do not | **accepted, not provable from this side** — see D2 and Residual risks |
| A4 | Two endpoints that must agree is worth more than one — i.e. `second_rpc_url` really returns a different operator | **BROKEN, and NOT fixed here** — see D7 |
| A5 | The AST anti-bypass tripwire still classifies every submit/sign site | **verified** — `settlement.py:_send` is still the only submit site; `_corroborate_dropped` adds none; 4/4 gate tests pass |
| A6 | `Client(url, timeout=...)` is the supported way to bound a solana-py request | **verified** — `inspect.signature(Client.__init__)` → `(endpoint, commitment, timeout=10, ...)` |
| A7 | Not closing the corroborating `Client` is consistent with the module | **accepted** — `_read_account` constructs a `Client` per call and never closes one either; solana-py's sync `Client` exposes no `close()`, only `_provider.session`. Reaching into a private attribute in one place only would be worse |

---

## Doubts raised

**D1 (fresh-context Claude, headless `claude -p`, separate process, no conversation history).**
Given the `src/` diff, the nine claims C1–C9 below, and instructions to break them with scripts
it actually runs. It ran 5 attack files (`/tmp/ddr_attack/`, `/tmp/ddr_adv/`), 15 mutants, and a
HEAD-vs-change A/B. It returned **BROKEN for five of nine**. Recorded as genuine fresh context,
not self-review. Tree verified untouched by it (`git status --porcelain` unchanged).

**D2 (fresh context) — C5(a) BROKEN. The G9 guard over-corrected.** *With
`skip_preflight=False` the endpoint simulates and refuses to forward what fails, so wrapping
`send_transaction` in a blanket `except Exception` turned every DETERMINISTIC rejection — wrong
salt, escrow already claimed, insufficient lamports — into `submitted_unconfirmed` +
"MAY ALREADY BE LIVE… Do not re-claim". Its A/B: HEAD says `failed`/no signature; the change says
`submitted_unconfirmed`/`claims live? True`/`tells agent not to retry? True`.* It named the
one-line separation: `RPCException` = the endpoint answered and refused; transport = ambiguous.

**D3 (fresh context) — C6 BROKEN.** *`xete_settle_status`'s two argument guards
(`_escrow_id_error`, `_salt_error`) return the exact `{"status","error"}` shape G19 deleted, with
no `determinate` and no `open`. Reachable exactly where it hurts: escrow_ids and salts arrive in
claim tickets, which arrive in the inbox. The property test "a property rather than a case"
enumerated four dict shapes and missed both guards.*

**D4 (fresh context) — C8 BROKEN on hang.** *`_corroborate_dropped` makes two requests from
inside a loop whose docstring promises `budget` bounds the total; solana-py's default is 10s per
request. Measured: `budget=7.0s elapsed=11.78s overshoot=+4.78s`. Also: the second `Client` is
never closed.*

**D5 (fresh context) — C7 caveat.** *Mutation testing killed 12 of 15 mutants. Three survived:
the `_corroborate_dropped` branch where the second endpoint does NOT agree the blockhash is dead,
and the new signature-carry in `xete_settle_create`'s and `xete_settle_reclaim`'s generic
handlers — working code with zero coverage.*

**D6 (fresh context) — C1 BROKEN, and it called this the single most serious thing.** *`st.err`
is concluded from ONE endpoint, on the FIRST poll, at `Processed` commitment — the exact level
this module refuses to accept as success one line below because it "can still be forked away".
It accepts it as failure unconditionally. That is the same single-source defect G15 fixed for
`dropped`, standing on the neighbouring branch and far cheaper to reach: one poll versus twenty
plus a dead blockhash plus corroboration. The tools then read `submit_outcome == "failed"` as
licence for "you were not paid".*

**D7 (fresh context) — C4 BROKEN.** *`second_rpc_url` decides "independently-operated" by raw
string equality, so `https://rpc.example` + `https://rpc.example/` (or host-case, or a query
string) corroborates itself and produces `dropped` from one host. Separately: `isBlockhashValid:
false` plus "no status" is also what a LAGGING or forked node answers.*

**D8 (fresh context) — C3 caveat.** *The endpoint controls the exception text, and the tools
truncate `str(e)` at 400 characters — so `Check signature <ours>` at the end of the message was
cut off while an attacker-supplied signature-shaped token survived at the front. "The message
promises a recovery string it no longer contains."*

**D9 (fresh context) — C2 caveat.** *A `BaseException` after submit still discards everything:
no tool output at all. This repo already documents pyo3 `PanicException` reaching these tools.*

**D10 (self, during the fix).** *Does downgrading a single-endpoint `dropped` to `unconfirmed`
cost 90 seconds of a blocked stdio session in the common honest case?*

**D11 (self).** *Making the fakes return the transaction's own signature touches ten existing
assertions. Is that weakening them?*

---

## Reconciliation

**D1 — RAN, and it broke five claims.** A separate `claude -p` process with no history, given
the diff and the claim list and told to break them. It returned VERIFIED for C2 (with D9's
caveat), C3 (with D8's), C7 (with D5's), C9, and C5(b)/(c); **BROKEN for C1, C4, C5(a), C6, C8**.
Every break came with a script and its output. Five of the six actionable ones are fixed below;
the sixth (C4) is another stage's finding and is recorded as a dependency, not silently absorbed.

**D2 — FIXED.** `except RPCException` now precedes the generic handler. An endpoint that
ANSWERED with a JSON-RPC error is reported `outcome="failed"` with text that says it was rejected
at submit, did not execute, and should be fixed and retried — **but the signature is carried
anyway**, which HEAD did not do, and the message names the one case where that matters ("a node
that refused a transaction it had already forwarded would look the same"). Transport failures
keep the G9 treatment. Tests: `test_a_preflight_refusal_is_a_failure_not_a_maybe_live_transaction`,
`test_the_claim_tool_tells_an_agent_to_fix_a_rejected_claim_not_to_wait`, and the counter-guard
`test_a_transport_failure_is_still_treated_as_possibly_live`.

**D3 — FIXED.** Both guards route through `_status_refusal`, which re-emits the shared refusal
with `open: null`, `determinate: false` and the warning key. It is scoped to
`xete_settle_status`: `xete_settle_claim`/`_reclaim` share the same helpers and must keep their
own shape. Test: `test_settle_status_argument_refusals_also_carry_determinate`, parameterised
over both guards.

**D4 — FIXED for the hang; the unclosed client is ACCEPTED (A7).** `_corroborate_dropped` takes
a `timeout`, clamped at the call site to `min(_CORROBORATION_TIMEOUT=5.0, remaining budget)`, and
`_await_confirmation`'s docstring now states the bound honestly instead of over-promising: the
polling budget plus at most ONE corroboration excursion, which can happen only once because every
branch out of it either raises or sets `seen`. Test: `test_the_corroboration_is_time_bounded`.

**D5 — FIXED.** All three survivors now have tests:
`test_a_second_endpoint_that_calls_the_blockhash_alive_blocks_the_dropped_verdict` and
`test_create_and_reclaim_also_carry_a_signature_out_of_the_generic_handler` (parameterised over
both tools).

**D6 — FIXED, and it is the best thing this round found.** `st.err` is now believed only at a
DURABLE commitment. At `Processed` the poller keeps watching: a real on-chain error reaches
`Confirmed` within a poll or two and is reported then, and anything that never does times out as
`unconfirmed` with the signature. This restores the module's own symmetry — `Processed` is not
proof of success, so it cannot be proof of failure. Tests:
`test_an_error_at_processed_is_not_yet_a_definite_failure` and the over-correction guard
`test_an_error_that_reaches_a_durable_status_is_still_a_definite_failure`. Both existing
on-chain-error tests use `Confirmed`/`Finalized` and pass unmodified.

**D7 — CONFIRMED, NOT FIXED HERE, and the dependency is written into the code.** The reviewer is
right, and it is not this change's finding: `second_rpc_url`'s raw-string dedupe is **[G10]** and
**[G16]** in the same findings file, both assigned elsewhere, both with the same suggested fix
(normalise on `(scheme, hostname, port)`). Touching it here would collide with that work. What
this change does instead is state the dependency at the point of use — `_corroborate_dropped`'s
docstring says in terms that it "is no stronger than the answer it gets there". The direction of
error is still an improvement: before, `dropped` needed no second endpoint at all. Recorded as
unresolved.
The second half — a lagging node answers "no status" + "blockhash dead" too — is real and
irreducible from the client. It is why the verdict requires two sources rather than being
abolished, and it is a residual risk below.

**D8 — FIXED.** Every `SettlementSubmitError` message on this path now leads with OUR signature
and puts endpoint-controlled text last, with a comment saying why. Asserted at the tool layer,
where the truncation actually happens:
`test_a_foreign_signature_never_reaches_the_caller_as_a_success` requires the local signature to
survive `str(e)[:400]` and the foreign one to appear in no field of the response at all.

**D9 — ACCEPTED, documented.** A `BaseException` cannot be converted into a
`SettlementSubmitError` without swallowing `KeyboardInterrupt` and `SystemExit`. The panic path
this repo actually documents is `find_program_address` on a bad seed, and it is already
unreachable from here: `parse_escrow_id`/`escrow_pda` validate before solders, and
`_escrow_id_error` runs as the first statement of every tool. Residual risk below.

**D10 — REFUTED by design.** The uncorroborated case still exits EARLY, at the same poll the old
code did; only the verdict changed, from `dropped` to `unconfirmed` with the observation named as
evidence. No wall-clock behaviour changed. The agent's recovery is one `xete_settle_status` call,
which for a claim answers `determinate=true, open=true` → "it did not land and you can safely
retry" — the same conclusion, reached from the chain instead of from one endpoint's word.

**D11 — REFUTED, and the fresh-context pass agreed independently.** `_SendClient` returned the
constant `"SiGnAtUrE"`, which no real RPC could return: the signature is ed25519 over the message
the client just signed and is fixed before submission. The fakes now echo the transaction's own
signature, and the assertions changed from `== "SiGnAtUrE"` to `== client.signature`, which reads
`_tx.signatures[0]`. The reviewer's words: "Both recalibrations are *stronger*, not weaker …
`assert _send(client) == client.signature` now pins 'returns the **locally signed** signature'
where the old constant only pinned 'returns whatever the RPC said'." Its 15-mutant pass killed
the single-endpoint-drop mutant *with* the recalibrated
`test_a_dead_blockhash_with_no_status_is_reported_as_definitely_dropped`, whose assertion
(`outcome == "dropped"`) is unchanged — only its fixture now configures the second endpoint the
verdict requires.

---

## Red/green evidence

Every fix was demonstrated RED before and GREEN after, one reverted hunk at a time, in a scratch
copy of the tree (`/tmp/red`, harnesses `revert.py` / `revert2.py`). Round 1: `G8a` (the
division) → 2 red; `G8b` (signature carry) → 1; `G9` (the unguarded submit) → 5; `G13` (the
signature comparison) → 2; `G15` (uncorroborated `dropped`) → 4; `G19` (the missing
`determinate`) → 2. Round 2, the fixes the fresh-context pass forced: `D2` → 2 red; `D1/D6` (the
`Processed` gate) → 1; `D3` (the status guards) → 2; `D4` (the timeout) → 1; `D6a`/`D6b`
(create's and reclaim's signature carry) → 1 each. The complete new test file was also run
against pristine `HEAD` source: **16 failed, 137 passed** — the 137 being exactly the pre-change
count, which is what shows the fixture recalibration did not break anything on old code either.

Three of the new tests are OVER-CORRECTION GUARDS and pass on both old and new code by design,
and are labelled as such in the file: `test_a_failure_before_the_send_call_is_still_an_ordinary_error`,
`test_a_transport_failure_is_still_treated_as_possibly_live`,
`test_an_error_that_reaches_a_durable_status_is_still_a_definite_failure`.

---

## Findings NOT fixed (reported, with reasons)

- **[G10] / [G16] — `second_rpc_url` and `alias_rpc_endpoints` de-duplicate by raw string.**
  Assigned to another stage; fixing it here would collide. It is the load-bearing dependency of
  G15's corroboration and is named as such in `_corroborate_dropped`'s docstring. **Unresolved.**
- **A lagging or forked node answers "no status" + "blockhash dead" exactly like a node whose
  cluster really dropped the transaction.** Irreducible from the client; requiring two sources is
  the mitigation, not a cure. The signature is always retained, so the answer is always
  checkable.
- **`BaseException` after submit** (D9) — see Reconciliation.

---

## Benchmarks

Per the doubt-driven-review skill, one `benchmarks/BM-*.md` per real defect on a protected path:
`BM-a-live-transaction-reported-as-a-clean-failure.md` (the five findings as one shape) and
`BM-a-verdict-cheaper-than-the-one-you-hardened.md` (D6: hardening `dropped` to two sources while
`st.err` reached the same flat failure in one poll). **Deliberately not staged** —
`.gitignore:81` excludes `benchmarks/` with an explicit reason: BM files document live exploit
paths and this repo is public. They are on disk at `/Users/johnhedrick/wt-int/benchmarks/`.

---

## Residual risks accepted

- **A hostile endpoint can still force `{"status": "failed"}`** by returning a JSON-RPC error
  from `sendTransaction` while forwarding the transaction anyway. This is HEAD's behaviour minus
  the signature loss: the signature is now carried and the message says in terms that a node
  which refused a transaction it had already forwarded would look identical. Refusing to conclude
  here instead would make every wrong-salt claim read as "may still land", which is D2.
- **`dropped` inherits `second_rpc_url`'s string-equality notion of "independent"** (D7).
- **The corroborating `Client` is not closed** (A7) — the same is true of every other `Client` in
  this module, and solana-py's sync client exposes no `close()`.
- **`BaseException` after a successful submit** discards the signature (D9). Unfixable without
  swallowing Ctrl-C; the reachable panic path is already guarded upstream.
- **Pre-existing, not from this change:** `test_status_confirms_an_escrow_that_really_is_yours`
  fails if `XETE_RPC_URL_2` is set in the ambient environment. The fresh-context pass reproduced
  it at HEAD. New tests that depend on the variable being unset now `delenv` it explicitly.

---

## Verdict: SHIP

528 tests pass (501 pre-existing, unmodified apart from the two fixture recalibrations argued in
D11, + 27 new); the suite was run twice end to end with identical results. Every fix was
demonstrated RED on reverted code and GREEN after — twelve reverted-hunk scenarios across two
rounds, plus the whole new file against pristine `HEAD`. A genuine fresh-context adversarial pass
ran against this change, broke five of nine claims, and five of those six actionable breaks are
closed with tests; the sixth is another stage's finding and is recorded as unresolved rather than
absorbed. `spendguard.py` byte-identical to `ee81682`. No transaction was ever built against a
real cluster and none was submitted.
