# DDR: the rent-exempt reserve is not a charge on the signer, the deposit's third account is checked, and the one money-path RPC site that produced no merge conflict is re-pointed and pinned

Commit scope:
- `src/xete_mcp/settlement.py` — `RENT_EXEMPT_LAMPORTS` (one source of truth, with the read-only
  mainnet deltas in the comment); `validate_deposit_amount()`, called from `deposit_ix` and from
  `deposit` **before** the spend gate (G12)
- `src/xete_mcp/draft.py` — `ESCROW_RENT_LAMPORTS` re-exported rather than recomputed; the
  `additional_charges_at_execution` disclosure corrected to `amount + fee`; new
  `amount_covers_rent` and `system_program_account` checks in `_verify_draft` (G12, G14)
- `src/xete_mcp/server.py` — `draft.draft_deposit(_signing_rpc_url(), ...)` (G20); `_echo()` and
  every caller-supplied argument routed through it in the four alias tools; `xete_alias_claim`
  reports the canonical `bare` where it used to echo the raw argument (G21); the
  `xete_settle_create` docstring's rent sentence corrected (G12)
- `src/xete_mcp/alias_chain.py` — the length branch of `normalize_name` no longer quotes the
  whole over-long name (G21)
- `test_alias_read_hardening.py`, `test_settlement_robustness.py`, `test_signing_regression.py`,
  `test_spendguard.py` — 28 new tests; the tripwire refactor; two pre-existing tests changed
  (one fixture value, one rename — see D8)
- `benchmarks/BM-a-constant-whose-value-was-checked-and-whose-meaning-was-not.md`,
  `benchmarks/BM-the-one-site-that-produced-no-conflict.md`

Input: `~/GATE-FINDINGS.md` findings **G12** (medium), **G14** (low), **G20** (medium),
**G21** (medium), **G22** (low), **G23** (low). G12/G14 are the money-path reviewer's
draft/verify items; G20–G23 are the merge-resolution audit's.

`src/xete_mcp/spendguard.py` was OFF LIMITS and is byte-for-byte unchanged —
`git diff ee81682 -- src/xete_mcp/spendguard.py` is empty, re-verified after the last edit.
G22 is closed entirely in `test_spendguard.py`; no production spendguard code was needed.

No Solana transaction was built against a real cluster and none was submitted. The only network
traffic was read-only `getTransaction` and `getMinimumBalanceForRentExemption` against
api.mainnet-beta, quoted below. Nothing was pushed; no remote touched.

This closes `DDR-settlement-hardening-20260801`'s assumption **A6**, which was recorded as
"verified arithmetically" and is false as written.

---

## Claim

1. **(G12, arithmetic)** The rent-exempt reserve is not an additional charge on the depositor.
   The program funds the escrow account with exactly `amount`, so the debit is `amount + fee`,
   and that is what the disclosure a human reads before signing now says.
2. **(G12, floor)** Because the reserve comes out of the amount, `amount` has a floor. An amount
   below `RENT_EXEMPT_LAMPORTS` is refused by `settlement.validate_deposit_amount` — from
   `deposit_ix` (both paths) and from `deposit` before the spend gate — and by the verifier's
   `amount_covers_rent` check. No draft that cannot execute is certified SAFE TO REVIEW AND SIGN.
3. **(G14)** `verify_draft` refuses a deposit whose third account is not the system program,
   including when the account list is short, and refuses no honest draft.
4. **(G20)** No money-path RPC site reads the import-time `RPC_URL` constant. Only
   `_signing_rpc_url` and `alias_rpc_endpoints` may name it at all, and that is asserted
   statically so reverting any site costs a red test.
5. **(G21)** No caller-supplied argument is echoed back to an agent unflattened or unbounded by
   `xete_alias_claim`, `xete_alias_quote`, `xete_alias_resolve`, `xete_alias_reverse` or
   `xete_resolve`, and `normalize_name`'s length refusal no longer quotes the whole name.
6. **(G22)** The spend-gate tripwire fails if a directly-gated path calls `authorize()` more than
   once, OR calls it inside a loop, and both rules are proven to bite — against a reconstruction
   of the double-gated merge and against a loop that charges N times from one line.
7. **(G23)** The coverage handoff in `test_signing_regression.py` names the file that actually
   holds the assertion, and the pointer is executable rather than prose.
8. **No existing assertion was weakened.** Two pre-existing tests changed: one fixture value
   (1_000_000 -> 2_000_000 lamports, because 1_000_000 is now an impossible deposit) and one
   rename with byte-identical assertions.

---

## Assumptions (verified / inherited / accepted)

| # | Assumption | Status |
|---|---|---|
| A1 | The program funds the escrow with exactly `amount`, so the debit is `amount + fee` | **verified, read-only mainnet, this session.** `getTransaction` on deposit `4zAVuxHQ...`: fee 5060; depositor `DUDEJNEB` 90_000_000 -> 20_994_940 (delta -69_005_060 = amount + fee); PDA `27hLEGEL` 0 -> +69_000_000; decoded inner CPI = system `create_account`, lamports 69_000_000, space 81, owner `GPCsJ6kv...`. If rent were additional the debit would have been 70_459_700 |
| A2 | `1_454_640` is the rent-exempt minimum for 81 bytes | **verified** — `getMinimumBalanceForRentExemption(81)` = 1454640 on mainnet, equal to `(128 + 81) * 3480 * 2` |
| A3 | An account created below the rent-exempt minimum makes the transaction fail | **inherited from the runtime's documented `InsufficientFundsForRent` rule; not executed against a validator.** Direction of error is safe: the consequence is a refusal I am asking for, not a permission. If it were wrong, the cost is over-refusal of sub-0.00145-SOL deposits, and A1 is unaffected |
| A4 | `STATE_LEN = 81` cannot drift under the constant | **verified by the prior lens and re-read here** — the program is immutable (null upgrade authority), the single historical deposit allocated 81, and `status()` answers `open: null` rather than `open: false` if a layout it does not recognise ever appears |
| A5 | No legitimate deposit is below the floor | **verified by construction** — `deposit`/`draft_deposit` always create a NEW PDA from a random escrow id, so every deposit is an account creation. There is no top-up path this refuses |
| A6 | `accounts[2] == SYS` is required by the program, not merely conventional | **verified from the chain** — the deposit's inner instruction is a system-program CPI, which requires the system program in the instruction's account list. Confirmed against `settlement.deposit_ix`, which is the byte-identical source both paths build from |
| A7 | The `alias_rpc_endpoints` exemption in the new AST tripwire is not a hole | **verified, ran it** — `alias_chain.resolve_owner("bob", "http://evil.example.com")` raises `InsecureEndpoint` with nothing sent, so a plain-http entry in that list is refused downstream before any request |
| A8 | Reporting `bare` instead of the raw `name` in `xete_alias_claim` breaks nothing | **verified** — the tool's success path, its `/alias/claim` POST and its `/alias/claim/confirm` POST already used `bare`; the refusal paths were the inconsistency. 631 tests green, including `test_claim_posts_the_normalised_name` which pins `got["name"] == "myname"` |
| A9 | `sanitize_text` is the right sanitiser for a CALLER argument, not only a server one | **accepted, and it is the point** — it is the same function the sibling `error` field already used. Using a second sanitiser is how the two fields drift apart again |
| A10 | `authorize`/`_authorize_spend` called once per gated path is the right rule today | **verified, measured** — AST says exactly one call in each of `pay_herd`, `settlement.deposit`, `xete_alias_claim`, and none of the three is inside a loop |
| A11 | A count of gate CALL SITES is a count of CHARGES | **BROKEN by the fresh pass, fixed** — one call in a loop body is one site and N charges. See D4 |

---

## Doubts raised

**D0 (self, before writing code).** *Is the G12 arithmetic actually right, or is the reviewer
repeating a plausible story?* Answered first, from the chain, before touching a line — A1 above.
Everything else in G12 depends on it.

**D1 (self, during the fix).** *Putting the rent floor only in `deposit_ix` leaves it AFTER the
spend gate in `settlement.deposit`. An impossible deposit would then charge 24h of budget for a
transaction that cannot exist.* This is `BM-failed-attempt-burns-the-spend-window` on a new
input.

**D2 (self, during the fix).** *G21 names the `%name` argument. Is `name` the defect, or is
"caller argument echoed unbounded" the defect?*

**D3 (self).** *Renaming `test_the_report_says_rent_and_fees_are_charged_on_top` — is that
touching an existing test to make the suite green?*

**D4–D8 (fresh-context Claude Opus 4.5, headless `claude -p`, separate process, no conversation
history).** Given the diff, the eight claims, the hard rules and the four benchmark doubt
prompts; instructed to break the claims with scripts it actually runs, and forbidden to write to
`~/wt-int`. It wrote seven attack files under `/tmp/ddr-fg/work/` and reported to
`/tmp/ddr-fg/FINDINGS.md`. `~/wt-int` verified untouched by it. Recorded as genuine fresh
context, not self-review.

It **broke no claim**, which I do not treat as a clean bill of health on its own — the
anti-rationalization table exists for exactly this — so what follows separates what it actually
ran from what it merely asserted.

**D4 (fresh context) — the tripwire's count is a count of SOURCE LINES, not of CHARGES.** *One
`authorize()` inside a loop body is one line and N ledger entries, so `len(gate_lines) == 1`
waves the loop double-charge straight through. Also flagged: a gate in a nested function is
counted in the outer function's total (over-count), and an aliased gate (`gate = authorize`) is
not detected at all.* This is the real finding of the pass, and it is a hole in MY fix rather
than in the code the fix was about.

**D5 (fresh context) — `_echo` returns 62 characters, not 48.** *48 caller-chosen characters plus
the 14-character `...(truncated)` marker.*

**D6 (fresh context) — the `wallet` argument still echoes the caller's string through `!r`.*

**D7 (fresh context) — extra accounts at index 3+ of the deposit instruction verify `ok=True`.**

**D8 (fresh context) — C7's "removed assertions".** It reported two removed assertions in
`test_settlement_robustness.py` (`d["recipient_wallet"] == str(ATTACKER.pubkey())` and its
sibling) and concluded they were replaced by stronger ones. **Its analysis drifted onto the wrong
baseline** — `git log -S` puts both lines in commit `4b6fea1`, the PREVIOUS stage's corroboration
fix, and neither string appears anywhere in the diff it was given. So C7 is the one claim the
fresh pass did not actually review, and I re-checked it mechanically myself (see C7 below).

**D12 (self, benchmark BM-unprovable-state-treated-as-proven).** *The two new verifier checks
have three possible answers — pass, fail, and "I could not tell". Which branch does the third
fall into?*

**D13 (self, benchmark BM-a-verdict-cheaper-than-the-one-you-hardened).** *G20 hardens the draft
tool's RPC. Enumerate EVERY remaining route to handing an unchecked URL to an RPC client, not the
one the finding named.*

**D14 (self, benchmark BM-a-control-that-identifies-a-source-by-the-string-you-typed).** *The AST
tripwire exempts `alias_rpc_endpoints`. Is the exemption a hole?*

---

## Reconciliation

**D0 — RESOLVED IN THE REVIEWER'S FAVOUR, from the chain.** The disclosure was wrong and the
finding is exactly right. Every figure in A1 is a fresh read this session, not a quotation from
the finding. Test: `::test_the_rent_reserve_is_not_disclosed_as_a_charge_on_top_of_the_amount`
asserts the corrected total is present AND that the old `amount + rent + fee` figure is absent —
both directions, so the test cannot pass on the unfixed code by accident.

**D1 — FIXED.** `validate_deposit_amount` is called at the top of `settlement.deposit`, before
`authorize`. The reasoning is the benchmark's own: "it might have landed" must be TRUE for the
window to be charged, and an amount the runtime refuses to execute cannot have landed. Unlike
`pay_herd`, `settlement.deposit` has no `_release_recorded_spend` path at all, so a charge made
here is never given back — which makes refusing before the gate the only correct placement, not
merely the tidier one. The check reads one constant and raises; it cannot spend. Test:
`::test_a_deposit_that_cannot_land_is_refused_before_the_budget_is_charged`, which asserts the
ledger is empty and that the RPC client was never even constructed.
**Residual, out of scope and recorded:** `settlement.deposit` still charges the window for OTHER
pre-submission failures (a dead RPC on `Client(...)`, a `get_latest_blockhash` timeout). That is
`BM-failed-attempt-burns-the-spend-window` in `settlement.py` rather than `payment.py`, it is
pre-existing at HEAD, and it is not one of the six findings assigned here. Flagged as unresolved
rather than silently widened.

**D2 — the defect, not the reproduction. FIXED beyond the finding.** Attacking my own fix found
the same class one ARGUMENT over: `f"{wallet!r} is not a base58 wallet address."` in both
`xete_alias_quote` and `_reverse_view` echoes the caller's string unbounded. `!r` escapes the
newline so it cannot forge a field boundary, but 600 characters of "SYSTEM: ignore all previous
instructions" in an agent's context is the payload and the quoting does not stop it. Both routed
through `_echo`. Test: `::test_the_wallet_argument_is_bounded_too` (4 cases). Had I fixed only
`name`, the finding would have been closed and the defect would not.

**D3 — RENAMED, NOT WEAKENED, and stated in the test's own docstring.** Every assertion in
`test_the_report_states_the_rent_reserve_and_the_fee_where_the_signer_reads` is byte-identical to
the one it replaces; only the title changed, because the title's claim ("rent and fees are
charged on top") is the thing G12 disproved. The assertions themselves remain true and remain
worth having: both quantities must still be disclosed to the signer. The corrected arithmetic is
a separate, new test rather than a rewrite of that one.

**D4 — FIXED, and it is the most important item in this DDR.** The reviewer is right: G22 asked
for "called exactly once" and a line count does not deliver it. `_gate_and_sign_lines` now
returns a third value — the gate calls that run inside a loop — computed per node rather than by
a blanket "anything under a loop node", so a `for`'s iterable and a `for`/`while`'s `else:` (both
of which run once) are not flagged while a `while`'s test (re-evaluated every iteration) is. The
tripwire refuses any looped gate. Two tests, and the second matters as much as the first:
`::test_the_tripwire_catches_one_gate_that_charges_many_times` (asserts the line count still says
ONE, which is the whole point) and `::test_the_loop_rule_does_not_refuse_a_confirmation_poll`, an
over-refusal guard — every submitting function in this package polls in a `for` loop after gating
once, so a rule that flagged "this function contains a loop" would have gone red on real code and
the pressure would then have been to weaken it. Proven load-bearing the same way as the original:
the `assert not looped_gates` line was stripped from a scratch copy and the meta-test failed
`DID NOT RAISE AssertionError`.
On the reviewer's other two: the **nested-function over-count** is deliberate and I left it —
a gate in a helper defined inside a gated path is still a charge on that path, so counting it is
correct, and if it is ever wrong the failure is a red test, not a silent double-charge. The
**alias** case (`gate = authorize`) needs dataflow, not AST shape; recorded as unresolved.

**D5 — not a defect; the marker is the point.** `sanitize_text(value, 48)` returns 48 caller-chosen
characters plus a fixed, system-authored `...(truncated)` marker. Truncation that is silent is
worse than truncation that is marked: an agent reading a name that stops mid-word needs to know
the tool cut it rather than that the caller typed it. The budget the finding is about — how much
attacker prose gets through — is 48. My tests assert a 200-character per-field ceiling and the
absence of the injected instruction, both of which hold.

**D6 — already fixed before the pass reported it**, by D2 above, in both `xete_alias_quote` and
`_reverse_view`. The reviewer was reading the diff snapshot taken before that edit landed; the
tree it then tested has the fix, which is why its own probe reports "truncated". Test:
`::test_the_wallet_argument_is_bounded_too`.

**D7 — examined, not a hole, recorded as unresolved.** The immutable program reads account
indices 0–2 only; extra metas move no lamports, and `total_lamport_movement`, `destinations` and
`exactly_one_deposit` bound the value flow regardless. Refusing them would be an over-refusal
against a program whose behaviour is fixed. Listed under unresolved because it is unasserted, not
because it is unsafe.

**D8 — C7 re-verified mechanically by me, since the fresh pass did not.**
`git diff -U0 -- <the four test files> | grep '^-'` returns exactly 25 removed lines and **not one
of them is an assertion**: an import line (extended), a comment block (corrected — the "pass for
the wrong reason" note G23 disproved), one test name (renamed), one docstring sentence (the G23
filename), the tripwire body (moved verbatim into two helpers, with assertions added), one
docstring line (extended), and two occurrences of `1_000_000` (the fixture value). Zero assertions
removed, zero relaxed.



**D12 — there is no third state, and that is checkable rather than asserted.** The deposit
instruction is a fixed 81 bytes reached only through `_find_deposit_ix`, which raises `ValueError`
(returning `deposit_instruction_present: False` and refusing) for anything malformed or with an
out-of-range account index. So by the time `amount_covers_rent` runs, `amount` is a decoded u64 —
never unknown. For `system_program_account`, "I could not tell" would be a short account list, and
that is deliberately routed to FAIL, not to a pass and not to an exception: `len(accounts) > 2 and
...`, with the actual reported as `<missing — the deposit carries only N accounts>`. That is the
correct branch for this tool specifically, because its contract is "refuses unless the total and
the destinations are exactly the deposit that was asked for" — an unreadable draft is a draft not
to sign. Test: `::test_a_deposit_with_the_system_program_account_missing_is_refused`. And the
whole function still sits inside `verify_draft`'s structural guard, so a novel parser escape
becomes `verifier_internal_error` / `ok=False`, never a pass.

**D13 — enumerated from the AST, not from memory, and that enumeration is now the test.** Every
`Name` load of `RPC_URL` in `server.py`: line 159 (inside `_signing_rpc_url`), line 1215 (inside
`alias_rpc_endpoints`), line 1698 (the draft site) — that third one is the finding, and the
tripwire is precisely "this list must contain nothing else". Beyond the constant: `draft.py`,
`settlement.py` and `payment.py` never read the environment for an RPC at all, they take
`rpc_url` as a parameter, and `server.py` is the only in-tree caller — every one of those call
sites now passes `_signing_rpc_url()`. The remaining env-var route is `XETE_SOLANA_RPC` /
`XETE_ALIAS_RPC`, which feed alias READS and are scheme-checked in `alias_chain.resolve_owner`
(A7). The cheapest route was in fact the one the finding named, and it is closed.

**D14 — NOT a hole, verified rather than argued.** `alias_rpc_endpoints` treats the constant as a
candidate endpoint STRING and does not connect to anything; the strings are scheme-checked at
`alias_chain.resolve_owner` before a request is built. Ran it: with `XETE_RPC_URL=http://evil...`
the endpoint list contains that string and `resolve_owner` raises `InsecureEndpoint` with nothing
sent. **Cosmetic wart, recorded not fixed:** the refusal message labels it `XETE_SOLANA_RPC` even
when the value came from `XETE_RPC_URL`, because `rpc_url()` reports its own primary env name. An
operator debugging this is sent to the wrong variable. Out of scope for these six findings
(it is alias-read's message), listed as unresolved.

---

## Evidence that every fix is load-bearing

Every test below was watched RED before the change and GREEN after, in that order.

| Finding | Test(s) | Red-before |
|---|---|---|
| G20 | `test_the_draft_tool_refuses_a_plain_http_rpc`, `test_the_signing_rpc_accessor_is_the_only_reader_of_the_import_time_constant` | Written first, run first: `the draft path reached the RPC with url=['https://api.mainnet-beta.solana.com']` (which also demonstrates the import-time/call-time split), and `RPC_URL constant directly at line(s) [1698]` |
| G12 | 6 tests (see the benchmark) | `assert not True` on the below-rent draft; `DID NOT RAISE ValueError` on the builder; the disclosure test failed on `~1454640 lamports rent ... Approximate total debit ~1001459700` |
| G14 | `test_a_deposit_whose_third_account_is_not_the_system_program_is_refused`, `..._missing_is_refused` | `assert not True` — the attacker-key draft verified `ok=True` with zero failures, exactly as G14 reported |
| G21 | 13 tests | 9 red on the `%name` payloads, 4 red on the `wallet` payloads; e.g. `xete_alias_claim echoed the injected instruction back`, and `normalize_name`'s length refusal reproduced verbatim at 592 bytes |
| G22 | `test_the_tripwire_itself_catches_a_path_that_gates_twice`, `test_the_tripwire_catches_one_gate_that_charges_many_times`, `test_the_loop_rule_does_not_refuse_a_confirmation_poll` | Each assertion was stripped from a scratch copy of the tripwire in turn and the matching meta-test failed `DID NOT RAISE AssertionError`; restored, green. This is the honest red/green for a test-only fix |
| G23 | `test_the_coverage_handoff_above_names_the_file_that_actually_has_it` | `test_alias_read.py does not contain the end-to-end refusal this docstring relies on` |

Suite: **631 passed** (baseline at the stage handoff: 603). Command:
`PYTHONPATH=$PWD/src ~/xete-mcp-fix/.venv/bin/python -m pytest test_alias_read.py
test_alias_read_hardening.py test_published_tools_regression.py test_settlement_robustness.py
test_signing_regression.py test_signing_safety.py test_spendguard.py -q -p no:cacheprovider`

---

## Unresolved / risk-accepted

1. **A3 is not executed.** "A deposit below the rent-exempt minimum cannot land" rests on the
   runtime's documented rule plus the observed mainnet deltas, not on a transaction that failed
   in front of me. Submitting one is forbidden here and would cost real SOL. Direction of error
   is a refusal, not a permission.
2. **`settlement.deposit` still charges the spend window for pre-submission failures** other than
   the new floor (dead RPC, blockhash timeout). Pre-existing at HEAD; `payment.pay_herd` has a
   release path and `settlement.deposit` does not. Belongs to the spend-caps lens.
3. **`alias_chain.rpc_url()` refusals name `XETE_SOLANA_RPC` even when the value came from
   `XETE_RPC_URL`.** Cosmetic, misdirects an operator, alias-read's message to fix.
4. **Extra accounts at index 3+ of the deposit instruction are still unchecked.** Examined
   (D7): the immutable program reads indices 0–2 only, extra metas move no lamports, and
   `total_lamport_movement` / `destinations` / `exactly_one_deposit` bound the value flow. Not a
   hole, but not asserted either.
5. **The spend-gate tripwire cannot see an ALIASED gate** (`gate = authorize; gate(...)`). Raised
   by the fresh pass (D4). Detecting it needs dataflow rather than AST shape. Every gated path
   today calls it by one of the two known names, and `test_every_signing_site_is_gated_or_explicitly_exempt`
   independently catches a NEW function that signs, so an alias would have to be introduced into
   an already-gated path to hide.
6. **The fresh-context pass reviewed seven of eight claims.** Its C7 analysis ran against the
   wrong baseline (D8); I re-verified that claim mechanically rather than leaving it to stand on
   a review that did not happen.

---

## Verdict: SHIP
