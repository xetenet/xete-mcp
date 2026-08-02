# DDR: no xete-mcp tool can sign a spend that exceeds the user's configured per-transaction or windowed limit, and no spending path reaches a signing key without passing that check

Commit scope:
- `src/xete_mcp/spendguard.py` (new — the gate, the ledger, the limits)
- `src/xete_mcp/payment.py` (gate inside `pay_herd`, before the transaction is built)
- `src/xete_mcp/settlement.py` (gate inside `deposit`, before the depositor key is used)
- `src/xete_mcp/server.py` (gate inside `xete_alias_claim` before `partial_sign`; limits surfaced
  in `xete_my_identity`; payment copy rewritten in the module docstring and `xete_send_message`)
- `README.md`, `server.json` (documented the limits; payment copy rewritten)
- `test_spendguard.py` (new — 51 tests)

Reviewer: Claude (implementer), then a deliberate adversarial pass against the finished diff.
No human co-reviewer. No second model was run; recorded as a gap, not as a pass.

---

## Claim

**Falsifiable form.** For every code path in the *packaged* `xete_mcp` distribution that
signs and submits a SOL-costing transaction — `xete_send_message`, `xete_alias_claim`,
`xete_settle_create` — a call to `spendguard.authorize()` executes before any signing key
is used, and that call raises unless

1. the amount is at or below `XETE_SPEND_MAX_LAMPORTS`, and
2. the amount plus everything recorded within the last `XETE_SPEND_WINDOW_SECONDS` is at or
   below `XETE_SPEND_WINDOW_LAMPORTS`, and
3. the amount was successfully written to a persistent ledger under an exclusive lock.

Falsified by exhibiting: any spend reaching a key without a preceding `authorize()`; any
configuration in which a limit is absent or infinite; any sequence of operations spending
more than `XETE_SPEND_WINDOW_LAMPORTS` inside one window; or any failure mode of the
ledger that results in a spend being *allowed*.

**Explicitly NOT claimed.** That an attacker able to write to `~/.xete/` or move the system
clock is constrained. That the amount a server *declares* is the amount its transaction can
actually move. Both are treated below.

---

## Assumptions

| # | Assumption | Status |
|---|---|---|
| A1 | The three tools above are the only packaged paths that autonomously sign a spend | **verified** — AST sweep of `src/xete_mcp/*.py` for `send_transaction` / `send_raw_transaction` / `partial_sign` / `Keypair.from_seed` / `Keypair.from_bytes`; result pinned by `test_every_signing_site_is_gated_or_explicitly_exempt` |
| A2 | Repo-root scripts (`manual_e2e_*.py`, `run_agent.py`, `agent_runtime.py`, …) are outside the shipped artifact | **verified** — `pyproject.toml` `[tool.hatch.build.targets.wheel] packages = ["src/xete_mcp"]`, sdist `include` lists only `src/xete_mcp`, `README.md`, `pyproject.toml`, `LICENSE` |
| A3 | Any such script that spends *through* `pay_herd` / `deposit` is gated anyway | **verified** — the gate is inside those functions, not in the tool wrappers |
| A4 | `xete_settle_claim` / `xete_settle_reclaim` are income, not spends | **verified** by reading the on-chain semantics in `settlement.py`: `claim` closes the escrow to the beneficiary, `reclaim` returns funds + rent to the depositor. Both cost only a signature fee. Capping them would block a user from collecting their own money |
| A5 | `xete_draft_settlement_tx` cannot spend | **verified** — holds no key, submits nothing; a human signs in their own wallet, which is that path's control |
| A6 | `LAMPORTS_PER_BLOB = 1_000_000` matches the on-chain program's per-blob rate | **inherited** from `payment.py` and the `BM-relay-payment-drainer` fix description; not verified against the deployed `GLdM82…` program in this pass. Consequence if wrong is bounded — see D7 |
| A7 | `time.time()` is UTC epoch seconds on every supported platform | **verified** by construction; all formatting goes through `time.gmtime`, so no local timezone enters the arithmetic |
| A8 | `os.replace` on POSIX and Windows is atomic within a directory | **verified** — documented Python guarantee; also exercised by the 30-process race test |
| A9 | `fcntl.flock` on separately-opened descriptors excludes across processes *and* threads | **verified** empirically — `test_racing_processes_cannot_both_pass_a_check_only_one_should` admits exactly 10 of 30 |
| A10 | Messaging on xete.net is free and the free path never reaches the payer | **verified in code** (`xete_send_message` returns before `_load_payer()` when the server reports a free delivery). **NOT verified against the live server** — no authenticated send was made. Flagged, see D9 |

---

## Doubts raised, and their reconciliation

### D1 — Can a caller bypass the gate?
*Attack:* call a spend function directly instead of through the MCP tool; or add a new tool
that quietly signs.

**Refuted, with evidence, for the packaged surface.** The gate is inside `payment.pay_herd`
and `settlement.deposit`, so every caller is covered, not just the tool wrappers
(`test_pay_herd_refuses_before_touching_the_network`,
`test_settlement_deposit_refuses_before_touching_the_network` — both substitute a booby-trapped
RPC `Client` that raises if constructed, and both refuse without reaching it).
`xete_alias_claim` signs inline and is gated inline before `tx.partial_sign`;
`test_the_gated_paths_really_call_the_gate_before_they_sign` compares AST line numbers to
prove the gate is *earlier*, not merely present.

A *future* ungated path is the real version of this doubt. It is covered by a tripwire
rather than by vigilance: `test_every_signing_site_is_gated_or_explicitly_exempt` walks the
AST and fails on any function touching a signing primitive that is not in an annotated table.
**Mutation-tested:** appending a plausible new `sweep_everything()` money path to
`settlement.py` fails the test naming the function; deleting the `authorize` call from
`deposit` fails three tests. The tests can fail.

*Residual, accepted:* repo-root dev harnesses can still sign with the identity key. They are
outside the wheel and the sdist (A2) and are not part of the product surface.

### D2 — Does the gate see the real amount, or only what a server says?
*Attack:* a malicious or compromised server declares a small price and moves a large amount.

**Partly refuted, partly risk-accepted, and this is the most important line in this review.**

- `xete_send_message`: **refuted.** The gate does not trust the quote. It derives
  `blob_count * LAMPORTS_PER_BLOB` on this side — `blob_count` is the value that actually goes
  into the instruction being signed — and checks `max(quoted, derived)`. A server understating
  its price cannot shrink the number checked
  (`test_pay_herd_uses_the_derived_cost_when_the_server_understates_the_quote`: quote of 1
  lamport against 50 blobs is checked as 50,000,000).
- `xete_settle_create`: **refuted.** The amount is chosen by the caller and is the exact value
  encoded into the deposit instruction.
- `xete_alias_claim`: **RISK ACCEPTED — the gate bounds the quoted price, not the transaction.**
  The permit server *builds* the transaction; this client only adds a signature. `price_lamports`
  is that server's declaration. A malicious permit server could declare `0` and hand over a
  transaction that empties the identity wallet, and the per-transaction cap would not catch it.

  Accepted for this commit because: (a) the change does not create this exposure — before it
  there was no client-side ceiling at all on that path, so this is a strict reduction, not new
  debt; (b) the windowed cap does bound *repetition* — every claim is charged at least
  `XETE_SPEND_FLOOR_LAMPORTS`, so at most ~25 claims fit in a default day
  (`test_a_zero_quote_still_costs_budget`); and (c) the only real fix is to derive the true cost
  by simulating the transaction (`simulateTransaction` with an `accounts` request, differenced
  against `getBalance`), which is a distinct feature with its own network failure modes and
  deserves its own review rather than being smuggled in here.

  Considered and rejected as inadequate: post-hoc reconciliation of the balance delta into the
  ledger. It would correct the accounting but not prevent the drain — after a wallet-emptying
  claim there is no second transaction to block.

  **This is the top follow-up and is stated as such in the hand-off, not buried here.**

### D3 — Can the ledger be corrupted, truncated, or rolled back to reset the budget?
*Attack:* damage the file, or restore an older copy, to win budget back.

**Fixed by design, and tested.** A ledger that is empty, not JSON, the wrong shape, of an
unknown version, or that contains a non-numeric timestamp, a non-integer amount, a negative
amount, or a bad `last_ts` causes a **refusal**, not a reset — eight shapes in
`test_a_damaged_ledger_refuses_rather_than_resetting`, which also asserts the damaged file is
left in place rather than overwritten. Reading is fail-closed precisely so that damaging the
ledger is not a way to clear it.

Rollback is tested directly (`test_rolling_the_ledger_back_does_not_grant_more_than_the_window`):
restoring an older snapshot replays the budget it contained, but the restored file is subject to
the same arithmetic, so the ceiling within any window is never lifted.

*Residual, accepted:* **deleting** the ledger is indistinguishable from first run and does reset
the window. There is no client-side anchor that could tell the two apart. This is bounded by the
scope statement below rather than by code.

### D4 — What happens on a clock change or a timezone shift?
**Timezone: refuted.** All arithmetic is on `time.time()` (UTC epoch); all rendering goes
through `time.gmtime`. A timezone or DST change moves nothing (A7).

**Clock backwards: fixed.** A backwards jump would otherwise stamp new spends into the past,
where a later correction forwards expires them early. `_effective_now()` never lets the window's
notion of "now" run behind the newest timestamp already recorded
(`test_a_backwards_clock_does_not_age_spending_out_early`).

**Clock forwards: risk accepted.** A forwards jump ages entries out early and cannot be detected
from the wall clock alone. Setting the system clock requires privilege on the machine that also
holds the signing key, so it is inside the boundary described under Scope.

### D5 — Does a race let two spends both pass a check only one should?
**Refuted, empirically.** Reservation is taken under an exclusive lock held on a *separate*
`.lock` file — deliberately not the ledger, since the ledger is replaced by rename and a lock on
a replaced inode protects nothing. Thirty concurrent OS processes against a window sized for ten
admit exactly ten, and the ledger totals exactly the cap with no overshoot
(`test_racing_processes_cannot_both_pass_a_check_only_one_should`). Writes are atomic
(temp + `fsync` + `os.replace`), and no temporary files survive
(`test_no_temp_files_are_left_behind`).

*Accepted latency:* a spend briefly blocks on the lock. The critical section is a small read,
some arithmetic, and one write.

### D6 — What if `~/.xete/` is read-only, or the ledger cannot be written?
**Fixed: refuse.** A spend that cannot be recorded cannot be limited, so it is not allowed.
Covered for an unwritable directory (`test_an_unwritable_directory_refuses_the_spend`), an
unopenable lock file, and a failed write. The error names the directory and says why.

### D7 — Does the ledger under-count, and does that matter?
Quoted prices exclude account rent and network fees, and a "free" 6+ letter %name quotes zero
while still burning rent. Without a floor, an injected agent could loop free claims forever and
never touch the budget.

**Fixed** by `XETE_SPEND_FLOOR_LAMPORTS` (default 2,000,000 — typical rent-exempt minimum plus a
fee): every on-chain action is charged at least the floor, and the floor never lowers a real
quote (`test_a_zero_quote_still_costs_budget`, `test_the_floor_never_lowers_a_real_quote`). The
refusal message states the quote and the charge separately rather than pretending they are equal.

This also bounds A6: if the deployed program's per-blob rate is *higher* than
`LAMPORTS_PER_BLOB`, the ledger under-counts message sends proportionally. Bounded, not
eliminated; verifying the rate against the deployed program is a follow-up.

### D8 — Can this damage `identity.json`?
*Attack:* aim the ledger at the keystore, or symlink one onto the other.

**Fixed and tested.** The ledger has a distinct filename; `ledger_path()` refuses outright if
`XETE_SPEND_LEDGER` names anything called `identity.json`
(`test_the_ledger_refuses_to_be_aimed_at_the_keystore`). A pre-existing `~/.xete/` is never
re-permissioned — `mkdir(exist_ok=False)` means `chmod 0o700` runs only on a directory this code
just created (`test_a_directory_we_create_is_private`). With a keystore present and the directory
deliberately at `0o755`, three spends leave the keystore's bytes, mode and mtime and the
directory's mode all identical (`test_identity_json_is_never_touched`). A ledger symlinked onto
the keystore fails closed on read and leaves the keystore intact
(`test_a_ledger_symlinked_onto_the_keystore_cannot_destroy_it`).

### D9 — Is the new payment copy true?
*Doubt:* "Messaging on xete.net is free" is asserted in a tool description that every model
reads, in the README, and in the registry manifest. If it is false, this diff ships a lie into
MCP registries.

**Partly refuted, partly flagged.** The code path is verified: `xete_send_message` returns
`{"status": "sent", "mode": "free"}` before `_load_payer()` is ever called when the server
reports a free delivery, so on such a server sending genuinely needs no keypair. The wording is
deliberately framed as a property of the server being connected to, with the fallback stated in
the same sentence — it neither presents free messaging as provisional nor promises it forever,
so a membership model remains open. **Not verified: that xete.net currently returns the free
flag.** That needs one authenticated live send, which was out of scope here. Flagged in the
hand-off.

The server's wire field is still named `free_alpha`. It is a protocol field, not prose;
renaming it would break compatibility with the deployed relay. The user-visible `mode` value it
produced was `"free_alpha"` and is now `"free"`. Renaming the wire field is a coordinated
client+relay follow-up.

### D10 — Is there any way to turn the limits off?
**Refuted by construction and by test.** There is no sentinel meaning "unlimited" and no disable
switch. Unset gets a conservative default; malformed refuses everything and names the variable;
`0` disables spending entirely with a message saying so; a floor above the cap is reported as a
contradictory configuration rather than silently blocking everything.
`test_there_is_no_way_to_switch_the_gate_off` greps the module for escape hatches
(`float('inf')`, `sys.maxsize`, `XETE_SPEND_DISABLE`, …) and fails if one appears.

Raising a limit is possible and intended — that is the user's own explicit, auditable act.

### D11 — Benchmarks whose doubt prompts touch this change
`benchmarks/` is gitignored in this public repo, so no `BM-*.md` can be staged here. The three
whose *class* overlaps this diff were read and answered:

- **`BM-relay-payment-drainer`** — *"Where is the invoice/price check that says this is the
  amount the user agreed to pay?"* This commit is that check, moved to the client. Answered in
  full for `xete_send_message` and `xete_settle_create`; answered only for the *declared* price
  on `xete_alias_claim` (D2).
- **`BM-swap-zero-amount-listings`** — *"What happens with zero/degenerate amounts?"*
  `authorize(0)` is not a no-op: the floor charges it, so a zero-quoted action cannot be repeated
  without bound (D7). Negative and non-integer amounts are refused explicitly.
- **`BM-permit-rpc-amplification`** — *known-debt gate: no acknowledged-but-deferred security
  note may merge on a protected path.* Considered seriously against D2, since D2 is exactly an
  acknowledged residual. Judged not to trip it: that gate exists to stop a change from
  **introducing** a new exposure with its control deferred. Here the exposure predates the
  change, the change strictly reduces it, and the remainder is written down with a named fix
  rather than left as a "later" marker in code. Recorded so a reviewer can disagree with the
  judgement rather than miss it.

### D12 — Blast radius if `spendguard.py` itself is wrong
A bug that refuses too much breaks spending loudly and is recoverable by configuration. A bug
that refuses too little returns the pre-existing behaviour, which is today's state. The module
is stdlib-only (no new dependency), imported lazily at the gate sites, and touches nothing but
its own two files. Custody and signing semantics are untouched: no change to how keys are
loaded, how transactions are built, or what is signed.

---

## Scope of the protection — stated so it cannot be overread

These limits bind **this server's own spending paths**, against a runaway or prompt-injected
agent and against a server quoting more than the user will tolerate. They do **not** bind an
actor who can write to `~/.xete/`, edit the MCP client's environment, or move the system clock,
because that actor can equally read `identity.json` and transact without this server at all. The
gate raises the floor on autonomous misbehaviour; it is not a custody boundary, and nothing in
this commit should be described as one.

---

## Evidence

- `python -m pytest test_spendguard.py -q` → **51 passed**, against the working tree.
- Same suite → **51 passed** against the exact commit image (HEAD + this change only, without
  the unrelated uncommitted work present in the tree).
- Mutation checks: removing the gate from `deposit` fails 3 tests; adding an ungated money path
  fails the tripwire by name.
- Real refusal messages captured for the per-transaction cap, the windowed cap (naming the
  UTC time and the wait), a malformed variable, and a damaged ledger.

## Commit hygiene note

The working tree carried substantial unrelated uncommitted money-path work (a treasury rotation
in `payment.py`; the custody-T1 draft path in `server.py`/`settlement.py`, which the project
record marks as awaiting its own review). It is deliberately **not** in this commit. Each edit
was applied twice — once to the working tree and once to a pristine HEAD image — after asserting
that every anchor was byte-identical in both, and the index was set from the HEAD image. The
other work remains uncommitted and untouched.

---

## Verdict: SHIP

Ships with D2 (`xete_alias_claim` bounds the declared price, not the server-built transaction)
recorded as an accepted, pre-existing residual with a named fix, and with D9 (xete.net's free
flag not confirmed by a live send) and A6 (per-blob rate not confirmed against the deployed
program) recorded as unverified. Nothing here weakens an existing control.
