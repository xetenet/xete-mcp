# DDR: a permit-server transaction can only be signed if it is, byte for byte, the 0x02 claim of the name the user typed, at the price we were quoted, paying the xete treasury — and the network has confirmed what it moves

Commit scope: `src/xete_mcp/txguard.py`, `src/xete_mcp/signguard.py`,
`src/xete_mcp/server.py` (three localised hunks in `xete_alias_claim`),
`test_signing_safety.py`, `test_signing_regression.py`, `test_spendguard.py` (one
touchpoint registration), `scripts/verify_mainnet_claims.py` (new).

Closes findings [9] critical, [10] high, [11] medium, [12] medium, [13] low, [14] low
from the second adversarial review of the signing track.

## Claim

1. **The money is bounded.** A claim's price is a `u64` at the tail of the registry
   instruction data, moved by CPI. `inspect_alias_claim` parses it, requires it to
   equal the quoted price exactly, and counts it as a debit, so `static_debit_lamports`
   describes a real claim instead of describing its fee.
2. **The operation is pinned.** `data[0]` must be `0x02`. The instruction is exactly
   `42 + name_len` bytes. The name is compared as BYTES against the name the user
   typed. The six accounts are checked by POSITION, including the treasury the price
   lands in.
3. **No top-level System instruction is permitted at all**, at any amount, to any
   destination.
4. **Simulation is mandatory** (`XETE_ALIAS_REQUIRE_SIMULATION`, default on). If an
   operator turns it off, `spend_charge()` charges the spend limits the whole ceiling,
   so the unsimulated path is never the cheap path.
5. **Only inspected bytes can be signed** — `approve_and_sign` re-hashes the message
   and compares it with the digest recorded at inspection time.
6. **Login no longer breaks on a slow client clock**: the challenge skew window is
   symmetric (±900s) and the refusal names the clock.

## Assumptions (verified / inherited / assumed)

| # | Assumption | Status |
|---|---|---|
| A1 | Claim data layout is `02 \| u8 name_len \| name \| 32-byte key \| u64 price` | **VERIFIED** — decoded from all 11 claims in the program's on-chain history; `len(data) == 42 + name_len` in 11/11 |
| A2 | The trailing u64 equals the lamports actually moved | **VERIFIED** — matches the inner CPI System transfer in every priced claim (50,000,000 / 50,000,852 / 10,000,000), and priced-0 claims have no inner transfer |
| A3 | A genuine claim has ZERO top-level System instructions | **VERIFIED** — 11/11 |
| A4 | Claim accounts are exactly 6, positional: payer / authority / alias PDA / config / treasury / System | **VERIFIED** — 11/11, including the case where payer and treasury are the same account |
| A5 | The alias record's owner is the PAYER account, not the 32-byte data field | **VERIFIED** — read the 106-byte records for %bolt, %meph, %seeker, %testy; `record[0:32] == fee payer of the claim` in 4/4, while the data's 32-byte field is stored at offset 65 |
| A6 | Config account is `find_program_address(["config"])` | **VERIFIED** — derives to `2WjYxKw…`, the account present in 11/11 claims |
| A7 | The treasury is `CmraiWB8…` | **VERIFIED against history, INFERRED for the future** — 11/11 claims paid it, and the config account carries no treasury field, so nothing on chain forces it to stay. Mitigated by `XETE_ALIAS_TREASURY` |
| A8 | The alias program validates the config/authority accounts it is handed | **ASSUMED** — the program source is still unread (merge-memo residual #5) |
| A9 | Widening the future skew window does not weaken replay resistance | **VERIFIED by reasoning + test** — replay requires a PAST challenge; freshness is carried by the nonce match and the relay's own 300s expiry |

## Doubts raised

Fresh-context status: **PARTIAL — self-review-only for the narrative pass.** No
subagent tool was available in this session, so per CLAUDE.md rule 5 this DDR does not
substitute for the independent adversarial re-review the merge memo requires before
`xete_alias_claim` ships. What the doubt pass DID do is stronger than narrative: every
doubt below was turned into executable code and run.

**D1 — "You pinned a shape you inferred from 11 transactions. What about claim #12?"**
Real risk. The treasury is the only pinned value that nothing on chain forces to stay
put. A treasury rotation breaks every claim with a clear refusal naming
`XETE_ALIAS_TREASURY`, which is a loud failure, not a silent one. Accepted with the
env escape hatch.

**D2 — "`_check_claim_accounts` derives the PDA from a decoded string. Can a name
round-trip differently?"** Found and fixed. The PDA is now derived from the matched
name BYTES; the string exists only for messages. Test:
`test_the_pda_is_derived_from_the_matched_name_bytes`.

**D3 — "Two `SetComputeUnitPrice` instructions: which one does the guard bound?"**
Found and fixed. The runtime rejects the duplicate, but the guard was silently taking
the last value while claiming to bound the fee. Duplicate compute-budget ops are now
refused. Test: `test_a_repeated_compute_budget_op_is_rejected`.

**D4 — "The 32-byte record key is unconstrained. A hostile server can write its own
key into our record."** Real, and NOT in the review's findings. What that field is used
for cannot be determined without the program or permit-server source, so it is not
pinned by default; it is surfaced in the inspection report and an optional
`expect_record_key` parameter exists so a caller that learns the answer can pin it
without touching this module. Recorded as a new residual. Test:
`test_the_record_key_is_reported_and_can_be_pinned`.

**D5 — "If the authority slot holds our own wallet, `nsig == 1` and no co-signature is
required at all."** True, and permitted, because three real mainnet claims have exactly
that shape. The worst case is a valid claim of the right name at the quoted price with
no permit authorisation, which the program will reject on chain. No loss of funds.
Accepted, recorded.

**D6 — "`bounded_simulated_debit` swallows `TransactionRejected` from
`check_debit_within`?"** No: `check_debit_within` is called outside the `try`, and the
`except TransactionRejected: raise` inside re-raises a network-says-it-fails verdict.
Refuted by `test_simulation_that_runs_bounds_the_measured_debit`.

**D7 — "Does the retry loop turn a real RPC error into a retryable one?"** The
`if "error" in body` branch raises `RuntimeError` inside the `try`, and the handler
ordering (`except RuntimeError: raise`) makes it non-retryable. A genuine RPC error
answer is reported once, not four times.

**D8 — "Refusing all top-level System instructions breaks the price-transfer path."**
It does not: no real claim has one. The test that asserted the permissive behaviour
(`test_price_transfer_within_tolerance_is_accepted`) was a COMPATIBILITY test asserting
a shape mainnet never produces, and finding [11] demonstrated an attacker using exactly
it. It is replaced by `test_priced_claim_within_tolerance_is_accepted`, which asserts
the same property — a paid claim within tolerance is accepted — against the real shape,
plus `test_no_top_level_system_instruction_is_allowed_at_any_amount`.

**D9 — "The compatibility evidence is unreproducible (finding [13])."** Fixed by
committing `scripts/verify_mainnet_claims.py`, which sources `expect_fee_payer` and
`expect_name` from the on-chain alias RECORD and `quoted_lamports` from the observed
inner CPI transfer — never from the transaction under test — and by
`test_a_real_mainnet_claim_is_accepted`, which does the same offline from committed
bytes. Result: **6 real permit-server claims accepted, 0 rejected.**

## Reconciliation

| Doubt | Outcome |
|---|---|
| D1 treasury pin brittleness | risk-accepted, env escape hatch + loud refusal |
| D2 name round-trip | **fixed** + test |
| D3 duplicate compute-budget | **fixed** + test |
| D4 unconstrained record key | **partially fixed** (reported + pinnable), residual recorded |
| D5 self-authorised claim | risk-accepted, no funds at stake |
| D6 simulation exception ordering | refuted with test |
| D7 retry semantics | refuted by code reading |
| D8 removed permissive test | fixed; property preserved by a replacement test |
| D9 unreproducible evidence | **fixed** — committed script + offline fixture test |

Security gates (solana-security-hardening): instruction-data parsing bounds-checked
before every slice; account roles checked by position, not membership; PDA derivations
client-side from pinned seeds; no arithmetic on attacker-controlled values without an
equality pin; the signing key reached only through a digest-bound chokepoint. Every
gate item is resolved; none is left open.

Suite: 140 passed. Every closed finding has a regression test that fails against the
pre-fix tree; seven of them fail there with "the transaction was signed and SUBMITTED
on-chain".

## Verdict: SHIP

Ships to the `fix2/signing` branch. **Merge to trunk remains BLOCKED** until the
independent fresh-context adversarial re-review the merge memo requires has run against
this diff — the doubt pass above is self-review-only for its narrative half, and
CLAUDE.md rule 5 does not let a same-context review clear a protected path.
