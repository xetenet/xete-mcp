# DDR: the claim guard was checking the wrong things — it pinned an address the program now rejects, and left unpinned the one field the product's own design says must not be forgeable

Repair round on `fix2/signing`. Commit scope: `src/xete_mcp/txguard.py`,
`src/xete_mcp/server.py` (four localised hunks in `xete_alias_claim` plus the env
docstring), `test_signing_safety.py`, `test_signing_regression.py`,
`scripts/verify_mainnet_claims.py`.

Closes findings [R1] high, [R2] high, [R3] medium, [R4] medium, [R5] low, [R6] low,
[R7] low from the third adversarial review — the one that read the permit-server source
at `~/permit-review/src/` and probed the live registry with `simulateTransaction`, which
is exactly what the previous round said it could not do.

## Claim

1. **The 32-byte record key is the on-chain `agent_id`, and it is now pinned.**
   `xete_alias_claim` passes `expect_record_key = sha256(agent_id)` — mirroring the
   permit server's own `auth::agent_id_bytes` — so a claim may only bind the agent this
   wallet actually is. The hook already existed in txguard and was simply never wired.
2. **The treasury is read, not hardcoded.** `config.names_wallet`, bytes 64..96 of the
   registry's config PDA, fetched with one `getAccountInfo`. The constant
   `MAINNET_ALIAS_TREASURY` is deleted. `XETE_ALIAS_TREASURY` remains as an override and
   is how offline callers (tests, the historical replay) pin a value.
3. **The caller can bound the price.** `xete_alias_claim(name, max_price_lamports=0)`.
   Supplied and exceeded → refused before anything is signed.
4. **The priority fee is bounded on its own**, at 100,000 lamports
   (`XETE_ALIAS_MAX_PRIORITY_FEE_LAMPORTS`), independently of the rent tolerance.
5. **Exactly one byte string is the name.** `_name_candidates` (a set of five spellings)
   is replaced by `canonical_name` = `strip().lstrip('%').strip().lower()`, matching
   `alias_chain.normalize_name`, plus a registrability check against the registry's own
   alphabet `[a-z0-9_]`, 1..32 bytes.
6. **A transaction that failed on chain is reported as `failed_on_chain`**, with the
   chain error, instead of `claimed` on the permit server's say-so.
7. **Server-chosen bytes cannot ride into the `reason` an agent reads.** They are
   escaped to the field's own alphabet, quoted, and length-bounded at the point they
   enter the message — the refusal itself stays untruncated.

## Assumptions (verified / inherited / assumed)

All chain facts below were re-verified read-only in this session, independently of the
reviewer's report. Nothing was signed or submitted.

| # | Assumption | Status |
|---|---|---|
| B1 | Config PDA `2WjYxKwHxEaD5Cp25YfymwxuG6XmyeTg3fs79RwELfms` is 97 bytes, `admin(32) \| permit_authority(32) \| names_wallet(32) \| bump(1)` | **VERIFIED** — `getAccountInfo` returned 97 bytes owned by the registry; layout matches `xete_alias_client::config_layout` (ADMIN 0, PERMIT 32, NAMES_WALLET 64, BUMP 96, LEN 97) |
| B2 | `names_wallet` today is `9zHPVcHhBeZBCLcw8NMWvAQqLWmMNBrcuiYVwyUcwFds`, not `CmraiWB8…` | **VERIFIED** — bytes 64..96 of that account |
| B3 | The program enforces slot 4 == `config.names_wallet` | **VERIFIED** — identical claim, only slot 4 changed: `Cmrai…` → `InstructionError InvalidArgument` (3664 CU); a random pubkey → `InvalidArgument`; `9zHPVcH…` → `err: None` (8152 CU) |
| B4 | The program does NOT validate the 32-byte record key | **VERIFIED** — `record=0xAB*32` → `err: None`; `record=0x00*32` → `err: None`. Simulation cannot catch a forged agent_id |
| B5 | The 32-byte field IS the agent_id, and `agent_id_bytes(s) = sha256(s)` | **VERIFIED from source** — `permit-review/src/cosign.rs`: `ClaimParts { … agent_id: [u8;32] … }` → `wire::data_claim(p.name, &p.agent_id, p.price_lamports)`; `auth.rs`: `agent_id_bytes` is sha256 of the registered agent_id string, and `AgentIdMismatch` / `NoAgentForWallet` are the only outcomes for anything else |
| B6 | The program does NOT bound the price | **VERIFIED** — `price=50,000,000` on a fresh name → `err: None`; `price=0` → `err: None` |
| B7 | The registry name alphabet is `[a-z0-9_]`, 1..32 bytes | **VERIFIED two ways** — `xete_alias_client::valid_name` + `MAX_NAME_LEN=32`; and on chain, `b'%zzatkprobe2'`, `b'ZzAtkprobe3'`, `b'zz atk4'` → `InvalidInstructionData`, `b'zzatkprobe1'` → `err: None` |
| B8 | The permit server normalises with `trim().to_ascii_lowercase()` and denies anything `valid_name` rejects (including a leading `%`) | **VERIFIED from source** — `server.rs:150` calls `xete_alias_client::normalize_name`, `None` → `{"status":"denied","reason":"invalid_name"}` |
| B9 | Reading `config.names_wallet` breaks no historical claim | **VERIFIED** — `scripts/verify_mainnet_claims.py --limit 60` against mainnet: 6 real claims accepted, 0 rejected, 24 non-claim ops skipped |
| B10 | The alias program's source is still unread | **UNCHANGED ASSUMPTION** — behaviour is now characterised by simulation rather than inferred from claim history, which is strictly better, but it is still black-box |

## Doubts raised

Fresh-context status: the adversarial pass that produced these findings **was** an
independent fresh context with tooling this session did not use (it read the permit
server's Rust and drove the tool from a hostile server). This document is the
implementer's reconciliation of that pass, and the doubts below were each turned into an
executed test rather than an argument.

**D1 — "You are about to remove a security pin. Isn't dropping the hardcoded treasury a
weakening?"** No, and the reverse is closer to true. The pin had *negative* value: the
program enforces the treasury itself (B3), so a hostile treasury was already impossible
to land on chain, while the stale constant made the client refuse the only shape the
program accepts. The previous DDR's own A7 said "VERIFIED against history, INFERRED for
the future" — the honest half — but the code comment shipped as *"the config account does
not carry a treasury field, so the client is the only thing that can bound it"*, which
was a factual claim, and false. The lesson recorded here: a comment asserting the absence
of a field is a claim that must be checked against the account, not against the claims
that happen to have been observed.

**D2 — "Reading the treasury adds an RPC round trip and a new failure mode. What happens
when the node 429s?"** It refuses, by default. That adds no new outage: simulation is
already mandatory on this path and needs the same node, so an unreachable RPC already
refused the claim. With `XETE_ALIAS_REQUIRE_SIMULATION=0` the operator has already
declared that an unanswering RPC may not stop a claim, so the treasury degrades to
unpinned and the report says `treasury_pinned: false`. Test:
`test_a_config_account_that_cannot_be_read_fails_closed`.

**D3 — "A hostile RPC can now lie about the treasury."** It can, and it gains nothing:
the program compares slot 4 against the real config account, so a lie converts into a
failed transaction and a burned fee, not a redirected payment. This is the same "the RPC
is one trusted party" residual the module already documents — it is not widened by
reading one more account from it.

**D4 — "Refusing when `ident.agent_id` is empty will brick legitimate users."** This was
a real defect in the reviewer's suggested fix, found by reading `client.py`:
`agent_id` is assigned at relay login and persisted in the *token cache*, not in
`identity.json`, so a perfectly legitimate keystore usually has it empty — and
`xete_alias_claim` deliberately does not log in. Implemented instead as: use
`ident.agent_id` if present, otherwise recover it through `_get_client()`, and refuse
only if that also fails. The cost is that a claim by an agent whose keystore lacks an
agent_id now touches the relay; the alternative is signing a claim whose identity field
is the server's free choice. Tests: `test_claim_refuses_when_this_agents_agent_id_is_unknown`
(refusal, before any challenge is requested) and
`test_an_honest_claim_binds_this_agents_own_agent_id` (the pin is the right value, not
just "any pin refuses").

**D5 — "Canonicalising the name will break `%name`, which is how everyone writes it."**
Checked, and it does not: `%mcptestname` canonicalises to `mcptestname` and the canonical
claim for it is accepted. What is refused is a *server* that writes the literal
`%mcptestname` bytes into the instruction. Note the asymmetry found in the source: the
permit server's `normalize_name` does NOT strip `%` (B8), so an honest server denies
`%name` outright; the client's canonical form strips it, matching the resolver. Accepting
the resolver's form is the correct choice — it is the only address anyone reads. Test:
`test_the_percent_form_still_claims_the_canonical_name`.

**D6 — "Rejecting names outside `[a-z0-9_]` is new behaviour the reviewer did not ask
for. Scope creep?"** Deliberate, and small: the program rejects them anyway (B7), so the
only thing such a claim can do is burn a fee — which is precisely the residual the
reviewer flagged for the `XETE_ALIAS_REQUIRE_SIMULATION=0` path. It also makes
`expect_name` safe to interpolate into every downstream message by construction.

**D7 — "Escaping the name to `[a-z0-9_]` makes a legitimate near-miss unreadable."**
Two alphabets, chosen per field: server-chosen NAME bytes are rendered against the
registry's own alphabet (so prose does not survive), while the caller's own argument is
rendered against a looser one (so `"Bob!"` stays legible). Both are quoted,
control-character-free and length-bounded. The refusal itself is still not truncated —
that property was worth keeping, and sanitising at the point of entry keeps it.

**D8 — "Is 32 bytes of escaped text really the whole injection surface of `reason`?"**
No, and the rest was audited rather than assumed. `signguard`'s refusals echo challenge
text, but only after `assert_signable`, which bounds it to 512 bytes and rejects every
non-printable byte, and they interpolate with `!r`. RPC error text reaches two messages;
both are truncated, and the one carrying the node's own `err` object is now escaped too.
No unbounded server string reaches `reason` on this path.

**D9 — "The priority-fee cap is a magic number."** 100,000 lamports = 0.0001 SOL, against
an observed cost of exactly 10,000 on 11/11 real claims — a 10x headroom for genuine
congestion pricing, and 50x below the 5,000,000 tolerance the fee could previously eat.
It is env-tunable, and the refusal names the variable. Chosen as a cap rather than the
outright ban the System-instruction rule uses, because unlike a top-level transfer a
priority fee has a legitimate future use. Tests both ways:
`test_priority_fee_is_bounded_independently_of_the_price_tolerance` and
`test_an_ordinary_priority_fee_still_goes_through`.

**D10 — "`max_price_lamports` defaults to 0, i.e. off. Isn't a default-off control
theatre?"** Partly, and it is stated rather than hidden: the ceiling only binds when the
caller supplies it, and spendguard remains the backstop when it does not. Making it
mandatory would break every existing caller and every free claim; the tool docstring now
tells the agent to call `xete_alias_quote` first and echo the figure. This is a genuine
residual, listed below.

**D11 — "Did you weaken any existing test to make this pass?"** Five tests in
`test_signing_safety.py` and the `alias_server` fixture in `test_signing_regression.py`
changed. Each change is a re-pointing, not a relaxation:
  * `TREASURY` / `XETE_TREASURY` now hold `9zHPVcH…` and are pinned through
    `XETE_ALIAS_TREASURY`; every "the money may only land HERE" assertion still runs, on
    a value that is now true.
  * `test_a_real_mainnet_claim_is_accepted` pins `Cmrai…` explicitly — the treasury that
    was in force when that 2026-07 claim landed. Replaying it against today's rotated
    value would be an anachronism, not a test.
  * Three `pytest.raises(match=…)` strings follow reworded refusals; the refusals still
    fire on the same input.
  * `test_the_pda_is_derived_from_the_matched_name_bytes` used a non-ASCII name to prove
    no decode/re-encode sits between the name check and the PDA derivation. That case can
    no longer be constructed, because the only permissible name is ASCII by construction
    — which is a stronger guarantee than the test was making. The test now asserts the
    derivation on a canonical name AND that the non-ASCII name is refused outright.
  * The fixture's claims now carry `sha256("agent-1")` as the record key, i.e. they
    became *honest* claims for that fixture identity instead of carrying 32 zero bytes.

**D12 — "The replay script now reads the treasury from the transaction it is
validating."** Caught during this pass and fixed before commit. It reads the destination
of the executed inner CPI transfer from `meta.innerInstructions` — where the money
provably went — not from the instruction's account list that the guard is being asked to
check. A free claim moves nothing, offers no independent source, and is replayed with the
treasury unpinned, which the output now says per line.

## Reconciliation

| Finding | Verdict | Where it is closed | Regression test |
|---|---|---|---|
| R1 agent_id forgeable (high) | **UPHELD** | `server.py` passes `expect_record_key`; refusal names the agent id | `test_claim_refuses_a_forged_agent_id`, `test_an_honest_claim_binds_this_agents_own_agent_id`, `test_claim_refuses_when_this_agents_agent_id_is_unknown` |
| R2 stale hardcoded treasury (high) | **UPHELD** | constant deleted; `read_config_names_wallet` + `treasury_pubkey(rpc_url=…)`; docstring corrected | `test_the_treasury_is_read_from_the_registry_config_account`, `test_there_is_no_hardcoded_treasury_left_to_go_stale`, `test_the_claim_the_live_program_accepts_is_not_refused`, `test_a_claim_paying_the_retired_treasury_is_refused`, `test_a_config_account_that_cannot_be_read_fails_closed` |
| R3 price unbounded by caller (medium) | **UPHELD** | `max_price_lamports` parameter | `test_max_price_lamports_bounds_what_the_permit_server_can_charge` |
| R4 priority-fee burn (medium) | **UPHELD** | independent cap in `inspect_alias_claim` | `test_priority_fee_is_bounded_independently_of_the_price_tolerance`, `test_an_ordinary_priority_fee_still_goes_through` |
| R5 non-canonical name accepted (low) | **UPHELD** | `canonical_name` + `_registrable_name_bytes` | `test_only_the_canonical_spelling_of_the_name_may_be_registered`, `test_the_percent_form_still_claims_the_canonical_name`, `test_a_name_the_registry_cannot_hold_is_refused_unsigned` |
| R6 chain error reported as `claimed` (low) | **UPHELD** | poll loop returns `failed_on_chain` | `test_a_transaction_that_failed_on_chain_is_not_reported_as_claimed` |
| R7 attacker prose in `reason` (low) | **UPHELD** | `_safe_text`, applied where server bytes enter the message | `test_attacker_prose_cannot_ride_into_the_refusal_reason` |

Every one of the seven was reproduced first — six through the reviewer's own harness
driving the real tool, and the chain facts underneath all of them re-probed read-only in
this session. All 16 new tests fail against the previous commit (`git checkout -- src`,
run, restore: 15 failed / 1 passed, the one being the `%name` compatibility test, which
is a "must not break" test rather than a "must now refuse" test).

Suite: **156 passed** (`test_signing_safety.py`, `test_signing_regression.py`,
`test_spendguard.py`), up from 140. Mainnet replay: **6 accepted, 0 rejected**.
`spendguard.py` untouched, as required.

## Residuals

* `max_price_lamports` is opt-in (D10). An agent that does not pass it is still bounded
  only by spendguard.
* The alias program's source remains unread (B10). Its behaviour is now characterised by
  controlled simulation rather than inferred from history, which is a real improvement,
  but it is still black-box.
* The RPC is a single trusted party for three things now: simulation, the config read,
  and confirmation. D3 argues none of them converts into a theft, only into a failed
  transaction — but that argument rests on the program enforcing what it appears to
  enforce.
* A wallet whose keystore lacks `agent_id` now touches the messaging relay during a
  claim (D4).
* `treasury_for_claim` is evaluated before `inspect_alias_claim`, so a malformed
  transaction still costs one `getAccountInfo`. Cosmetic.

## Verdict: SHIP
