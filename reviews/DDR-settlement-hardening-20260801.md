# DDR: the settlement path no longer certifies a payment it cannot independently verify

Commit scope: `src/xete_mcp/settlement.py`, `src/xete_mcp/draft.py`,
`src/xete_mcp/server.py` (settlement tools only), `test_settlement_robustness.py`

Closes findings [15]-[25] from the second adversarial pass (`FINDINGS-settlement.md`).
Branch `fix2/settlement`, rebased onto track 1 (`alias_chain.py` / `safehttp.py` present).

---

## Claim

Falsifiable form, four parts:

1. **No answer from the permit server can change who a settlement pays.** `%alias` resolution
   for every settlement tool goes to the on-chain AXTREG registry via `alias_chain`, and a
   registry read that fails raises rather than falling back to HTTP. The permit server is not
   contacted on this path at all.
2. **`xete_verify_settlement_tx` is not fed its own answer.** `xete_draft_settlement_tx` no
   longer pre-fills `verify_with.expect_recipient`; the caller must supply the destination from
   independent knowledge, so `recipient_commitment` is a real comparison rather than an identity.
3. **`settlement.status()` reports `open: true` only for an account owned by the settlement
   program and exactly `STATE_LEN` (81) bytes long.** No field is read out of an account failing
   either test, so the commitment comparison is never performed on unauthenticated bytes.
4. **No settlement tool asserts an outcome it does not know.** `SettlementSubmitError` with
   outcome `unconfirmed` returns `submitted_unconfirmed` plus the signature from all three
   submitting tools, and the confirmation budget bounds total wall-clock time rather than a poll
   count that the untrusted RPC multiplies.

## Assumptions (verified / inherited / assumed)

| # | Assumption | Status |
|---|---|---|
| A1 | `Transaction.from_bytes` ACCEPTS a v0 transaction; the old code refused it only because `0x80` is misread as `num_required_signatures=128` | **verified** — compiled a real `MessageV0` with an `AddressLookupTableAccount`, `from_bytes` accepted it and reported 128 signatures. The prior review's claim that it rejects with "invalid value: alias encoding" is **wrong**; that error is what solders emits for a *non-canonical shortvec length prefix*, an unrelated condition (probe D1b). Finding [21] is correct and the earlier report is not. |
| A2 | `from_bytes` does not bounds-check compiled account indices | **verified** — round-tripped a transaction carrying index 200 against a 5-key array; the index survives. Pinned by `test_from_bytes_does_not_sanitise_account_indices` so a solders upgrade that changes it is noticed. |
| A3 | A legacy message's first byte can never have the high bit set, so `0x80` is an unambiguous version discriminator | **verified** by construction (the bit is reserved) and probed: signed, unsigned, and 3-signature legacy transactions all classify as `None`. |
| A4 | `solders.account.Account` exposes `.owner` | **verified** — `dir(Account)` lists it. Absence is treated as failure anyway, so a shape change fails closed. |
| A5 | Escrow state is exactly 81 bytes | **inherited** from this module's own docstring and the deployed program's layout. Not re-verified against the on-chain program — nobody has read the program source (memo residual risk #5). If the layout is not 81, `open` becomes permanently `false` — a loud, safe failure, not a silent one. |
| A6 | Rent for the escrow account is `(128 + 81) x 3480 x 2 = 1_454_640` lamports | **verified** arithmetically against Solana's documented constants; matches the reviewer's independently measured ~0.00145 SOL. It is a stated approximation in the output, not a check. |
| A7 | `alias_chain.resolve_owner` returns `None` only for a provably-unclaimed name and raises otherwise | **inherited** from track 1, read at source (`alias_chain.py:110-187`) — the module's docstring makes this its central contract and the code matches it. |
| A8 | 50_000 lamports is above any honest draft this codebase produces | **verified** — `draft_deposit` emits 60_000 CU at 1_000 µL/CU = 5_060 lamports all-in; 200_000 CU at 50_000 µL/CU (a genuinely congested slot) = 15_000. |

## Doubts raised

**Reviewer: self (same context) — see Verdict. No fresh-context agent was available in this
session; no subagent tool is exposed to it.** Every doubt below was nonetheless driven by a
*reproduction first*: each of [15]-[25] was turned into a working attack against the pre-fix
tip before any code was changed, and re-run against the fix afterwards.

- **D-a. Does the version gate create a parser differential?** If `_message_version` and solders
  disagree about where the message starts, one of them reads the version byte from the wrong
  offset and something versioned could be classified legacy.
- **D-b. Does the version gate break signed transactions?** It must skip a populated signature
  array. Misreading a real signature's first byte as a version prefix would refuse every signed
  draft as "versioned" and the `unsigned` check would never fire.
- **D-c. Is hand-rolled byte parsing on attacker input a new crash path?** The whole point of
  [23] is that `verify_draft` must always return a `VerifyResult`.
- **D-d. Does tightening `MAX_TX_FEE_LAMPORTS` to 50_000 refuse honest congestion?** An
  over-tightened ceiling is a denial of service on the product.
- **D-e. Does the wall-clock loop reduce to zero polls, or spin?** `budget` can be set to
  anything by the operator.
- **D-f. Did updating the two test fixtures (realistic `owner`, virtual clock) weaken any
  existing security assertion?**
- **D-g. Does the strict `owner`/length gate make `status()` useless against a *slow* RPC** —
  i.e. is "not an escrow" now returned for real escrows?
- **D-h. Does routing `%alias` through the chain break `xete_settle_create`'s notify handle?**

## Reconciliation

- **D-a — refuted with evidence.** Probe D1b: a non-canonical `0x80 0x00` length prefix is
  classified legacy by this module and **rejected outright by solders** ("expected strict form
  encoding"), so the pair fails closed; `verify_draft` returns `deserialize`. Pinned by
  `test_a_non_canonical_length_prefix_cannot_smuggle_a_message_past_the_version_check`. There is
  no encoding where this module says "legacy" and solders parses something other than the legacy
  message it was handed — `from_bytes` only ever parses legacy.
- **D-b — refuted with evidence.** `test_a_signed_legacy_transaction_is_still_classified_legacy`:
  a fully signed legacy transaction classifies as `None` and fails on `unsigned`, which is the
  correct reason.
- **D-c — refuted with evidence.** `test_truncated_input_returns_a_result_instead_of_raising`
  over `b""`, `b"\x01"`, `b"\x02"`, `b"\x80"`; all return `ok=False, failures=["deserialize"]`.
  Both `ValueError` paths in `_message_version` are inside the existing try/except.
- **D-d — refuted with evidence.** `test_a_congested_but_honest_priority_fee_still_passes` holds
  200_000 CU x 50_000 µL/CU = 15_000 lamports green, and
  `test_the_ceiling_is_within_an_order_of_magnitude_of_the_honest_cost` stops a future change
  from setting the ceiling at or below honest cost. The ceiling remains caller-overridable via
  `max_fee_lamports`, so an operator who needs more must say so explicitly and own it.
- **D-e — refuted by construction and test.** The loop polls *before* it checks the deadline, so
  at least one poll always happens (matching the old `max(1, ...)`); it sleeps
  `min(_POLL_SECONDS, remaining)`, so it neither spins nor overshoots.
  `test_the_confirmation_budget_is_a_wall_clock_not_a_poll_count` measures 240s for a 90s budget
  before the fix and <=90s after.
- **D-f — examined line by line; no assertion weakened.** Two fixture changes, both of which make
  the fake *more* faithful rather than the assertion looser:
  - `_account_client` now attaches `owner=settlement.program_id()` by default. The old fake
    omitted the field entirely, which is precisely why an unchecked `info.owner` went unnoticed;
    a real `Account` always has one. Every existing assertion is unchanged and still passes, and
    hostile ownership is now expressible (`owner=`) and tested.
  - `instant` swaps the module-level `time` for a virtual clock instead of monkeypatching the
    global `time.sleep`. Strictly stronger — elapsed time is now *measured*, which is what makes
    [19] testable at all — and less invasive, since it no longer mutates the real `time` module
    for the whole process.
  - `test_status_does_not_call_a_foreign_account_an_open_escrow` retains its original
    assertions; the new `open is False` property is asserted by a separate, additional test.
  - Baseline 95/95 passed before any test was added, confirming no existing test needed relaxing.
- **D-g — refuted.** `status()` distinguishes three cases and only the middle one is new:
  account absent (`open: false`, "settled or never opened"), account present but wrong
  owner/length (`open: false`, verdict naming the actual owner and byte count), and a real
  escrow (`open: true`, unchanged). An RPC that is merely slow raises out of the client as
  before. `test_a_real_escrow_is_still_reported_open` guards the happy path.
- **D-h — accepted, and it is an improvement.** The handle is now `%` + `normalize_name(...)`,
  i.e. lower-cased, where it was previously the raw string with `%` stripped. Per the merge memo
  the permit server lower-cases before lookup, so the normalised form is the correct one; the
  previous behaviour would have missed a handle written `%Bob`.

### Risks NOT closed here, with owners

Recorded rather than silently tolerated. None is introduced by this change; all are inherited.

1. **The RPC remains a single trusted party.** Chain-authoritative resolution moves trust from
   the permit server to one RPC host — strictly better (it is a public, independently checkable
   registry with an owner-program and stored-name check) but not multi-sourced. Memo residual
   risk #2. *Owner: unassigned / structural.*
2. **`alias_chain.rpc_url()` does not fall back to `XETE_RPC_URL`** before its publicnode
   default, so an operator who hardened to their own validator still gets money-destination
   resolution from a third party. This is a real issue and it is now on the settlement path —
   but `alias_chain.py` is **track 1's file** and this track must not edit it.
   *Owner: track 1 (alias-read); already named in the merge memo.*
3. **`spendguard` has no refund/rollback entry point** (finding [25c]), so a definitively
   `dropped` deposit still consumes the rolling-window cap. Conservative direction. `spendguard.py`
   is under a **do-not-edit** freeze for this release (zero diff across all three tracks is
   load-bearing). *Owner: post-release.*
4. **Escrow state length is inferred, not read from the program source** (A5). *Owner: memo
   residual risk #5.*
5. **`benchmarks/BM-*.md` not authored here.** The doubt-driven-review skill asks for a benchmark
   case per real defect fixed, but `benchmarks/` was deliberately untracked and gitignored by
   commit 30292de because those files document live exploit paths in a public-facing repo; the
   master copy lives in the private `xete-agent-skills` repo. Writing them here would either be
   ignored by git or re-introduce the leak. *Owner: whoever lands this in xete-agent-skills.*

### Note for whoever re-applies this

Finding [25d] is accurate and still applies: `draft.py` and `settlement.py` were vendored
verbatim, but the `server.py` hunks are a hand-merge onto committed base. Re-apply the
`server.py` changes by hand and re-read them; do not trust a clean-looking patch.

---

## Verdict: BLOCK  *(superseded — see the appended fresh-context review)*

same-context-only *(status superseded 2026-08-01 — independent review obtained; see the appended section)*. CLAUDE.md rule 5 is explicit: reviewing one's own reasoning inside the
same context does not count as the adversarial pass, and for a protected path that downgrades
the verdict to BLOCK. No subagent tool was exposed to this session, so genuine fresh-context
doubt could not be obtained, and claiming SHIP would be exactly the rationalisation the skill's
own anti-rationalisation table warns about ("tests encode the same assumptions the author made").

The work itself is complete and green — 144/144 offline tests pass, and all 38 new assertions
were confirmed to fail against the pre-fix tip. What is missing is the second pair of eyes, not
the code.

**This unblocks to SHIP when:** a fresh-context reviewer (new session or another model) is given
this diff, the claim, and the assumption table above, and produces at least one concrete attack
attempt per claim — with particular attention to A5 (the 81-byte layout, which is inherited and
load-bearing for `open`) and to residual risk 2 (the RPC fallback in track 1's file, which is on
the money path and is not fixed by this branch).


---

## FRESH-CONTEXT REVIEW — appended 2026-08-01, verdict moved BLOCK -> SHIP

**The unblock condition this file set for itself** was: *a fresh-context reviewer is given this
diff, the claim and the assumption table, and produces at least one concrete attack attempt per
claim — with particular attention to A5 and to residual risk 2.* That happened. A lens was pointed
at exactly those two points (62 automated attacks plus 6 read-only mainnet probes, worktree left
clean), and two further independent lenses attacked the same code. Every finding they produced is
closed with a red-before-green regression test.

### Doubts and reconciliations

- **D-i. Claim 4 ("no settlement tool asserts an outcome it does not know") was FALSE as shipped —
  falsified twice.** `received / 1e9` threw `TypeError` into the tool's bare `except Exception`,
  reporting a **confirmed, landed** claim as a flat failure with no signature and no
  do-not-assume-you-were-not-paid guidance — triggered by one rate-limited balance read on the
  repo's own default RPC. Separately, `send_transaction` raising unwound past every handler and
  discarded a locally-known signature for a live transaction. *Reconciliation:* both fixed in
  `550a3cf`; the signature is captured before submission and the live-boundary comment moved above
  the send. Claim 4 now holds on the exception paths too.
- **D-ii. A5 (the inherited 81-byte escrow layout) — discharged.** The fresh lens attacked
  `status()` with 80/82/attacker-chosen bytes and could not get a field read out of an account
  failing the owner or length gate. 81 is now load-bearing in a second place via
  `RENT_EXEMPT_LAMPORTS`, and a read-only mainnet escrow shows `space=81`.
- **D-iii. Residual risk 2 (degrade-to-weaker-source) was real and WORSE than this file described.**
  Not merely a fallback: corroboration de-duplicated endpoints **by raw string**, so one host under
  two spellings — or one provider with two API keys — filled both slots and certified a payment to
  an attacker while printing "TWO independent endpoints that agree". And the rule was enforced on
  the *advisory* tool but not the *spending* tools. *Reconciliation:* fixed in `4b6fea1` via
  `endpoint_identity()` keyed on `(scheme, host, port)`, applied at both sites, with
  `xete_settle_create` and `xete_draft_settlement_tx` bound to the corroborated resolver.
- **D-iv. A6 (the rent figure) was right as a number and wrong as a meaning.** The arithmetic was
  correct; the claim that rent is charged *on top of* the amount was not — it comes *out of* it,
  making `amount` a floor, and a draft below that floor was certified "SAFE TO REVIEW AND SIGN".
  *Reconciliation:* fixed in `0c59d4c`, one source of truth plus `validate_deposit_amount()` at
  both the builder and the top of `deposit()`.

### Residual, carried forward
`xete_resolve` still answers from a single endpoint and warns rather than refuses, so the
corroboration rule can be walked around with one extra tool call. The configuration half is fixed
(`7f7c5eb`); the refuse-vs-warn policy is the owner's decision. See
`DDR-post-gate-integrator-20260801.md`.

## Verdict: SHIP


---

## Independent fresh-context review — appended 2026-08-01

The same-context-only *(status superseded 2026-08-01 — independent review obtained; see the appended section)* status recorded above was TRUE WHEN WRITTEN and is no longer the
current state. It is replaced here rather than edited away, so the artifact shows what was
outstanding and what closed it.

The reviewer is **s1**, an independently-running session with its own clone of this
repository and no shared history with the session that wrote the code. Coverage below is
recorded EXACTLY as it answered when asked per-artifact — including where it answered "I did
not look at that". It explicitly declined credit for one item, in its words: *"the
claim-shape confirmation you cited is YOURS, not mine — citing me for it would be citing
your own work under my name."* Nothing in this section is rounded up.

### What was independently reviewed

**`settlement.py` — YES, thoroughly, across three commits** (`701fdca`, `a297e5d`,
`7875152`). Seven credential-emission sites, the claim-confirmation logic, and every `_send`
raise path. The reviewer then built its own behavioural oracle WITHOUT sight of this
session's tests, keyed on a different canary literal, and ran it against this tree: 18/18
green. It did not trust that green — it reverted each of the ten redactions one at a time,
**pinned by line number** and with its own static sweep DESELECTED so the behavioural tests
had to do the catching. **10/10 red**, and the first pass was 9/10: reverting one line left
everything green, because the SIGNATURE MISMATCH branch had no behavioural coverage at all.
That gap was reproduced here before being accepted, and the test it wrote is merged.

Two sessions independently derived a character-identical seven-site diff, including
`redact_url(rpc_url) if rpc_url else '(unnamed)'` over the more obvious `or`.

**`draft.py` — reviewed 2026-08-01 against `1c63da7`,** after the reviewer answered NO when
asked. It had never read the file; the only prior contact was pointing this session at
`verify_draft` as a trap to check, which this session then checked — *its* work, not the
reviewer's, and it said so. **Four findings, all reproduced by execution, all returning
`ok=True, failures=none` from a verifier whose whole promise is refusal.** Root cause: the
value-weighted checks are blind to zero-lamport instructions. Fixed at `8277b0c` with a
shape whitelist and a nonce-identity check, and re-verified — all four refused, honest
control still passes.

It also ran a regression check nobody asked for, and it is the one that mattered: whether
the whitelist had killed the durable-nonce feature outright. Verified alive, and verified
that the nonce finding is closed by IDENTITY rather than merely by shape — a distinction no
other check in this round would have caught.

### What was NOT covered

The compute-budget fee arithmetic was read but not fuzzed. The ALT/v0 refusal was reasoned
about but not verified empirically.

### Status

Fresh-context adversarial review: **OBTAINED**, for both files in scope.


## Verdict: SHIP

Superseding every earlier verdict in this file. The condition those verdicts were held open
for — a genuine fresh-context adversarial pass by a party that did not write the code — has
been met and is documented above, including what the reviewer did NOT cover.

The historical statuses are left in place rather than rewritten. An artifact that shows only
its final state cannot be audited: the useful record is that this sat open, why, and what
closed it.
