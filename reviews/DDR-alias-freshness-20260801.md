# DDR: a per-endpoint freshness floor turns a stale %alias owner into an explicit error, and cannot be turned into a denial of service by the endpoint it watches

Commit scope: `src/xete_mcp/alias_chain.py`, `src/xete_mcp/server.py`,
`test_alias_freshness.py`, `test_alias_read_hardening.py`,
`benchmarks/BM-a-safety-mark-that-latches.md`

## Claim

Every Solana RPC reply carries `result.context.slot`, and every request may carry
`minContextSlot`. Using both, an endpoint that is merely BEHIND stops silently returning a
stale `%name` owner and instead produces a specific error naming lag as the cause — and the
mechanism introduces no new way to return a wrong owner, and no way for an endpoint to deny
service beyond what it could already do by refusing to answer.

**Explicitly NOT claimed:** that this detects a lying endpoint. A dishonest node reports
whatever slot flatters it. Solana exposes no account inclusion proof against the bank hash
over standard RPC — no `eth_getProof` equivalent — so there is no local check that a node
quoted the chain honestly. This is a lag check. Dishonesty is met by corroboration across
endpoints, on the spending path, or not at all. The module comment and the test file header
both say so, because "freshness" reads like an integrity property and is not one.

## Assumptions

| # | Assumption | Status |
|---|---|---|
| A1 | An endpoint cannot use this to deny service to others, or to itself irrecoverably | **FALSIFIED, then fixed** — see doubt 1 |
| A2 | An endpoint cannot use this to make a stale or wrong owner *more* likely | **Verified** — reviewer found no input; the new code only ever rejects, never accepts something previously rejected. Withholding the slot returns you to pre-change behaviour |
| A3 | `resolve_owner`'s contract is unchanged for existing callers | **Verified by grep and mutation** — callers are `server.py:1325`, `server.py:804`; `_alias_view` is the only site moved to `resolve_owner_at`. Mutating `resolve_owner` to return the raw tuple fails 9 tests, so the string contract is pinned, not merely intended |
| A4 | The floor can never be sent as an invalid value, and a malformed slot cannot corrupt the mark | **Verified for negative/bool/non-integer; FALSIFIED for the upper bound**, fixed — see doubt 1 |
| A5 | Module state is safe under this server's concurrency | **Verified** — `mcp` 1.29.0 dispatches sync tools as a bare `return fn(**args)` with no `to_thread`; all 15 tools are `def`, so tool bodies cannot interleave. The lock is kept anyway: it is cheap, correct, and survives a future move to `async def` |
| A6 | Map eviction cannot be weaponised | **Verified unreachable, hardened anyway** — no MCP tool accepts an endpoint argument, so nothing can drive keys into the map. Eviction changed from `clear()` to popping one entry so this cannot become a one-parameter mistake later |
| A7 | The lag error cannot be triggered to manufacture a phantom problem | **FALSIFIED, then fixed** — see doubt 3 |
| A8 | The tests fail without their fixes | **Verified by mutation, 17/17** — see below |
| A9 | Two endpoints are told apart correctly | **FALSIFIED, then fixed** — see doubt 2 |

## Doubts raised

Round 1 was self-review inside the implementing context; under CLAUDE.md rule 5 that carries
no weight and is recorded only because it found the hollow test. Round 2 is a fresh-context
adversarial subagent given the diff, the claim and the assumption list, with no history.
**Its verdict on the first version was NEEDS-WORK, with two HIGH findings.**

1. **(fresh context, HIGH — A1/A4)** *An out-of-range slot latches a permanent lockout.*
   Nothing bounded `raw_slot` from above. One reply of `10**30` pinned the endpoint's own
   floor above anything it could ever serve again, for the life of the process. Driving the
   real `_resolve_recipient_corroborated(..., "spend")`, the reviewer showed one endpoint
   emitting one integer and then behaving perfectly killed **all `%name` spending** for the
   process — it fails closed, but it is a persistent attacker-triggered outage that outlives
   the attack. `head + 10_000` is the quiet version: plausible, ~70 minutes.
   → **Fixed.** Every recorded slot is bounded by elapsed time against a maximum slot rate,
   anchored at chain genesis for a never-seen endpoint so the first observation is bounded
   too. A confirmed regression (`-32016`) now drops the mark, so a noticed fault
   re-baselines instead of latching. Both were needed: the bound stops the absurd value, the
   reset stops the plausible one. Benchmarked as `BM-a-safety-mark-that-latches.md`.

2. **(fresh context, HIGH — A9)** *`redact_url` is the wrong identity key, and this repo has
   already written that down.* `safehttp.endpoint_identity`'s own docstring says
   `redact_url` "is NOT usable for this and the difference is load-bearing", and
   `BM-a-control-that-identifies-a-source-by-the-string-you-typed` repeats it. Both failure
   directions were live: `https://h.test` / `https://H.test` / `https://h.test:443` are
   three keys for one machine (so the floor never establishes and the feature silently does
   nothing), while `localhost` and `127.0.0.1` are two keys for one box.
   → **Fixed.** Keyed on `endpoint_identity`; `redact_url` is retained only for the
   human-readable `shown` string. **This is a repeat of an existing benchmark, which the
   doubt-driven-review skill names as the system's cardinal failure.** Recorded honestly:
   the benchmark's doubt prompt was not consulted while writing the first version. The
   remedy applied is a public accessor, `observed_slot_for(url)`, so no caller or test can
   rebuild the key and re-pin the wrong function.

3. **(fresh context, MEDIUM — A7)** *`-32016` was read as lag even when no floor was sent*,
   producing "behind slot None but cannot serve slot None" — manufacturing the phantom
   problem the branch exists to prevent, and advertising the disable switch on the
   endpoint's unprompted say-so.
   → **Fixed.** The branch requires `floor is not None`, plus `isinstance(code, int)`,
   which also closes the `-32016.0` float spelling (`-32016.0 == -32016` is True).

4. **(fresh context, MEDIUM)** *The `server.py` half was pinned by nothing* — deleting
   `answered_at_slot` left all 656 tests green, which is verbatim the
   `BM-the-one-site-that-produced-no-conflict` prompt: if the suite stays green with the
   change removed, what shipped is a comment, not a control.
   → **Fixed.** Four tests now drive `_alias_view` end to end.

5. **(fresh context, MEDIUM)** *`resolution.rpc` named a host that was never contacted.*
   `rpc_display()` re-derives `XETE_SOLANA_RPC → XETE_RPC_URL → default` and never reads
   `XETE_ALIAS_RPC`, so once the read honoured the operator's ranked list the reported
   endpoint was wrong — while `rpc_display`'s own docstring says "which host answered" is
   the entire diagnostic it owes anyone. A precise slot beside a wrong endpoint name is
   worse than neither: both halves look authoritative and agree.
   → **Fixed.** `_chain_source` takes the URL actually used.

6. **(fresh context, MEDIUM)** *An endpoint omitting `context` opts out of the check with no
   signal at all* — the `[G18]` shape, where a degraded condition was the only one in the
   file with no `WARNING_` key, while the caveat lived in a Python comment no agent reads.
   → **Fixed.** `answered_at_slot` is always emitted, `null` included, with
   `WARNING_ENDPOINT_DID_NOT_STATE_A_USABLE_SLOT` beside it. The unclaimed path needed this
   most: the one-endpoint warning is gated on there being an owner.

7. **(self, round 1)** *Is the bogus-slot test real?* — **It was not.** It asserted only the
   floor, and `True == 1` yields a floor of `1 - tolerance`, negative, which a *different*
   guard suppressed. It passed with the type check deleted. Rewritten to assert the reported
   slot. Recorded because it is the second hollow test in this effort found by mutation
   rather than by reading.

8. **(self, round 2)** *Is the eviction test real?* — **It was not.** `clear()` wipes the
   table and then refills from the remaining inserts, leaving ~5 marks, which sailed through
   a `> 1` assertion. Tightened to near-capacity. Third hollow test, same cause: an
   assertion that is true for a reason other than the one it names.

## Reconciliation

- Doubts 1, 2, 3, 4, 5, 6: **fixed**, each with a test proven red by mutation.
- Doubts 7, 8: **fixed**; both are recorded in the tests themselves so the hollow versions
  are not rebuilt.
- A5, A6: **risk accepted as verified-unreachable**, hardened regardless.
- **Open, accepted:** an endpoint that persistently claims an inflated (but in-range) slot
  oscillates — record, refuse once, re-baseline, record again — giving roughly alternating
  failures. It fails closed, recovers without intervention, and affects only an operator
  pointed at an endpoint that lies about slots, who has larger problems. Not worth more
  state.
- **Open, unchanged and deliberate:** this is one endpoint per read. Two-of-two agreement
  stays on the spending path. Asking two endpoints on every read doubles RPC cost and turns
  ordinary node lag into a hard failure in a tool whose job is to answer — tried, and it
  broke 15 tests for exactly that reason.

## Verification

- **671 tests pass** (was 634 before this work; +37 in `test_alias_freshness.py`).
- **17 of 17 mutations go red**, one at a time, sources restored and verified byte-identical
  after each: 8 round-1 guards, 9 round-2 fixes. No mutation is accepted without asserting
  it applied — a mutation that silently no-ops produces a green run that reads like a pass.
- Invariants: `spendguard.py` byte-identical to `ee81682`; 15 tools at runtime; no BOM on
  `server.json`.

## Benchmark doubt prompts with overlapping Paths

- **BM-a-control-that-identifies-a-source-by-the-string-you-typed** — *not answered in round
  1; that omission IS doubt 2.* Now answered: keyed on `endpoint_identity`, with the five
  spellings the reviewer enumerated covered by parametrized tests.
- **BM-the-one-site-that-produced-no-conflict** — *not answered in round 1; that omission IS
  doubt 4.* Now answered: the revert-and-run-the-suite test fails.
- **BM-unprovable-state-treated-as-proven** — answered. Its "how often does this run, and
  does it latch?" prompt is precisely doubt 1; the mark no longer latches, and the third
  state ("the endpoint did not state a usable slot") is now visible to the caller rather
  than folded silently into "fine".
- **BM-derived-key-destroys-legacy-mailbox** — not applicable. No key derivation, no
  persisted format change; `_slot_seen` is in-memory only, so there is no old-format state
  to load and no downgrade path.

## Verdict: SHIP

A genuine fresh-context adversarial pass ran, returned NEEDS-WORK with two HIGH findings,
and every finding is closed with a mutation-proven test. The residual risks are stated above
rather than dismissed. The one thing a reader should carry away: the review did not merely
polish this change, it **reversed** its two central design decisions — the identity key and
the unbounded mark — and one of those was a repeat of a defect this repo had already written
a benchmark about.
