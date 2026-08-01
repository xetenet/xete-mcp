# DDR: the read path honours the operator's configured endpoints, and three unasserted properties are now asserted

Commit scope: `src/xete_mcp/server.py` (`_alias_view`), `test_alias_read_hardening.py`

## Claim

Three gaps the final gate left open are closed, without changing any money-path policy:
`_alias_view` reads through the endpoint the operator ranked first, and the two properties
the test-integrity lens found unasserted now fail loudly when broken.

## Assumptions (verified / inherited / assumed)

| Assumption | Status |
|---|---|
| `XETE_ALIAS_RPC` was genuinely ignored by `_alias_view` | **Verified** — `resolve_owner(bare)` with no rpc walks `XETE_SOLANA_RPC → XETE_RPC_URL → DEFAULT_RPC`; regression test goes red without the fix |
| Reusing `distinct_endpoints()` matches the spending path's notion of "same server" | **Verified** — same `(scheme, host, port)` primitive, single definition in `safehttp` |
| The suite is green | **Verified** — 634 passed |
| Each new test fails without its fix | **Verified by mutation, individually** (see doubts) |

## Doubts raised (fresh-context gate lenses / integrator)

1. **(gate, HIGH)** `xete_resolve` launders the corroboration refusal: `settle_create('%bob')`
   refuses → `xete_resolve('%bob')` returns a single endpoint's answer → that wallet is deposited
   as base58, short-circuiting corroboration. — *Partially reconciled.* The **configuration bug**
   is fixed: the read now honours the operator's ranked list, so an operator who pointed
   `XETE_ALIAS_RPC` at their own validator is answered by it instead of a public default.
   The **refuse-vs-warn policy** is deliberately NOT changed and is left to the owner — the repair
   agent's rationale (refusing breaks a read tool with legitimate non-money uses) is sound.
   **Risk accepted, owner to decide.**
2. **(integrator)** Should the read path require two agreeing endpoints, like the spending path?
   — *Refuted with evidence.* Implemented it; it broke **15 tests**, because it doubles the RPC
   cost of every alias read and turns ordinary node lag into a hard `endpoints_disagree` failure
   in a tool whose job is to answer. Reverted to the narrow fix. Recorded in the code comment so
   the next person does not repeat it.
3. **(gate, HIGH)** The encryption core has no negative test; `test_crypto_unification.py`, cited
   by the G1 repair as assurance the crypto core is untouched, is near-worthless as evidence. —
   *Fixed.* `test_the_encryption_core_is_actually_pinned` asserts ECDH depends on both halves, a
   stranger cannot decrypt, and nonces are never reused. **Verified red** with `_shared_key`
   mutated to ignore the recipient.
4. **(gate, MEDIUM)** `_migrate_keystore`'s never-overwrite-the-backup guarantee is unasserted,
   in new code, in the same failure class as the critical bug G1 fixed. — *Fixed, on the third
   attempt.* **Two earlier versions of this test were hollow and both passed with the guard
   deleted**: one started from a fresh keystore (no legacy secret → migration returns at line 1),
   the other migrated the same file twice (idempotency check returns early). The guard only does
   work when migration runs again with *different* content and a backup already exists. The test
   now drives that, and is **verified red** with the guard removed and the mutation asserted as
   applied.

## Reconciliation

- D1: fixed in part, policy half explicitly deferred to the owner — see §Open below.
- D2: refuted with evidence, reverted, reasoning recorded in-code.
- D3, D4: fixed with mutation-proven tests.

## Open, carried forward

- **`xete_resolve` still answers from one endpoint and warns rather than refuses.** An agent that
  ignores `WARNING_ONE_ENDPOINT_CHOSE_THIS_WALLET` is not stopped. Owner's call.
- The method lesson from D4 is worth more than the fix: *a regression test is not a test until
  you have watched it fail.* Two plausible-looking tests here asserted nothing at all.

## Verdict: SHIP
