# DDR: an existing 0.1.4 install survives this upgrade — its mailbox stays readable, its messaging key change is visible, and a relay that will not accept the new key stops the send instead of reporting it as delivered

Commit scope:
- `src/xete_mcp/client.py` — Identity legacy-key retention + keystore migration,
  per-message decryption fallback, 409 handling, 403 message (G1, G6)
- `src/xete_mcp/payment.py` — pre-submission spend release (G2)
- `src/xete_mcp/server.py` — client errors as JSON from all four tools, messaging-key
  reporting, ledger-path redaction, env docs (G1, G3, G5, G7)
- `src/xete_mcp/signguard.py` — trailing-newline diagnostic (G4)
- `README.md` — upgrade notes, `XETE_INVITE_CODE`, `XETE_RPC_URL` refusal rules (G5, G7)
- `test_published_tools_regression.py` (new, 28 tests)

Input: `~/GATE-FINDINGS.md` findings **G1–G7**, from an independent regression review of
the four already-published tools (`xete_my_identity`, `xete_lookup_agent`,
`xete_send_message`, `xete_check_inbox`) diffing integration tip `cb1ccb4` against
`origin/main 4413c2c` (v0.1.4). Verdict on the lens: **needs-work**.

`src/xete_mcp/spendguard.py` was OFF LIMITS for this change and is byte-for-byte
unchanged — `git diff ee81682 -- src/xete_mcp/spendguard.py` is empty, re-verified after
the last edit.

---

## Claim

1. **(G1)** An existing 0.1.4 keystore loaded by this build still decrypts every message
   encrypted to its OLD x25519 public key, indefinitely, including after the keystore has
   been rewritten to disk. The old secret is retained in the keystore, tried per message
   when the derived key fails, and the message that opened on it is flagged.
2. **(G1)** Nothing is ever ENCRYPTED or PUBLISHED with a legacy key. The sending and
   published key is always `derive_x25519_secret(ed_seed)`; the fallback is
   decryption-only and one-directional, so the cross-language unification is intact.
3. **(G1)** A 409 from `/keys/register` is resolved, not assumed. If the relay is PROVEN
   to publish a different key for us, that is `MessagingKeyConflict` and
   `xete_send_message` returns `"status": "failed"` — it can never report `"sent"` for a
   message the recipient provably cannot decrypt. The genuinely idempotent 409 (relay
   already holds OUR exact key) still succeeds silently. A 409 whose read-back could not
   be completed is recorded as unconfirmed and re-checked before the next send — never
   latched.
4. **(G1)** The keystore rewrite cannot lose key material: the original is copied to
   `<name>.pre-derived-key.bak` (0600, never overwritten) first, the new content is
   written to a temp file and renamed into place, and every failure leaves the loaded
   identity correct in memory.
5. **(G2)** In `pay_herd`, a failure strictly BEFORE `send_transaction` releases the
   ledger entry it recorded; a failure at or after `send_transaction` does not. The
   release removes at most the single entry that call added — identified by a token the
   CALL generated, not by anything the relay chose — so it can never return budget the
   caller did not consume and cannot lift the windowed cap.
6. **(G3)** All four published tools return JSON on a login/signing refusal instead of
   raising out of the tool, and the actionable half of the diagnostic ("Check the system
   time") survives truncation.
7. **(G4)** The trailing-newline branch changes only the MESSAGE. No challenge that was
   refused before is accepted now.
8. **(G6)** A 403 never discards the relay's own words; the invite hint is appended and
   labelled as this client's guess.
9. **(G7)** `xete_my_identity` emits no absolute filesystem path — including through the
   error PROSE of a failed `spendguard.status()` — and `XETE_INVITE_CODE`, the
   `XETE_RPC_URL` refusal rules and the keystore migration are documented in both README
   and the `server.py` env block.

---

## Assumptions (verified / inherited / assumed)

| # | Assumption | Status |
|---|---|---|
| A1 | AES-256-GCM authenticates, so a wrong key raises rather than yielding wrong plaintext — trying keys in sequence is a correctness fallback, not a guess | **verified** — `test_a_failed_decrypt_never_reports_an_empty_reason` and `test_old_and_new_mail_decrypt_side_by_side_in_one_inbox` both depend on it; the eavesdropper case in `test_crypto_unification.py` asserts it directly |
| A2 | `Identity.__post_init__` is the only place `x_secret` is set, so no path can smuggle a legacy key into the sending position | **verified** — `grep "self.x_secret\s*=" src/` returns exactly `client.py:117`, inside `__post_init__`. `send_multi` (`client.py:567`) and `x_public` (`:157`) both read `self.x_secret` |
| A3 | Nothing else in the tree breaks on the new `legacy_x_secrets` field | **verified** — the only other keystore writers are `manual_e2e_claim.py` / `manual_e2e_settle.py`, which write throwaway `{ed_seed, random x_secret}` files in tempdir for settlement flows that never message. They now migrate on load, which is harmless. A 0.1.4 downgrade reads `x_secret` (the derived key) and ignores the unknown field |
| A4 | `_release_recorded_spend` matching on `(path, detail, lamports)` cannot release an entry the call did not add | **BROKEN by the fresh-context pass, then fixed** — see doubt D10 |
| A5 | Reusing spendguard's private `_ExclusiveLock` / `_read_ledger` / `_write_ledger` takes the same lock and the same atomic replace as a normal write | **verified** — `payment.py` opens the identical `f"{path.name}.lock"` file and calls the identical writer; `spendguard.py` itself is unmodified |
| A6 | Fail-closed on a 409 conflict is the right direction | **BROKEN by the fresh-context pass, then fixed** — see doubt D11 |
| A7 | The new `except BaseException` in `pay_herd` does not swallow `KeyboardInterrupt` / `SystemExit` / pyo3 `PanicException` | **verified** — the handler's only statements are the release and a bare `raise`; nothing is suppressed, and releasing before re-raising is the correct behaviour for a Ctrl-C before submission |
| A8 | Persisting the legacy secret and a `.bak` is not a meaningful new exposure | **accepted** — see doubt D8 |
| A9 | The 900s skew window itself stays as-is (a previous review already widened it) | **inherited** from `test_a_slow_client_clock_does_not_brick_login`; G3's fix is the reporting channel only, and both skew tests still pass |

---

## Doubts raised

**D1 (fresh-context Claude, headless `claude -p`, diff + claims + assumptions only, no
conversation history).** Ran against claims C1–C8 and assumptions A1–A8 with instructions
to break them. See "Reconciliation" for the disposition of each.

**D2 (self, during EXTRACT).** *Does the reorder needed for G2 weaken the spend gate?*
The first attempt fetched the blockhash BEFORE `authorize`. That made
`test_pay_herd_refuses_before_touching_the_network` and
`test_pay_herd_uses_the_derived_cost_when_the_server_understates_the_quote` fail — two
existing tests that exist precisely to prove "the gate is really wired, not merely present
in the source" by asserting the RPC client is not even CONSTRUCTED before a refusal.

**D3 (self).** *Is the deliverable test actually red on unfixed code, or does it pass for
an unrelated reason?* Specifically: `test_a_failed_decrypt_never_reports_an_empty_reason`
initially passed with the `_why()` fix reverted at the reporting site.

**D4 (self + fresh context).** *`detail` contains the relay's `payment_nonce`. A malicious
relay therefore controls part of the release key. Can it make us release someone else's
ledger entry?*

**D5 (self).** *Are there other paths that raise out of a tool, beyond the one G3 names?*

**D6 (self).** *Does refusing to send on a 409 brick a user whose relay is merely flaky?*

**D7 (self).** *Does the migration contradict the documented intent in
`test_crypto_unification.py`, which calls the old random key "the cross-interface bug" and
asserts it must be "discarded"?*

**D8 (self).** *Does writing the legacy secret plus a `.bak` file widen key exposure?*

**D9 (self).** *Does `_compact()` merging entries let a release delete aggregated history?*

**D10 (fresh-context Claude) — C5 / A4 BROKEN.** *`detail` is `blobs=<n> nonce=<relay's
payment_nonce>`. The relay chooses that nonce and may repeat it, so two concurrent sends
can produce byte-identical ledger entries. The reviewer built the interleaving
(`/tmp/attack_release_race.py`): call A authorizes first and blocks in
`get_latest_blockhash`; call B authorizes second and reaches `send_transaction`, getting a
real signature; A then fails and its release — scanning newest-first — deletes **B's**
entry, the one that had already been submitted and must never be released. A's own failed
entry survives as charged.* The reviewer also correctly caught that this DDR's original D4
reasoning ("removing the older one leaves the newer, which frees budget LATER") described
the opposite of what the code does; the scan is newest-first.

**D11 (fresh-context Claude) — C4 / A6 BROKEN, worse than D6 accepted.** *`register_encryption_key`
runs exactly ONCE per process (`_get_client`'s `_client is None` singleton) and there is no
retry anywhere. So a single transient failure on the confirmatory GET at startup latched
`messaging_key_conflict = True` for the whole life of the MCP server, blocking every
`xete_send_message` until an operator restarts it — over a relay state that was fine all
along (`/tmp/attack_flaky_readback.py`: relay holds our own key, one `ConnectionError` on
the GET, immediate retry succeeds).*

**D12 (fresh-context Claude) — C8 BROKEN.** *`_redact_ledger_path` popped the `ledger` KEY
but never scrubbed the `error` TEXT. Every failure branch of `spendguard.status()` — a
corrupt ledger, the refusal when `XETE_SPEND_LEDGER` names something called identity.json —
embeds the absolute path in its prose, which went straight into `xete_my_identity`'s
output. Two reproductions, both printing the full home path.*

**D13 (fresh-context Claude) — C2 caveat + defect 1.** *The `.pre-derived-key.bak` write was
not atomic and the retry guard is only `exists()`, so a crash mid-backup leaves a
permanently empty backup that is never retried — a safety net that silently isn't one. And
`_migrate_keystore`'s temp file had a fixed name, so two concurrent migrators share it: the
second truncates it while the first is mid-write, and the first's `os.replace` publishes a
truncated prefix as the keystore.*

---

## Reconciliation

**D1 — RAN, and it broke three claims.** A separate `claude -p` process, no conversation
history, given only the diff, the claims and the assumption list, with instructions to
break them. Recorded as **genuine fresh context**, not self-review. It returned VERIFIED
for C1, C2 (with a caveat), C3, C6, C7 and A1, A2, A3, A5, A7, A8 — each with a named
attack script it actually ran — and **BROKEN for C4, C5 and C8**. Those three are D10, D11
and D12 below; all three are now fixed with regression tests. Its process note is also
accurate: `server.py` changed mid-review (the D5 fix landing), and its verdicts are against
the code re-read after that.

**D2 — FIXED, by abandoning the reorder.** Rule: never weaken an existing assertion. The
two tests protect a real property, so the ordering was restored to `authorize` first and
G2 is fixed the other way the finding suggests — by RELEASING the recorded entry when the
failure provably precedes submission. Both existing tests pass unmodified;
`test_the_gate_still_refuses_before_anything_is_submitted` adds the complementary
assertion that nothing reaches `send_transaction` after a refusal.

**D3 — FIXED (the test, not the code).** The non-empty reason actually comes from `_why()`
inside `decrypt_with_any`, not from the assignment in `inbox()`. The red-check patch was
corrected to revert both halves, at which point the test goes red as required. Recorded
because a test that passes on unfixed code is not a test, and this one nearly shipped as
one.

**D4 — PARTLY REFUTED, and its remaining half was WRONG.** Refuted correctly: `path` is the
hardcoded `SEND_PATH_LABEL`, so no entry from another spend path (`xete_alias_claim`,
`xete_settle_create`) can ever match — `test_the_release_gives_back_only_this_attempts_entry`
proves it. The rest of the original argument (that colliding entries are "interchangeable"
and that removing the older one is conservative) was wrong twice over: the scan is
newest-first, not oldest-first, and the two entries are NOT interchangeable when one of
them has been submitted. Superseded by D10.

**D5 — FIXED (a defect the finding did not name).** `_load_payer()` in
`xete_my_identity` was outside every `try`: a malformed `XETE_SOL_KEYPAIR` file raised
`json.JSONDecodeError` straight out of the tool, the same class of defect G3 describes.
Now caught and reported as `payer_error`, with
`test_a_malformed_payer_keypair_does_not_raise_out_of_my_identity`.

**D6 — SUPERSEDED by D11. The risk-acceptance was wrong and is withdrawn.** It reasoned
about "this one send fails" without checking how often the check runs. It runs once per
process, so the cost was not one send, it was every send until restart.

**D7 — REFUTED with evidence.** No contradiction. `test_crypto_unification.py`'s assertions
are that the stored random key must not be the DERIVED key and must not be used for
sending; all 14 of its checks still pass verbatim (`legacy from_json ignores stored random
x_secret`, `legacy from_json re-derives correct key`, both gold vectors). What it never
asserted, and what the finding is about, is that the old key must be DESTROYED. It is now
demoted to decryption-only, which satisfies the unification and preserves the mailbox.

**D8 — RISK ACCEPTED, documented.** The secret was already in that file. The change adds
one more copy of the same bytes in the same directory, both `0600`, both under the
existing README warning that `~/.xete/` is the account and must stay off shared or synced
storage. The alternative is guaranteed, silent, unrecoverable data loss for every current
install. The backup is written once and never overwritten, so a second run cannot clobber
a good copy with a bad one.

**D9 — REFUTED with evidence.** `_compact()` only merges above `MAX_ENTRIES = 2000`, and
every merged entry is written with `path: "(compacted)"`. The release matches on
`path == "xete_send_message"`, so it can never touch aggregated history; and above 2000
entries the fresh entry is in the `keep` tail, so it remains matchable.

**D10 — FIXED.** The ledger identity for an attempt is now
`attempt=<16 hex from secrets.token_hex> blobs=<n> nonce=<relay's>`
(`payment._attempt_detail`). The token is generated by the call, so two attempts can never
collide however the relay behaves, and the release provably deletes only the entry its own
call wrote. The token LEADS the string because spendguard truncates `detail` to 200 chars
and the relay's nonce is unbounded — a token at the tail could be truncated off — and the
release compares against `detail[:200]` for the same reason.
Tests: `test_two_attempts_with_the_same_relay_nonce_get_distinct_ledger_identities`
(deterministic) and `test_a_release_cannot_take_a_concurrent_calls_entry`, which forces
the exact interleaving the reviewer built (failing call authorizes first, submitting call
completes, failing call then releases) and asserts the SUBMITTED call's entry is the one
that survives. Both go red on the pre-token code; the threaded one was re-run 8 times for
stability.

**D11 — FIXED.** "Could not check" is now a distinct verdict from "conflict".
`_published_key_verdict()` returns `match | differs | unknown`; only `differs` sets
`messaging_key_conflict` and raises `MessagingKeyConflict`. `unknown` sets
`messaging_key_unconfirmed`, still raises (so the 409 is never silent and still surfaces in
`xete_my_identity`), but does not block sending — `send_multi` re-runs the check on the
next send and only refuses on a positive `differs`. G1's requirement is intact: a 409 is
still an error everywhere, and only PROVEN unreadability stops a send.
Tests: `test_a_transient_readback_failure_does_not_latch_a_conflict` (one flaky GET, then
the send goes through) and `test_an_unconfirmed_409_still_refuses_once_the_conflict_becomes_readable`
(not latching must not mean never checking again).

**D12 — FIXED.** `_scrub_paths()` rewrites the configured ledger path to its basename, its
parent to `…`, and the home directory to `~`, longest-needle-first, and is applied to the
`spend_limits` error prose, the outer `spend_limits` exception, and `payer_error`.
Test: `test_no_absolute_path_leaks_through_the_spend_limits_error_text`, parameterized over
both of the reviewer's reproductions (corrupt ledger; ledger aimed at an `identity.json`).
The reviewer's point that the original test only exercised the happy path was correct.

**D13 — FIXED.** Both migration writes go through `_write_0600_atomic` (unique temp name
from `secrets.token_hex(6)`, then `os.replace`, unlinking the temp on failure). The backup
is therefore either absent or complete, which is what makes the `exists()` retry guard
sound; and two concurrent migrators can no longer share a temp file and publish each
other's partial writes.

---

## Findings NOT fixed (reported, with reasons)

- **G2, second half** — "set the send floor from `LAMPORTS_PER_BLOB` rather than a 0.002
  SOL rent figure that PayHerd does not incur." The floor is
  `spendguard.DEFAULT_FLOOR_LAMPORTS`, applied inside `authorize`, in the one file this
  change may not touch (its zero-diff against `ee81682` is load-bearing for the release).
  It is also not clearly wrong: PayHerd derives and writes a payment PDA
  (`payment.py:_derive_pda`), so it DOES incur account rent, which is exactly what the
  floor's docstring says it covers. Left for whoever owns `spendguard.py`.
- **G4, second half** — "pin the challenge template in the relay's own contract tests."
  The relay is a different repository; nothing in this tree can pin it.
- **G5, second half** — "consider allowing http to RFC1918 with a loud warning rather than
  a hard refusal." **Declined.** `_signing_rpc_url()` is the endpoint that submits signed
  transactions and returns the confirmations that say they landed. A warning field an
  agent may or may not read is not an adequate substitute for refusing an interceptable
  money path, and the reviewer themself calls the tightening "defensible". Documented
  loudly in both README and the env block instead, with the tunnel-to-loopback workaround
  named. The credential rule's ordering (checked before the loopback exemption, so even a
  loopback URL with basic auth is refused) is likewise kept and documented.
- **G6, second half** — "key off a specific error code rather than the substring
  'invite'." The relay's error-code vocabulary is not known from this side, and guessing
  one would make the hint disappear on a relay that uses a different code. The substring
  heuristic is kept for the HINT only; the relay's text is now never discarded, which
  removes the actual harm.

---

## Benchmarks

The doubt-driven-review skill asks for a `benchmarks/BM-*.md` per real defect fixed on a
protected path. Three were written:

- `BM-derived-key-destroys-legacy-mailbox.md` — G1, the cardinal case: a derivation change
  is a MIGRATION for every published install.
- `BM-failed-attempt-burns-the-spend-window.md` — G2, plus the follow-on prompt that caught
  D10 in the fix itself.
- `BM-unprovable-state-treated-as-proven.md` — D11: "fail closed" mis-calibrated onto an
  UNVERIFIED condition, latched for the process lifetime.

They are **deliberately not staged**. `.gitignore:81` excludes `benchmarks/` with an
explicit reason — BM files document live exploit paths and this repo is public; the master
copy belongs in the private `xete-agent-skills` repo. The skill's "same commit" instruction
loses to the repo's own security rule. The files are on disk at
`/Users/johnhedrick/wt-int/benchmarks/` for whoever moves them across.

---

## Residual risks accepted

- **A8 / keystore exposure** — the legacy secret is now in the keystore under its own key
  and in a `.pre-derived-key.bak` alongside it. Both `0600`, both in `~/.xete/`, and the
  same bytes were already in that directory. The reviewer's soft caveat stands and is
  worth naming: external tooling that protects `identity.json` BY NAME (sync-ignore
  rules, backup exclusions) will not automatically cover the `.bak`. No such tooling
  exists in this repo. The README already tells operators to keep the whole `~/.xete/`
  directory off shared or synced storage, which is the right granularity.
- **`_migrate_keystore` still takes no cross-process lock.** With unique temp names and
  atomic replace, concurrent migrators can only publish complete, byte-identical content
  (`to_json` is a pure function of the loaded identity), so the outcome is the same file
  whoever wins. Adding an `_ExclusiveLock` to the keystore is a larger change than this
  release should carry; noted for whoever next touches `load_or_create_identity`.
- **Downgrade to 0.1.4** reads the (now derived) `x_secret` and ignores
  `legacy_x_secrets`, so a downgraded install temporarily cannot read pre-upgrade mail.
  It is not lost — re-upgrading restores it, because 0.1.4 never rewrites an existing
  keystore. Verified by the fresh-context pass against `git show 4413c2c:...`.

---

## Verdict: SHIP

501 tests pass (467 pre-existing, unmodified, + 34 new); the full suite was run three
times and the one threaded test eight times for stability. Every new test was demonstrated
RED on reverted code and GREEN after — **twelve** reverted-fix scenarios, all confirmed
red, in a scratch copy of the tree. The excluded cross-language script
`test_crypto_unification.py` still passes 14/14 unmodified. `spendguard.py` byte-identical
to `ee81682`. No Solana transaction was built against a real cluster and none was
submitted.
