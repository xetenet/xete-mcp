# DDR: the alias-read track's own hardening no longer leaks credentials, no longer forwards attacker prose as this client's own output, and no longer crashes on a mistyped endpoint

Commit scope:
- `src/xete_mcp/safehttp.py` (owned by this track)
- `src/xete_mcp/alias_chain.py` (owned by this track)
- `src/xete_mcp/server.py` (SHARED — hunks confined to the `%alias` section plus six
  one-token `RPC_URL` → `_signing_rpc_url()` swaps)
- `README.md`, `test_alias_read.py`, `test_alias_read_hardening.py` (new)

Input: `~/FINDINGS-alias-read.md`, eight findings from an independent adversarial review
of `fix/alias-read @ 86a32a0`, verdict **needs-work**. This DDR covers the fixes for all
eight.

---

## Claim

Against the eight findings, as falsifiable statements:

1. No string this package emits — exception message, `error` field, `permit_server`
   field, or reported endpoint — contains userinfo or a query string from a configured
   URL, for any of `XETE_PERMIT_URL`, `XETE_SOLANA_RPC`, `XETE_RPC_URL`.
2. No untrusted server string reaches a tool's output containing a newline, a control
   character, or a Unicode format character; every one of them is length-capped; and
   every one of them is delivered inside a block whose first key states that the permit
   server wrote it and that it is not instructions. Dropped key names are only echoed
   verbatim when they are identifier-shaped.
3. No output field named `owns_both` exists. The recomputed badge is named
   `owns_both_per_server` and travels with a caveat naming the exact forgery that still
   works.
4. A refused or unreachable RPC endpoint returns a `reason` + `hint` object from
   `xete_alias_resolve`, `xete_alias_reverse`, and both `xete_resolve` branches. None of
   them raises.
5. `XETE_RPC_URL` is scheme-checked at every point it is used, including the four
   settlement tools and the two messaging paths. `alias_chain.rpc_url()` prefers
   `XETE_SOLANA_RPC`, then `XETE_RPC_URL`, then the public default, and
   `resolution.rpc` reports whichever was actually used.
6. `xete_alias_claim` posts, spend-gates, confirms, and reports the SAME normalised name
   that `xete_alias_resolve` will later look up.
7. The README no longer states that `/alias/resolve` and `/alias/reverse` are undeployed.
8. This artifact exists, staged in the same commit as the source change.

---

## Assumptions (verified / inherited / assumed)

| # | Assumption | Status |
|---|---|---|
| A1 | Every finding describes real behaviour at my tip | **VERIFIED** — `probe_findings.py` reproduced all of [1][2a][2b][2c][3][5a][5b][6] and two of the four tools in [4] before any edit; [7] verified by grep. See "Doubt D6" for the two [4] cases the probe initially missed and why. |
| A2 | `InsecureEndpoint` is not caught by `except AliasChainError` | **VERIFIED** — `InsecureEndpoint(EndpointError(RuntimeError))`; `AliasChainError(RuntimeError)` is a sibling. Reproduced as an escaping exception. |
| A3 | `requests` redacts userinfo in its own exception text | **INHERITED from the reviewer, NOT relied on.** `scrub()` is applied to every third-party exception string this package interpolates, so the claim does not need to be true. |
| A4 | A registry `%name` cannot contain whitespace or control characters | **VERIFIED against this repo's own normaliser** (`alias_chain.normalize_name`), which is what every read path uses. NOT verified against the xete-alias program source — see residual R3. |
| A5 | The permit server lower-cases names before lookup | **ASSUMED, and the fix removes the dependency.** Finding [6] is closed by making this client's behaviour correct under either answer, not by confirming the assumption. |
| A6 | `spendguard.py` must have zero diff | **VERIFIED** — `git diff ee81682 -- src/xete_mcp/spendguard.py` is empty. |
| A7 | Relocating three existing assertions is not weakening them | **ARGUED, see Doubt D1.** |
| A8 | The 106-byte layout / PDA derivation from the base branch is correct | **INHERITED** from the prior track and its mainnet verification. Untouched by this change; no test here re-verifies it. |

---

## Doubts raised (fresh-context adversarial pass over my own diff)

**D1 — "You changed three existing security tests. That is exactly what rule 5 forbids."**

Three assertions in `test_alias_read.py` were edited:

- `test_quote_fields_are_allow_listed`: `got["fields_ignored"]` →
  `got["untrusted_server_text"]["fields_ignored"]`, same set asserted, plus a new
  assertion that the banner is present.
- `test_reverse_returns_a_name_the_chain_confirms`: same relocation, one line.
- `test_alias_resolve_returns_the_chain_owner_not_the_servers`:
  `unverified["owns_both"] is False` → `unverified["owns_both_per_server"] is False`,
  plus a NEW assertion that `owns_both` is absent.

**Reconciliation: refuted-with-evidence.** In all three the property under test is
unchanged and the assertion is strictly stronger. The first two tested "the dropped key
NAMES are reported and the VALUES never reach the caller" — both still asserted, at the
field's new address, with an added check on the label. The `"ignore your caller" not in
json.dumps(got)` line, which is the actual security assertion in the second test, was not
touched. The third tested "the server's `owns_both: true` is discarded" — still
asserted, and now also asserts the forgeable key cannot appear under the name that
implied client verification. No assertion was deleted or loosened. Every one of these
three tests still fails against the pre-fix source for its original reason if the
relocation is reverted.

**D2 — "Quarantining `note` doesn't stop prompt injection. The text is still delivered.
You have relabelled the problem."**

**Reconciliation: risk-accepted, explicitly, and it is the merge memo's own position.**
The memo (residual #6) says: "Prompt injection remains open wherever a server-supplied
string reaches an agent that spends money. An allow-list doesn't fix it; only truncation,
escaping, and labelling reduce it." All three are now applied. What changed measurably:
the string can no longer contain a newline (so it cannot forge the visual shape of a new
JSON field — `test_untrusted_text_cannot_forge_a_new_line_or_a_new_field`), it cannot
exceed 200 chars, it cannot carry bidi or zero-width characters, and it no longer sits
flat beside `verified` and `total_lamports` where an agent reads it as this client's own
words. What did NOT change: an agent that reads and obeys a labelled quotation from a
declared-untrusted party is still exploitable. That is not closable here. It is R1 below.

**D3 — "Renaming `owns_both` to `owns_both_per_server` is cosmetic. The value is
identical. You closed a naming complaint, not a vulnerability."**

**Reconciliation: accurate, and it is what the finding asked for.** Finding [3] says
"Either drop `owns_both` entirely until there is an on-chain SNS read, or rename it
`owns_both_per_server` too." I took the rename and added a caveat string carrying the
exact forgery, because dropping it removes information an operator legitimately uses.
The reviewer's probe P10 is now a passing test that asserts the badge is **still true**
under the attack — `test_owns_both_is_not_presented_as_a_client_verified_badge` — so the
residual is pinned in the suite rather than described in prose. The real fix is an
on-chain SNS read; it is R2.

**D4 — "You touched six lines in the settlement and messaging tools. Those belong to
other tracks. You were told to keep shared-file hunks tight."**

**Reconciliation: fixed as required, and deliberately minimised.** Finding [5] names
`server.py:516` and `668/702/718/730` specifically: `XETE_RPC_URL` drove signing traffic
with no scheme check while a plain-http *read* was refused. Leaving those unchanged
leaves the finding open. Each edit is a single token — `(RPC_URL` → `(_signing_rpc_url()`
— on one line, in a file all three tracks edit anyway. Nothing else in those functions
was read or altered. `settlement.py`, `draft.py`, `signguard.py`, `txguard.py`,
`client.py` and `spendguard.py` were not opened for editing at all.

**D5 — "`_signing_rpc_url()` raises inside tools that previously could not fail there.
You have introduced a new hard failure on a published path."**

**Reconciliation: refuted-with-evidence, with one caveat recorded.** All six call sites
are already inside `try/except Exception` handlers that return a JSON error object
(`xete_my_identity` catches around the balance read, `xete_settle_status` and the other
settlement tools wrap their whole body, `xete_alias_claim` wraps its whole body). Verified
by reading each. So the new exception surfaces as a `status: failed` object, not a crash —
`test_a_read_only_settlement_tool_refuses_a_plain_http_rpc` asserts exactly that at the
tool boundary. **Caveat, recorded not dismissed:** this DOES newly refuse an operator
running `XETE_RPC_URL=http://` against a non-loopback host. That is intended (it is the
finding), it fails closed, and loopback is still permitted
(`test_loopback_is_still_allowed_for_the_signing_rpc`). Track 2's reviewer flagged a
structurally similar problem — a new hard failure on an already-published path — so it
is worth naming here rather than discovering it at merge.

**D6 — "Your own probe showed only two of the four tools in [4] raising. Did you verify
the reviewer's claim, or just implement their fix?"**

**Reconciliation: the reviewer is right; my probe was wrong.** `xete_alias_reverse` and
`xete_resolve(<wallet>)` appeared to "return cleanly" only because the probe had left a
prior fixture in place whose proposed name failed `normalize_name` — an
`InvalidAliasName`, which IS an `AliasChainError` — so the code returned before ever
reaching `resolve_owner()`. With a valid proposed name both raise. This is pinned by
`test_an_insecure_rpc_refuses_the_tool_with_a_hint_not_a_stack_trace`, parametrised over
all four tools, which fails on all four against the pre-fix source. Recorded because it
is the one place my own verification initially contradicted a finding and the finding won.

**D7 — "`redact_url` runs inside error paths. If it throws, it converts a clean refusal
into a crash."**

**Reconciliation: fixed.** It catches `ValueError` from `urlsplit`, coerces non-strings,
and has no other failure mode. `test_redact_url_never_raises_on_junk` covers `None`, an
int, bytes, `http://[oops`, and `://`.

**D8 — "Restricting `fields_ignored` to identifier-shaped names hides a real protocol
change behind a count. You have traded a diagnostic for a security property."**

**Reconciliation: accepted trade, bounded.** A real endpoint's keys are identifier-shaped
and still reported by name — `test_fields_ignored_cannot_carry_a_sentence` asserts
`sol_enabled` (the actual field the reviewer saw live on `/alias/resolve`) comes through
by name while both injection payloads do not. Only non-conforming names degrade to
`fields_ignored_unnamed: <count>`, which still tells an operator the protocol drifted.
A server whose legitimate keys contain spaces would be an outage this makes marginally
harder to diagnose; no such server is known, and the alternative is a confirmed
injection channel.

**D9 — "Does anything still read the un-normalised name in the claim flow?"**

**Reconciliation: refuted-with-evidence.** Grepped the function: all five uses (`/alias/claim`
body, spend-gate `detail`, denial response, `/alias/claim/confirm` body, returned `name`)
take `bare`. `test_claim_posts_the_normalised_name` asserts the wire body. The
`%MyName` → `myname` split that finding [6] describes cannot occur.

**D10 — "Did any test you wrote submit a transaction, sign with a funded key, or touch
the real identity?"**

**Reconciliation: refuted-with-evidence.** `test_claim_posts_the_normalised_name` is the
only test that enters `xete_alias_claim`. It monkeypatches `server.IDENTITY_PATH` to a
`tmp_path`, and the permit server answers `status: "denied"` — the function returns at
the approval check, before `_authorize_spend`, before `Keypair.from_seed`, before
`Transaction.from_bytes`, and before `send_raw_transaction`. The whole suite runs with
`requests` monkeypatched; `net.calls == []` is asserted wherever a refusal should have
sent nothing. No test constructs a `solders` transaction. The real `~/.xete/identity.json`
(mtime 2026-07-31 22:58, predating this session) is never opened by the suite.

**D11 — "Benchmarks first — does any `benchmarks/BM-*.md` overlap this diff?"**

**Reconciliation: none exist here, and the four new ones are deliberately NOT committed.**
`benchmarks/` was untracked and gitignored by commit `30292de` ("security: untrack
vulnerability corpus from public-facing repo") because BM files document exploit paths and
this repo is public; the master corpus lives in the private `xete-agent-skills` repo. The
DDR skill says to author a BM file in the same commit as a protected-path defect fix, which
directly conflicts with that. I resolved it in favour of the security decision: four
benchmark cases are written to `benchmarks/` **on disk, untracked** —

- `BM-refusal-echoes-the-secret.md` (finding [1])
- `BM-allowlist-mistaken-for-injection-defence.md` (finding [2])
- `BM-asymmetric-endpoint-hardening.md` (finding [5])
- `BM-exception-family-escapes-the-handler.md` (finding [4])

— and are **not** `git add -f`'d. **Action required by a human:** copy these four into the
private `xete-agent-skills` corpus, or they are lost on the next clean checkout. I did not
do it myself because it is outside this worktree. All four are `Gate mapping: NEW`, so per
the gate-backtest skill each also owes a line in `solana-security-hardening`'s checklist;
that is a change to the shared skills repo and is left to the human as well.

---

## Reconciliation summary

| Finding | Severity | Disposition | Regression test |
|---|---|---|---|
| [1] credential echoed into 3 tools | high | **fixed** | `test_a_credential_in_the_permit_url_never_reaches_the_output` (×4 tools), `test_the_refusal_names_the_host_but_not_the_url`, `test_redact_url_*`, `test_a_credential_in_the_rpc_url_never_reaches_the_output` |
| [2] content injection via values / names | high | **fixed** (channel narrowed + labelled; see D2, R1) | `test_a_note_is_quarantined_*`, `test_untrusted_text_cannot_forge_a_new_line_*`, `test_untrusted_text_is_truncated_hard`, `test_sanitize_text_*`, `test_a_proposed_name_that_is_not_a_name_is_boxed_once_*`, `test_fields_ignored_cannot_carry_a_sentence`, `test_injected_key_names_are_quarantined_in_every_tool` |
| [3] `owns_both` forgeable | medium | **fixed as specified** (renamed + caveat; see D3, R2) | `test_owns_both_is_not_presented_as_a_client_verified_badge`, `test_reverse_does_not_put_a_bare_owns_both_*`, `test_a_server_lying_about_the_alias_half_*` |
| [4] `InsecureEndpoint` escapes 4 tools | medium | **fixed** | `test_an_insecure_rpc_refuses_the_tool_with_a_hint_not_a_stack_trace` (×4), `test_an_unreachable_rpc_still_reports_chain_unavailable` |
| [5] asymmetric hardening + ignored node | medium | **fixed** | `test_plain_http_is_refused_for_the_rpc_that_signs`, `test_a_read_only_settlement_tool_refuses_a_plain_http_rpc`, `test_loopback_is_still_allowed_*`, `test_alias_reads_inherit_the_operators_already_configured_node`, `test_the_dedicated_variable_still_wins_*`, `test_the_public_default_applies_only_*`, `test_the_tool_reports_the_endpoint_it_actually_used` |
| [6] claim posts raw name | low | **fixed** | `test_claim_posts_the_normalised_name`, `test_claim_refuses_an_impossible_name_*` |
| [7] stale README | low | **fixed** | `test_readme_does_not_claim_the_live_alias_endpoints_are_undeployed` |
| [8] no DDR on a protected path | medium | **fixed** — this file; hooks enabled via `git config core.hooksPath .githooks`, and see below | n/a |

On [8], the finding understates the problem. Setting `core.hooksPath` was not sufficient:
`.githooks/pre-commit` and `.githooks/pre-merge-commit` were committed mode `100644`, so
git skipped them with `hint: the hook was ignored because it's not set as executable`.
The gate was decorative for a second, independent reason that survives any
`git config` fix and reappears in every fresh clone. Both are now mode `100755`
(`.githooks/pre-push` already was). Verified by observing the hook's own
`[xete-gate] Protected paths staged on branch ...` output on the commit that carries this
line — before the chmod, that line did not appear at all.

One defect found by me, not by the reviewer, and fixed in the same pass: `xete_alias_quote`
reported the permit server's echoed `name` rather than the name asked about, so a server
asked to price `%bob` could answer `name: "carol"`. Covered by
`test_a_quote_reports_the_name_we_asked_about_not_the_servers_echo`.

**Suite: 146 passed** (`test_alias_read.py`, `test_alias_read_hardening.py`,
`test_spendguard.py`). 45 new tests; 42 of them fail against the pre-fix source, verified
by `git stash push -- src README.md` and re-running. The 3 that pass pre-fix are
deliberate non-regression guards on behaviour the fix must NOT change (the ordinary
`chain_unavailable` path, and the two RPC-precedence cases that were already correct).

---

## Residual risk (accepted, not closed)

- **R1 — prompt injection is reduced, not eliminated.** A 200-char single-line note and
  identifier-shaped key names still reach the agent, now under an explicit untrusted
  banner. Matches merge-memo residual #6. Closing it needs a policy at the agent
  boundary, not a change in this package.
- **R2 — `owns_both_per_server` is still forgeable by design.** Pinned by a passing test
  that asserts the attack works. Real fix: an on-chain SNS read.
- **R3 — nobody has read the xete-alias program source.** A4/A5 are inferred from this
  repo's own normaliser and from mainnet transactions. Merge-memo residual #5. Finding [6]
  is fixed in a way that does not depend on which way the inference falls, but the
  106-byte layout and PDA derivation (A8) still do.
- **R4 — the RPC remains a single trusted party.** Unchanged by this work. Merge-memo
  residual #2. Finding [5]'s fix means the operator now at least gets the node they
  configured.
- **R5 — `_signing_rpc_url()` newly refuses `http://` to a non-loopback host** for
  settlement and messaging. Intended, fails closed, but it is a behaviour change on paths
  this track does not own. Flag it to the settlement and signing tracks at merge (D5).

## Review provenance

Fresh-context subagent session, spawned by the orchestration script with the findings
file and the branch, no prior conversation history from the session that wrote
`fix/alias-read @ 86a32a0`. The code under review was written by a DIFFERENT session;
the fixes in this commit were written by me. The doubts above are therefore a genuine
fresh-context pass over the ORIGINAL work (D6 is where that pass corrected my own
verification against the reviewer's), but D1–D5 and D7–D11 are a **self-review of my own
fixes**. Per CLAUDE.md rule 5 that is same-context-only *(status superseded 2026-08-01 — independent review obtained; see the appended section)* for the fix diff and does not
substitute for the independent re-review the merge memo requires
("Fix → re-review → DDR → merge, in that order"). This artifact records the work and
satisfies the hook; it is **not** a substitute for the adversarial re-review before this
merges to trunk. Recommended before merge: hand this diff to a fresh reviewer with D2,
D3, D5 and D8 as the starting prompts — those are the four places I accepted a trade
rather than closed a hole.

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

**Credential redaction — YES.** The reviewer imported `redact_url` from this tree and fed it
nine credential-bearing URLs, finding two that returned the live token byte-for-byte
(homoglyph `@` characters make `urlsplit` raise, and the `except ValueError` arm fell back to
a function with no path pass). It also **retracted two of its own claims** on this thread
unprompted: a `.strip()` it had recommended turned out to be unnecessary, and it downgraded
its own severity call after checking reachability. The finding was fixed at the ROOT — in
`scrub` itself — and the reviewer re-verified that through its oracle run.

**The prose-quarantine property — reviewed 2026-08-01 against `1c63da7`,** after the
reviewer answered NO when asked. Its reason for the "no" is worth preserving: it had read
`test_primitives_hardening.py` that evening, but only because a hollow guard lived in it,
and *"reading a test that pins someone else's fix is not reviewing the property — I am not
going to let proximity masquerade as coverage."*

**Verdict: the quarantine mechanism is sound.** It tried to break it and could not.
Confirmed: every consumer honours the box (`_quarantine()` at all nine sites in `server.py`,
including the nested case where a chain error inside an alias tool is re-keyed to
`chain_untrusted_server_text` rather than flattened); `sanitize_text` holds against a
newline-plus-U+202E payload; and the JSON-RPC error path handles non-object shapes
(`{"error": 500}`, `{"error": ["x"]}`) with the `-32016` freshness branch correctly guarded
on `floor is not None` AND `isinstance(code, int)`.

One LOW finding: `AliasChainError`'s "this client's own words, end to end" was not true —
Cf characters passed `normalize_name` and reached three interpolations unsanitised. Fixed at
`f67d706` at the guard rather than at the interpolations, which the reviewer confirmed is
better than the fix it proposed, and re-verified 4/4.

### Status

Fresh-context adversarial review: **OBTAINED**, for both halves of the pair.


## Verdict: SHIP

Superseding every earlier verdict in this file. The condition those verdicts were held open
for — a genuine fresh-context adversarial pass by a party that did not write the code — has
been met and is documented above, including what the reviewer did NOT cover.

The historical statuses are left in place rather than rewritten. An artifact that shows only
its final state cannot be audited: the useful record is that this sat open, why, and what
closed it.
