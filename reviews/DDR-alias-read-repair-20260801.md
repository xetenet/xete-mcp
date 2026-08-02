# DDR: the alias-read hardening's own repair — credentials survive no URL spelling, the sanitiser cannot crash, redaction keeps only the origin, and BOTH untrusted authors' prose is boxed

Commit scope:
- `src/xete_mcp/safehttp.py` (owned by this track)
- `src/xete_mcp/alias_chain.py` (owned by this track)
- `src/xete_mcp/server.py` (SHARED — 9 hunks, 29 added / 8 removed, all inside the
  `%alias` section: the quarantine banner, `_endpoint_error`, `_chain_error`, one line in
  `_reverse_view`, one line in `xete_alias_quote`)
- `test_alias_read.py`, `test_alias_read_hardening.py`

Input: six demonstrated defects from three independent adversarial reviewers against
`fix2/alias-read @ 5b9c254`. Every one was reproduced here before being fixed. Four of the
six were CREATED by the previous round's hardening — the same shape as the round before it,
which is the finding that matters most about this track.

---

## Claim

Falsifiable, in the reviewers' own numbering:

1. **[R1]** For every spelling of userinfo an operator can type — `user:pw@host`,
   `user:pw#SECRET@host`, `user:pw?SECRET@host`, `user:pw%40host`,
   `https:/\/\user:pw@host` — `require_secure_url` REFUSES before any request is made, and
   neither the refusal, `redact_url`, nor `scrub` reproduces any byte of the password.
2. **[R2]** `sanitize_text` never raises for any JSON value. A hostile or non-conformant
   JSON-RPC error (`{"error":{"code":-32602}}`, `{"error":{"message":429}}`,
   `{"error":500}`, `{"error":["x"]}`) produces `reason: "chain_unavailable"` from all
   three read tools and an `AliasChainError` — never a `TypeError` — from
   `_resolve_recipient_wallet`.
3. **[R3]** No string this package emits contains any part of a configured URL beyond
   `scheme://host:port`. `resolution.rpc` on a SUCCESSFUL resolve is an origin.
4. **[R4]** No third-party exception TEXT is interpolated into any message. Query-string
   credentials in `XETE_RPC_URL` / `XETE_PERMIT_URL` do not appear in any tool's output.
5. **[R5]** Every string authored by a party other than this client — permit-server `note`,
   `status`, dropped key names, HTTP reason phrase, `Location`; RPC `error.message` and
   account `owner` — is delivered inside a `_quarantine()` box whose `_warning` names its
   author. There is no unlabelled top-level field carrying server prose. The comment above
   `_QUOTE_FIELDS` that asserted this is now true.
6. **[R6]** The identifier-shaped-key channel is 5 names x 24 chars with at most three
   `_ . -` separators each. Measured width of one hostile `xete_alias_quote` response:
   **248 characters, down from the reviewer's measured 661** (ceiling 368, down from 1048).

---

## Assumptions

| # | Assumption | Status |
|---|---|---|
| A1 | `urlsplit` ends the authority at `?`/`#`, so `.username`/`.password` are None for a password containing either | **verified** — `urlsplit('https://svcuser:hunter2#SECRET@permit.test/')` → `netloc='svcuser:hunter2'`, `username=None`, `password=None`, `fragment='SECRET@permit.test/'` |
| A2 | The base commit `86a32a0` did not print these strings, so each is a regression, not a pre-existing gap | **verified** — base used `str(detail)[:200]` (no crash) and read only `XETE_SOLANA_RPC` in `_chain_source` (no inherited token) |
| A3 | `sanitize_text` reaches non-string values in production, not just in a hostile lab | **verified** — `alias_chain.py:181` passes `error.message` straight from parsed JSON; a *legal* JSON-RPC error object has no required `message` member |
| A4 | Dropping the path from `redact_url` does not destroy the diagnostic | **verified by reasoning + test** — `kind`, `status` and the tool name identify which endpoint; `scheme://host:port` identifies which server. `test_an_unreachable_endpoint_still_says_what_went_wrong` pins that the failure MODE survives |
| A5 | The exception CLASS is enough diagnostic to replace the exception text | **verified** — `ConnectionError` / `Timeout` / `SSLError` / `InvalidURL` are the distinctions an operator acts on, and none contains caller-supplied bytes |
| A6 | Real permit-server key names fit 24 chars / ≤3 separators | **verified** — longest in `_QUOTE_FIELDS` is `land_rush_lamports` (18 chars, 2 separators); pinned by `test_a_real_api_key_name_is_still_reported_by_name` |
| A7 | `requests` does not decode `%40` when splitting the authority, so `user:pw%40host` reaches the wire as host `svcuser` | **assumed** — not verified against urllib3 source. Mitigated by refusing the URL outright, which makes the wire behaviour irrelevant |
| A8 | No other track edits these files this round | **verified** — `git status` clean apart from my four files; `spendguard.py` untouched |

---

## Doubts raised

### Fresh-context (three independent adversarial reviewers, on `5b9c254`)
The six findings above ARE the fresh-context doubt for this round, each with a runnable
probe against loopback endpoints. They were not accepted on assertion: every one was
re-reproduced locally before any code changed (transcript below, under Reconciliation).

### Self-attack (same context — recorded honestly as same-context-only *(status superseded 2026-08-01 — independent review obtained; see the appended section)*)
No subagent-spawn tool was available in this thread, so the doubt pass on the REPAIR itself
was mine. Per CLAUDE.md rule 5 this does not count as fresh context. It was nonetheless a
real attack with a real harness — a loopback permit server and a loopback JSON-RPC endpoint
(`/tmp/repair/live.py`, `/tmp/repair/creds.py`, `/tmp/repair/width.py`) — and it found **two
defects the reviewers did not**, both of the same class as [R1]:

- **D-self-1**: `https://svcuser:pw%40permit.test/` — percent-encoded `@` separator.
  `urlsplit` reports a host named `svcuser` and no credentials; the textual `@` scan found
  no `@`; the URL was ACCEPTED and `svcuser:pw` printed as the failing endpoint.
- **D-self-2**: `https:/\/\svcuser:pw@permit.test/` — backslash-mangled scheme separator.
  A `://`-only scan finds no authority, so the credential check was skipped, `redact_url`
  fell through to `scrub` (which also requires `://`), and the whole credentialed string
  landed in the "names no host" refusal message.

Both are fixed and both have regression tests
(`test_userinfo_written_another_way_is_still_refused_and_still_redacted`, which fails on
`5b9c254`).

### Benchmarks whose `Paths` overlap this diff
All four existing benchmarks match. Their doubt prompts, answered:

**BM-refusal-echoes-the-secret** — *"print the rejection message for the worst-case input;
check the sibling fields too."*
Answered by running exactly that, for five password spellings x four tools:
`SECRET occurrences {quote:0, resolve:0, reverse:0, xete_resolve:0}` for all five. This
benchmark's own real-solution text (`redact_url()` + `scrub()`) is what [R1] proved
insufficient — the prompt was answered last round with ONE password spelling. The prompt is
now widened: *the worst-case input includes the worst-case SPELLING of the input.*

**BM-allowlist-mistaken-for-injection-defence** — *"for each surviving key: who writes its
VALUE, how long, can it contain a newline? Is the DROP REPORT a channel?"*
Answered per key this time and the answer produced [R5d]: `status` is written by the server,
48 chars, allow-listed, and was still flat at top level. The prompt's second half is
extended by [R6]: an identifier-shaped drop report is a *narrower* channel, not a closed
one, and "identifier-shaped" at 40 chars is readable English. Both budgets tightened.

**BM-exception-family-escapes-the-handler** — *"draw the actual class tree for every
exception the module's public functions can raise; test at the TOOL boundary."*
Answered, and it is what [R2] is: `TypeError` is not in the tree at all — it is raised by a
*defensive helper*, below both error families, so widening the `except` clause could never
have caught it. Extension to the prompt: **the exception tree must include the ones your own
sanitisers raise on malformed input.** Tested at the tool boundary, parametrised over four
hostile bodies x three tools plus `_resolve_recipient_wallet`.

**BM-asymmetric-endpoint-hardening** — *"(1) COVERAGE: grep every other variable of the same
kind. (2) UPGRADE PATH: what does an existing install do after upgrading?"*
Answered, and (2) is precisely [R3]. Making alias reads inherit `XETE_RPC_URL` was the right
fix for the config trap and simultaneously created a NEW upgrade-path defect in the opposite
direction: an operator whose `XETE_RPC_URL` is a QuickNode URL had their token start being
printed on every success. Extension to the prompt: **when a variable starts being READ by
new code, ask what that code PRINTS, not only what it requests.**

---

## Reconciliation

| Doubt | Reproduced (pre-fix evidence) | Disposition |
|---|---|---|
| **[R1]** `#`/`?` in password defeats refusal + `redact_url` + `scrub` | `require_secure_url('https://svcuser:hunter2#SECRET@permit.test/')` returned the URL **unchanged**; `redact_url` → `https://svcuser:hunter2#<redacted>`; `scrub` left the string untouched | **fixed** — `_authority_span()` takes the authority textually (after `scheme:` + 2+ slashes of either lean, up to the first slash of either lean); `_userinfo_end()` treats `@` and `%40` as separators; `require_secure_url` refuses on that, not on `parsed.username`; `redact_url` cuts userinfo textually BEFORE `urlsplit`; `_USERINFO_RE` widened to `[^\s/\\]*@`. Tests: `test_a_credential_in_the_permit_url_never_reaches_the_output` (now 4 passwords x 4 tools), `test_a_delimiter_in_the_password_does_not_smuggle_the_url_past_admission`, `test_scrub_reaches_userinfo_across_a_delimiter`, `test_userinfo_written_another_way_is_still_refused_and_still_redacted` |
| **[R2]** `sanitize_text` raises `TypeError` past every handler | `sanitize_text(None)` → `TypeError: 'NoneType' object is not iterable`; same for `429`, `500`, `["x"]` | **fixed** — one-line coercion at the top of `sanitize_text`. Tests: `test_sanitize_text_coerces_instead_of_raising`, `test_a_non_string_jsonrpc_error_is_a_clean_refusal_not_a_traceback` (4 bodies x 3 tools), `test_the_settlement_recipient_path_raises_its_own_error_not_a_typeerror` |
| **[R3]** RPC token in URL path printed on the SUCCESS path | `rpc_display()` returned `http://127.0.0.1:9/qn-TOKEN-9f3a1c-DO-NOT-LOG/` verbatim; `_chain_source()` put it in `resolution.rpc` | **fixed** — `redact_url` now emits origin only, `/<redacted-path>` marker when the path is non-empty. Tests: `test_the_rpc_token_in_a_url_path_is_not_printed_on_a_successful_resolve`, `test_rpc_display_is_an_origin_not_a_url` |
| **[R4]** query credentials ride out in `requests`' exception text | `get_json('https://127.0.0.1:1/?api-key=hl-SECRET-KEY-4242')` → `EndpointError` containing `hl-SECRET-KEY-4242` | **fixed**, two layers: the exception TEXT is no longer interpolated at any of the three sites (class name only), and `scrub` gained a `?key=value` pass as defence in depth. Tests: `test_scrub_strips_a_query_credential`, `test_a_query_credential_in_the_rpc_url_never_reaches_the_output`, `test_a_query_credential_in_the_permit_url_never_reaches_the_output`, plus `test_scrub_does_not_mangle_an_ordinary_question_mark` and `test_an_unreachable_endpoint_still_says_what_went_wrong` guarding the fix's own blast radius |
| **[R5]** four unboxed prose channels; the `_QUOTE_FIELDS` comment was a false claim in source | reproduced all four on a live loopback pair | **fixed** — `EndpointError.server_text` and `AliasChainError.server_text` carry endpoint-authored strings *beside* the message, never inside it; `_endpoint_error` and `_chain_error` box them; a second banner names the RPC as author; `owner` is shape-checked (base58 → named in the clear, anything else → boxed); `status` moved into the box; the comment corrected. Tests: `test_a_hostile_rpc_error_message_is_boxed_not_a_top_level_error`, `test_the_reverse_path_also_boxes_a_hostile_rpc_error_message`, `test_a_hostile_owner_program_string_is_boxed_not_rendered_into_the_error`, `test_a_permit_http_reason_phrase_is_boxed_not_a_top_level_error`, `test_a_redirect_target_is_boxed_not_rendered_into_the_error`, `test_status_is_quarantined_like_every_other_server_written_string`, `test_a_real_program_address_is_still_named_in_the_clear` |
| **[R6]** channel ~5x wider than self-reported | reviewer measured 661 chars in one response | **fixed** — `_MAX_IGNORED_REPORTED` 20→5, `MAX_KEY_NAME` 40→24, and a key name must now be alphanumeric runs joined by at most three `_ . -`. Re-measured on the reviewer's exact payload: **248**. Tests: `test_identifier_shaped_keys_cannot_be_readable_english_prose`, `test_the_reported_key_budget_is_small`, `test_one_quote_response_cannot_deliver_a_paragraph`, `test_a_real_api_key_name_is_still_reported_by_name` |
| **D-self-1** `%40` separator | `require_secure_url` ACCEPTED; `redact_url` → `https://svcuser:pw%40permit.test` | **fixed** (see [R1]) |
| **D-self-2** backslash scheme separator | refused for the wrong reason ("names no host") with the credential in the message | **fixed** (see [R1]) |

### Existing tests changed, and why that is not weakening

Two, both **strengthened**, neither a security test whose property was reduced:

1. `test_redact_url_strips_every_place_a_credential_hides` — three expectations changed
   from keeping the path to redacting it (`https://permit.test/path` →
   `https://permit.test/<redacted-path>`). Strictly MORE is redacted than before; the
   property "a credential in a URL does not survive redaction" is unchanged and now covers
   the path, which is where QuickNode/Alchemy/Ankr put the token. Six new cases added to
   the same parametrisation.
2. `test_a_jsonrpc_error_is_not_read_as_unclaimed` — the `match="WrongSize"` was dropped.
   The property under test is *"a JSON-RPC error RAISES rather than returning None"* and it
   is still asserted. `WrongSize` is a string the RPC wrote; asserting it appeared in our
   exception message was asserting the [R5a] defect. The test now asserts the inverse
   (`"WrongSize" not in str(e)`) plus `e.server_text == "WrongSize"` plus the client-authored
   `-32602`, i.e. it pins strictly more than it did.

### Residual risk, stated plainly

- **The quarantine box is a mitigation, not a boundary.** A reading agent that ignores
  `_warning` still sees up to 248 attacker-chosen characters per `xete_alias_quote`
  response. The floor is `note` (200) — an allow-listed prose field on the real endpoint.
  Removing it entirely is a product decision, not a security fix I should make unilaterally.
- **A7 is unverified.** I did not read urllib3's authority parser to confirm what it does
  with `%40`. The URL is refused outright, so this only matters if some other caller ever
  bypasses `require_secure_url`.
- **`redact_url` over-redacts a stray `@` in a query on a path-less URL** (the authority
  scan runs to the first slash). Harmless direction; noted so the next reviewer does not
  file it as a bug.
- **Origin-only redaction costs diagnostic detail.** An operator whose permit server 404s
  now sees `https://host/<redacted-path>` rather than the path. The tool name identifies
  the endpoint. I judged the uniform rule better than a heuristic that tries to tell a
  token-shaped path segment from a safe one — such a heuristic is exactly what an attacker
  attacks.
- **`server.py` is shared.** 9 hunks, all inside the `%alias` section. The
  `_quarantine(_banner=...)` signature change is the only one another track could collide
  with; it is backward-compatible for every existing call site.

---

## Verdict: SHIP

with the recorded caveat that the doubt pass on this repair was **same-context-only *(status superseded 2026-08-01 — independent review obtained; see the appended section)*** (no
subagent tooling in this thread). Per CLAUDE.md rule 5 that downgrades a contract-path
verdict; `src/xete_mcp/*.py` is a protected path here. Mitigating facts, offered for the
human to weigh rather than to override the rule: (a) the round's INPUT was three genuine
fresh-context adversarial reviews, all six findings reproduced locally before any change;
(b) the self-attack was run against live loopback endpoints and did find two further
defects; (c) 225 tests pass, and every one of the 22 new/changed test names fails on
`5b9c254`. **Recommend a fresh-context reviewer be pointed at this diff before it merges to
trunk** — this track has now regressed its own hardening twice, which is the strongest
available argument that one more pair of eyes is cheap.

Suite: `225 passed in 1.37s`
(`test_alias_read.py`, `test_alias_read_hardening.py`, `test_spendguard.py`)


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
