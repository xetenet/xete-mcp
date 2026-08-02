# DDR: a paid RPC credential cannot reach the agent's context on any branch of any tool, and the guard that says so cannot pass by finding nothing

Commit scope: `src/xete_mcp/safehttp.py`, `src/xete_mcp/settlement.py`,
`src/xete_mcp/server.py`, `src/xete_mcp/txguard.py`, `test_endpoint_credential_leak.py`,
`test_primitives_hardening.py` (deletion), `conftest.py`,
`.github/workflows/tests.yml`, `benchmarks/BM-a-guard-satisfied-by-the-absence-of-what-it-searches-for.md`

## Claim

An operator's RPC credential — Helius `?api-key=TOKEN`, QuickNode `/qn-TOKEN/`, or HTTP
userinfo — does not appear in anything `xete_settle_status`, `xete_verify_settlement_tx`,
`xete_settle_create`, `xete_draft_settlement_tx` or `xete_alias_claim` returns, on the
success path or any refusal path, in the single-provider default configuration or the
two-provider one. And the check that certifies this **fails when it stops being able to
see**, rather than passing over an empty result set.

**Explicitly NOT claimed:** that no credential can reach a LOG. This covers what the tools
return to the agent. Anything a dependency writes to stderr on its own initiative is out of
scope and unaddressed.

## Assumptions

| # | Assumption | Status |
|---|---|---|
| A1 | The previous fix (`701fdca`) closed the settlement credential leak | **FALSIFIED** — it closed the two-provider configuration and left the single-provider DEFAULT raw on every call. See doubt 1 |
| A2 | The static guard in `test_primitives_hardening.py` was covering this | **FALSIFIED, and it was worse than absent** — see doubt 2 |
| A3 | `scrub` strips credentials from arbitrary text, as its docstring says | **FALSIFIED** — no path pass, so it returned QuickNode credentials byte-for-byte. See doubt 3 |
| A4 | Truncating an error to 300 characters bounds the exposure | **FALSIFIED** — `requests` puts the URL at roughly character 110 |
| A5 | The suite that verifies all this actually runs | **FALSIFIED twice over** — no CI job ran pytest, and a bare `pytest` could not collect this repo at all. See doubt 5 |
| A6 | Each of the thirteen fixes is load-bearing | **Verified by mutation, 13/13**, after the harness itself was corrected twice — see doubt 6 |
| A7 | Redaction does not destroy the diagnostic | **Verified** — every behavioural assertion checks the HOST survives as well as that the credential does not. Over-redaction is a defect in the other direction and is asserted against |
| A8 | `scrub` calling `redact_url` cannot recurse | **Verified, then made structural** — see doubt 4 |

## Doubts raised

Round 1 is a **fresh-context adversarial review by s1**, an independently-running session
with its own clone, its own tooling and no access to this session's history. It reached
these findings by EXECUTING the code, not by reading it, and delivered them with a `STOP.
DO NOT PUBLISH` on a build I believed was ready. Under CLAUDE.md rule 5 this is the pass
that counts; my own round-2 checks are recorded separately and carry no independent weight.

Every one of its findings was re-verified at THIS tree's HEAD (`a297e5d`, three commits
past the `701fdca` it reviewed) before any code moved. Line numbers had shifted; every
defect was still present.

1. **(s1, RELEASE BLOCKER — A1)** *The single-provider default leaks on every call.*
   `_ONE_SOURCE_CAVEAT` is a `.format()` template keyed `{endpoint}`, and all three call
   sites passed `endpoint=rpc_url` unwrapped. It fires whenever `XETE_RPC_URL_2` is unset —
   the default install. So `xete_settle_status` returned `endpoints_asked:
   ['https://…helius-rpc.com?<redacted>']` in the same dict as a `note` containing the full
   `?api-key=`: the redacted field and the raw credential side by side. Also raw: both
   endpoints as **dict KEYS** on the disagreement path, and `{rpc_url or '(unnamed)'}` in
   two `SettlementSubmitError` messages surfaced by three tools on ORDINARY rejections
   (wrong salt, already claimed, insufficient lamports).
   → **Fixed**, seven sites. My previous commit message claimed it had fixed "endpoints_asked
   and the verdict strings"; that was untrue of three verdict/note strings, and the claim is
   corrected here rather than left standing.

2. **(s1, HIGH — A2)** *The guard that certified this closed had erased its own ability to
   see.* `test_the_settlement_module_cannot_emit_an_unredacted_endpoint` searched for
   `{rpc_url}`, `{second}`, `{url}`. It matched six sites; the fix wrapped those six as
   `{redact_url(rpc_url)}` — **which deleted the literal tokens the regex keys on**. From
   that commit it matched zero and passed green over every remaining leak, and over the
   whole of `server.py`, which it never opened.
   → **Fixed by deletion, not repair** — the shape is the defect. Replaced with a
   behavioural canary sweep that never reads the source, plus an AST sweep whose passing
   condition includes **a floor on how many sites it examined**. Benchmarked as
   `BM-a-guard-satisfied-by-the-absence-of-what-it-searches-for.md`. This is the fifth
   hollow control found today and the only one that did not merely miss a bug — it
   *retired* one.

3. **(s1, HIGH — A3/A4)** *`server.py`'s untruncated `reason` field.* `txguard._rpc_call`
   talks to `requests` directly rather than through `safehttp`, and re-raises the library's
   own exception text, which embeds the full credentialed URL. It reaches the agent through
   a field deliberately left untruncated, via `bounded_simulated_debit` (mandatory by
   default on EVERY claim) and `treasury_for_claim`. Triggers are routine operations — DNS
   failure, connect timeout, TLS error, connection reset, 401 after a key rotation.
   → **Fixed at the raise AND at the boundary.** Both, because a boundary that is correct
   only while its callers are correct is not a boundary — and the mutation run proved the
   point: with only the source fix in place, removing the boundary's `scrub` left the suite
   green. That fix was decoration until a test was written that injects an UNSCRUBBED
   exception.

4. **(s1, MEDIUM — A3)** *`redact_url`'s `except ValueError: return scrub(raw)` fail-open.*
   s1 proved by execution that a homoglyph `@` makes `urlsplit` raise, and `scrub` has a
   userinfo pass and a query pass and **no path pass**, so a QuickNode credential came back
   whole from the function whose only job is removing it.
   → **Root cause fixed rather than the symptom.** `scrub` now routes every embedded
   `scheme://…` through `redact_url`, so its docstring's claim is true for the first time.
   That creates a cycle risk (`scrub` → `redact_url` → `scrub`); the guard on that branch
   already excludes every string that could match a URL, but a proof spread over two
   functions and three regexes whose failure mode is unbounded recursion inside the
   credential redactor is not a thing to leave resting on an argument. Factored into
   `_scrub_credentials` so the cycle is **structurally impossible**.

5. **(s1, separate report — A5)** *Nothing in CI runs the tests, and a bare `pytest` cannot
   run them either.* Four workflows, zero pytest references. And three root-level
   `test_*.py` files are standalone scripts: two execute at import and end in a
   module-level `sys.exit`, killing collection (exit 3, zero tests collected).
   → **Both fixed.** `conftest.py` excludes the three scripts; `.github/workflows/tests.yml`
   runs a bare `pytest` on PRs and pushes, plus a runtime tool-count assertion. **A bare
   `pytest` from the repo root now collects and passes 768 tests — the first time that has
   ever worked here.**

6. **(self, round 2)** *Is each fix load-bearing?* — **Two were not, and the harness lied
   about which.** The first mutation run reported the untruncated-`reason` fix as
   decoration; it was, and doubt 3's new test fixed it. The second reported the generic
   error handler as decoration; that was the HARNESS's defect — the anchor matched two sites
   in `server.py` and `replace(old, new, 1)` mutated the one in a different tool.
   → **Fixed in the harness: an ambiguous anchor is now a hard error, not a silent
   first-match.** It immediately caught a third instance (the caveat line appears three
   times), which forced the three caveat sites to be pinned individually — and that in turn
   exposed that two of the three had no behavioural coverage at all, because only the
   earliest-returning branch had ever been driven. **This is the tenth time today the
   measuring instrument was the defect rather than the code.**

7. **(self, round 2)** *Does the AST sweep cry wolf?* — Initially yes: it flagged
   `answers[first_url]` (which emits the wallet, not the URL) and the predicate of
   `redact_url(u) if u else '(unnamed)'`.
   → **Fixed precisely** — a subscript INDEX and an `IfExp` TEST are not emissions.
   Recorded because the temptation was to lower the floor or trim the name list instead,
   and that is the precise mechanism by which the predecessor guard went blind.

## Reconciliation

- Doubts 1, 2, 3, 4, 5, 6, 7: **fixed**, each with a test proven red by mutation.
- **s1 retracted one of its own findings**, unprompted: it had reported a 429 `api-key`
  leak, then verified against a live local 429 server that `solana-py`'s
  `_build_error_message` discards the httpx message, and withdrew it. Recorded because a
  reviewer that corrects itself downward is the reason the rest of its findings were worth
  acting on without re-litigating each one.
- **Open, accepted:** two items s1 classified BACKLOG and I agree are not blockers. (a) On
  the DURABLE claim path, `server.py` still writes the permit server's raw status verbatim
  where the adjacent key sanitises the same value — it cannot forge ownership. (b)
  `blockhash_is_live` is never passed at its only call site; durable-nonce staleness is
  closed twice elsewhere, so the floor is zero. Both go to `next-versions/xete-mcp.md`.
- **Open, accepted:** `05cf0cf` narrowed one half of the spendguard seam scan from
  `ast.walk(func)` to body-only, so decorator expressions and argument defaults are scanned
  by no scope. A widened rescan of real `src/` finds the identical 17 sites, so nothing is
  missed today; it is a detection gap, not a live hole.

## Verification

- **768 tests pass** from a bare `pytest` at the repo root (was 740 by explicit file list,
  and 0 by bare `pytest` — it did not collect).
- **13 of 13 mutations go red**, one at a time, sources restored and verified byte-identical
  after each. Ambiguous anchors are fatal in the harness, so a mutation that lands on the
  wrong site is reported rather than counted.
- **8 distinct leaks reproduced by execution before the fix**, including one on a
  `verified: true` SUCCESS return, then re-run green after.
- Invariants: `spendguard.py` byte-identical to `ee81682` (0 diff lines); 15 tools at
  runtime.

## Benchmark doubt prompts with overlapping Paths

- **BM-a-control-that-identifies-a-source-by-the-string-you-typed** — answered. `redact_url`
  is used here for DISPLAY only; no identity decision is keyed on it. `endpoint_identity`
  remains the identity function and is untouched by this change.
- **BM-the-one-site-that-produced-no-conflict** — answered, and it is doubt 6: every fix was
  reverted individually and the suite was watched to fail.
- **BM-a-safety-mark-that-latches** — not applicable. Nothing here records, caches or
  thresholds a remote-chosen value; `scrub` and `redact_url` are pure functions of their
  input.
- **BM-unprovable-state-treated-as-proven** — answered, and it is doubt 2 in its purest
  form: a guard whose green result was proof of nothing.

## Verdict: SHIP

An independent session, running its own clone with no shared history, executed this code and
returned a release blocker on a build I had already called ready — and it was right on every
count that mattered, including one I had reported as fixed in a commit message. Thirteen
fixes, thirteen mutation-proven tests, and the suite is runnable and CI-enforced for the
first time.

The thing a reader should carry away is not the leak. It is that **the check certifying the
leak was fixed had been rendered incapable of failing by the fix itself**, and no amount of
re-reading it would have revealed that — only executing it against a credential would, which
is what an outside reviewer did and what I had not.
