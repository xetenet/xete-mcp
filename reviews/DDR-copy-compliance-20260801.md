# DDR: no published surface asserts that sending a message costs, could cost, or is free-for-now

Commit scope: `server.json`, `README.md`, `gemini-extension.json`, `pyproject.toml`,
`src/xete_mcp/server.py` (two tool docstrings), `test_copy_compliance.py`,
`next-versions/xete-mcp.md`

## Claim

Every surface that syndicates to a directory, renders in an MCP client, or appears on the
PyPI project page describes what a configuration variable IS, without asserting that
messaging has a price — present or future — and a test fails the build if that stops being
true.

**Explicitly NOT claimed:** that the string "charges to send" appears nowhere in the
package. It survives in one RUNTIME diagnostic, deliberately, and that decision is recorded
below and escalated rather than taken silently.

**Also NOT claimed:** that 0.1.5 can be corrected. It cannot — see A4.

## Assumptions

| # | Assumption | Status |
|---|---|---|
| A1 | The pre-publish copy audit covered this | **FALSIFIED** — it grepped four phrases and returned clean over two live violations. See doubt 1 |
| A2 | The violation is confined to `server.json` and `README.md` | **FALSIFIED** — three more sites, found by widening the SURFACE rather than the pattern. See doubt 2 |
| A3 | An earlier fix of the same pair was sufficient | **FALSIFIED** — it relocated the charge instead of removing the claim. See doubt 3 |
| A4 | The 0.1.5 registry record can be corrected in place | **FALSIFIED** — PyPI renders the README as the project description and that is immutable per version, so 0.1.5's page cannot be edited at all. 0.1.6 is required, not preferred |
| A5 | Everything the sweep flags is a violation | **FALSIFIED** — three legitimate strings, allow-listed with reasons; one runtime diagnostic left alone. See doubt 5 |
| A6 | The new guard cannot go hollow the way its predecessor did | **Verified by three explicit properties** — see Verification |

## Doubts raised

The finding is from **s1**, the independently-running session, which held all remaining
directory submissions rather than carrying the copy into two more listings by hand. It was
re-verified here against `raw.githubusercontent.com/.../main/server.json` — the published
bytes, not the local tree.

1. **(s1 — A1)** *The audit that ran before publish returned CLEAN over two live
   violations.* It grepped `free alpha|free during|currently free|will start charging`;
   neither offending string contains any of those tokens.
   → **Root cause accepted and fixed structurally.** A phrase list encodes the WORDING of
   the last violation, so it goes stale the moment anyone paraphrases — and a clean result
   from a stale matcher is indistinguishable from compliance. Replaced with a concept sweep:
   any sentence mentioning cost AND mentioning sending.

2. **(self, extending the reviewer's finding — A2)** *Is it only the two reported sites?* —
   **No.** Widening the SURFACE (not the pattern) found three more: the built `.mcpb`
   manifest inherited both strings from `server.json`, and **two tool docstrings —
   `xete_my_identity` and `xete_send_message` — assert the same thing.** Those render
   directly in an MCP client's tool picker and are the source the `.mcpb` is generated from.
   → **Fixed.** Recorded because the reviewer's sweep was correct and still incomplete for a
   reason worth naming: it swept the files it knew were published. The `.mcpb` inheritance
   is invisible unless you sweep the BUILT artifact, which is what surfaced it.

3. **(s1, from this project's own record — A3)** *This exact pair was flagged before and
   "fixed".* The earlier fix RELOCATED the charge to a hypothetical other server. "Messaging
   on xete.net is free" implies by contrast that it is not free somewhere — the same
   future-price hint in a politer coat.
   → **Not repeated.** The replacements assert nothing about price in either direction. They
   are also TRUE: claiming a `%name` genuinely is an on-chain cost, so
   "used for on-chain actions such as claiming a name" is accurate without being a price
   claim about messaging.

4. **(self)** *Can the guard I am adding go hollow the way the one it replaces did?* — It
   could, in three ways: the matcher could stop matching, the allow-list could grow into a
   set of standing permissions nobody rereads, or the surface list could go stale.
   → **All three closed.** The test asserts the matcher still fires on the exact strings
   that SHIPPED (so a broken matcher fails rather than passes); it fails on any allow-list
   entry that no longer matches anything; and tool docstrings are swept via AST rather than
   by trusting a filename list. The first of those is the direct lesson of
   `BM-a-guard-satisfied-by-the-absence-of-what-it-searches-for`.

5. **(self — A5)** *Does the concept sweep over-refuse?* — Yes, deliberately, and one of the
   hits is a case where satisfying the rule would make the product worse. Sweeping all of
   `server.py` flags the RUNTIME message returned when a relay actually answers with an
   invoice: *"This xete server charges to send. Set XETE_SOL_KEYPAIR..."*
   → **Left alone, escalated, not decided silently.** It executes only when a server has
   genuinely demanded payment; an operator hitting it needs to know why the send failed and
   what to set. It appears in a tool RESULT, never in a listing, manifest, README or tool
   description. Blunting a real diagnostic for a cosmetic pass is the wrong trade — but it
   is a product-copy call, so it is logged in `next-versions/xete-mcp.md` for John with the
   constraint that any replacement must keep the remediation intact. The test is scoped to
   rendered docstrings so this is a visible decision rather than a silenced match.

## Reconciliation

- Doubts 1, 2, 3, 4: **fixed.**
- Doubt 5: **risk-accepted in writing and escalated.**
- **0.1.5 is NOT yanked.** It is functional, safe, and installs correctly; yanking would
  break anyone who has already pinned it, to fix copy. 0.1.6 supersedes it, and the registry
  `isLatest` pointer is what agent discovery actually reads.
- **Open, unavoidable:** the 0.1.5 PyPI project page keeps the non-compliant prose forever.
  Nothing can edit it. Its blast radius is one page that `isLatest` no longer points at.

## Verification

- **837 tests pass** from a bare `pytest` (was 828; +9 in `test_copy_compliance.py`).
- The violation was re-verified against the PUBLISHED `server.json` on `main` and against
  PyPI's rendered 0.1.5 description before anything was edited — not from the local tree.
- The concept sweep is proven to fire on all three strings that actually shipped.
- No source-behaviour change: the diff is metadata, prose and two docstrings.
- Invariants: `spendguard.py` byte-identical to `ee81682`; 15 tools at runtime.

## Benchmark doubt prompts with overlapping Paths

- **BM-a-guard-satisfied-by-the-absence-of-what-it-searches-for** — answered, and this is a
  textbook instance in a NON-CODE surface: a matcher whose clean result proved only that it
  was looking for the wrong thing. The floor here is "the matcher still detects what
  shipped" rather than a count of sites.
- **BM-a-red-that-came-from-the-wrong-cause** — answered. The allow-list reachability test
  exists so an exemption cannot pass by matching nothing.

## Verdict: SHIP

A standing product directive was violated in the one file that syndicates to every directory
at once, and it reached the canonical record. The reviewer caught it inside the window —
before `mcpservers.org` and `mcp.so` were submitted by hand, and before Glama re-crawled —
and held the submissions rather than proceeding.

Carry away: **the audit that would have caught this ran, and passed.** It was a phrase list
built from the last violation's wording. Grep the concept the directive is about, never the
words that triggered it — and prove the matcher still fires on what actually shipped, or a
clean result means nothing.
