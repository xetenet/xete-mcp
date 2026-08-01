# DDR: "two independently-operated endpoints" is decided by the identity of the SERVER, not by the string an operator typed — and the rule now binds every tool that chooses where money goes, not only the tool that advises about it

Commit scope:
- `src/xete_mcp/safehttp.py` — `endpoint_identity()` / `distinct_endpoints()`, the normalising
  key the whole corroboration story now rests on (G10, G16)
- `src/xete_mcp/settlement.py` — `second_rpc_url()` keyed on that identity; `status()` enforces it
  even for an explicitly-passed `second_rpc=` (G10, G16, reviewer §4)
- `src/xete_mcp/server.py` — `alias_rpc_endpoints()` collapses by server;
  `_resolve_recipient_corroborated()` replaces `_resolve_for_verification()` and is now the single
  door to a `%name` on the spending path too; `WARNING_CORROBORATION_REQUESTED_BUT_NOT_OBTAINED`
  and `WARNING_RECIPIENT_WAS_NOT_INDEPENDENTLY_RESOLVED` in `xete_settle_status`;
  `WARNING_ONE_ENDPOINT_CHOSE_THIS_WALLET` in `_alias_view` (G17, G11, G18, reviewer §1)
- `test_settlement_robustness.py`, `test_alias_read.py` — 39 new tests; five pre-existing tests
  changed (four fixture-only, one strengthened — see C5)
- `benchmarks/BM-a-control-that-identifies-a-source-by-the-string-you-typed.md`

Input: `~/GATE-FINDINGS.md` findings **G10** (medium), **G16** (high), **G17** (medium),
**G11** (medium), **G18** (medium). G10 and G16 are the same defect found independently by two
reviewers under two different lenses, with the same control. G17/G11 and G18 are the same control
examined from two other sides.

`src/xete_mcp/spendguard.py` was OFF LIMITS and is byte-for-byte unchanged —
`git diff ee81682 -- src/xete_mcp/spendguard.py` is empty, re-verified after the last edit.
No Solana transaction was built against a real cluster and none was submitted; every RPC in every
test is a fake. Nothing was pushed; no remote touched.

This closes the DDR-settlement-submit-receipt assumption **A4** ("two endpoints that must agree is
worth more than one — i.e. `second_rpc_url` really returns a different operator"), which that DDR
recorded as **BROKEN, and NOT fixed here**, and its doubt **D7**.

---

## Claim

1. **(G10/G16)** No two URLs that reach the same server can occupy both slots of a two-of-two
   corroboration rule, at either site. Endpoints are keyed on
   `(scheme, hostname, port-or-default)` from `urlsplit`, lower-cased, with the FQDN root dot
   stripped, IP literals and IDNA hostnames normalised, and the whole loopback family folded to a
   single identity. Path, query, fragment and userinfo are discarded: an API key buys a second
   credential, never a second opinion.
2. **(G10/G16, second half)** When the list collapses to one distinct host, the code takes the
   EXISTING refusal path rather than certifying — `_resolve_recipient_corroborated` raises, and
   `settlement.status` drops to the one-source caveat and never prints "no single endpoint chose
   this answer".
3. **(G17)** Every tool that chooses a destination for money — `xete_settle_create`,
   `xete_draft_settlement_tx`, and the verifier — resolves a `%name` through two
   independently-operated endpoints that must agree, or refuses. The tool that only advises is no
   longer better defended than the tools that move money.
4. **(G11)** `xete_settle_status` applies the same rule to `expect_recipient`, but DEGRADES
   instead of refusing: `beneficiary_verified` goes null with
   `WARNING_RECIPIENT_WAS_NOT_INDEPENDENTLY_RESOLVED` while `open`/`determinate` still answer.
   No failure of the recipient check can destroy the escrow answer.
5. **(G18)** A configured corroborator that does not answer produces
   `WARNING_CORROBORATION_REQUESTED_BUT_NOT_OBTAINED` next to the booleans an agent branches on.
   The availability tradeoff behind it — a corroborator that is down costs confidence, not the
   answer, tested at `test_settlement_robustness.py:1465` — is deliberately kept.
6. **No existing assertion was weakened.** Five pre-existing tests changed: four fixture-only
   (`drafting` → `two_endpoints`, assertions byte-identical), one strengthened.

---

## Assumptions (verified / inherited / accepted)

| # | Assumption | Status |
|---|---|---|
| A1 | `(scheme, host, port)` is the right granularity — two URLs sharing a host share an operator, and two hosts do not | **verified for the shapes that matter, with one deliberate over-collapse.** Provider spellings (slash, doubled slash, path, `?api-key=`, case, `:443`, `:0443`, userinfo, fragment, whitespace, root dot) all collapse; subdomain, port and scheme differences all stay distinct. Over-collapse: `straße`/`strasse` — see D6 |
| A2 | `redact_url` is not usable as this key | **verified** — it keeps `?<redacted>`, does not lower-case the host, and leaves an explicit `:443` in place. The G16 reviewer said so and I re-checked it |
| A3 | A default install still has ≥ 2 distinct endpoints, so this does not brick `%name` spending | **verified, measured** — `['https://solana-rpc.publicnode.com', 'https://api.mainnet-beta.solana.com']`, n=2. One config collapses to n=1 — see D5 |
| A4 | `alias_rpc_endpoints()[:2]` after identity dedupe really is two different servers | **verified** — that is exactly what the key buys, and `len(endpoints) < 2` is now a true "one distinct host" test rather than "one string" |
| A5 | `CorroborationUnavailable` subclassing `RuntimeError` keeps every existing `except Exception` handler working | **verified** — the fresh-context pass ran 194 tests plus 12 probes with no uncaught traceback |
| A6 | `endpoint_identity` never raises — it runs inside refusal paths and before every money-path resolution | **verified** — the fresh-context pass threw 17 hostile inputs at it (`None`, `0`, `3.5`, `bytes`, bare `object()`, `:99999`, `[::1` unclosed, `:-1`, `:+443`, a 300-char label, a 20-digit port, a leading NUL, a ZWJ in the host); zero raised. Pinned by `test_the_identity_key_never_raises` |
| A7 | Discarding the path is safe — no provider distinguishes two independent operators by path on one host | **accepted** — QuickNode/Alchemy/Ankr put a per-customer TOKEN in the path, which is a credential for one operator's infrastructure. Two tokens on one host is the `?api-key=` case wearing a different hat |
| A8 | The IDNA fold matches what `requests` puts on the wire | **BROKEN, accepted** — built-in codec is IDNA2003, `requests` uses IDNA2008/UTS-46. See D6 |
| A9 | `_alias_view`'s `verified: true` means corroborated | **BROKEN — it never did, and that was the hole.** It means "chain rather than permit server". See D1 |

---

## Doubts raised

**D0 (self, before writing code).** *Routing the spending tools through the verifier's rule breaks
five existing tests. Is updating them "weakening an assertion"?* — see Reconciliation C5.

**D1–D7 (fresh-context Claude, headless `claude -p`, separate process, no conversation history).**
Given the `src/` diff, the six claims above and the benchmark doubt prompts, instructed to break
them with scripts it actually runs. It built four trees (`at-head`, `at-diff`, `at-worktree`,
`reverted`), ran five attack files and an AST-level assertion diff, and returned **seven confirmed
findings**, three of which were already closed on disk by the time it finished. Recorded as genuine
fresh context, not self-review. `~/wt-int` verified untouched by it.

**D1 (fresh context) — C3 BROKEN as a security property.** *"The corroboration requirement is one
tool call away from being optional, and the refusal text is the thing that routes the agent around
it." `xete_resolve('%bob')` → `_alias_view` → `alias_chain.resolve_owner(bare)` with no `rpc`
argument → ONE endpoint, chosen by a precedence chain that never reads `XETE_ALIAS_RPC`, returned
stamped `verified: true`. Demonstrated: `settle_create('%bob')` refuses with "PASS THE RECIPIENT'S
BASE58 WALLET ADDRESS"; `xete_resolve('%bob')` returns the attacker's wallet from the single
hostile endpoint; `settle_create(<that wallet>)` deposits to the attacker — and
`_resolve_recipient_corroborated` short-circuits it with "nothing was resolved, so no endpoint had
any say in it", which is false in that flow.* This is BM-a-verdict-cheaper-than-the-one-you-hardened
exactly.

**D2 (fresh context) — C4's availability half BROKEN in the reviewed diff.** *`xete_settle_status`
caught only `CorroborationUnavailable`. Of five ways recipient resolution can fail, four
(unregistered name, alias RPC down, confusable name, syntactically bad name) destroyed
`open`/`determinate` — the field create/claim/reclaim all tell the agent to "read FIRST". And the
change DOUBLES the alias RPCs consulted, so the outage row is now twice as reachable.* Fair-minded
note from the reviewer: not a regression from HEAD, which raised the same four into the same
handler — "the diff does not make these cases worse; it claims to fix them and does not."

**D3 (fresh context) — C1 BROKEN, loopback family.** *`localhost` / `127.0.0.1` / `[::1]` /
`127.0.0.2`, and http vs https on any of them, produced up to three distinct keys for one box.
`require_secure_url` accepts all of them, and `getaddrinfo('localhost')` → `['127.0.0.1', '::1']`.
End to end: `primary=http://localhost:8899`, `XETE_RPC_URL_2=http://127.0.0.1:8899` →
`corroborated=True` and the uncaveated "Two independently-configured endpoints … so no single
endpoint chose this answer". Also: the docstring justified keeping `scheme` on the grounds that
"a plain-http corroborator is refused elsewhere on its own merits" — false for loopback, which
`require_secure_url` admits by design, i.e. the stated justification has a hole exactly where the
split is reachable.* Plus, from the same pass against the earlier cut: trailing root dot, expanded
vs compressed IPv6, and unicode vs punycode.

**D4 (fresh context) — the identity check is bypassable by an explicit `second_rpc=`.**
*`settlement.status`'s `second = second_rpc_url(rpc_url) if second_rpc is None else (...)` skips
the hardened comparison whenever the caller passes the kwarg. No in-tree caller does, so latent —
but it reproduces the exact G10/G16 output shape through the parameter.*

**D5 (fresh context) — one plausible configuration loses `%name` spending entirely.** *An operator
who sets `XETE_RPC_URL` to a host this package already uses as a default collapses the list to
n=1 and every settlement tool refuses a `%name`. The same URL in `XETE_SOLANA_RPC` yields n=2,
because `RPC_URL` mirrors `XETE_RPC_URL` and gets deduped away. The cliff is asymmetric and
undocumented.* Secondary: in a default install both endpoints are public RPCs the operator did not
choose, and both must answer — a rate-limit on either now fails a spend that one endpoint would
have completed.

**D6 (fresh context) — C2 counterexample against the on-disk IDNA fold.** *`host.encode("idna")`
is IDNA2003 + nameprep; `requests`/`urllib3` reach the wire through the `idna` package
(IDNA2008/UTS-46). They disagree: `straße.example` and `strasse.example` fold to one key here and
are two different DNS names there.* Over-refusal check that PASSED alongside it: every realistic
provider hostname, an underscore host, a 64-char label, an empty label, a leading hyphen and a
malformed `xn--` label all pass through unchanged.

**D7 (fresh context) — the test file's blanket claim is false.** *"Every test here was run against
the code with the fix reverted and FAILS there" — measured: 25 of 30 fail reverted; five pass. All
five are labelled over-refusal guards or "the reviewers' CONTROL", so the substance is fine, but
the sentence is not true in a file whose style is precise claims.* The same pass confirmed **all 18
parametrised instances are load-bearing** — no decorative parametrisation.

**D8 (self, during the fix).** *`_CORROBORATION_PURPOSE[purpose]` raises `KeyError` on a typo'd
purpose. Should it `.get()` a default?*

---

## Reconciliation

**D1 — PARTIALLY FIXED, remainder risk-accepted, and it is the most important item here.**
Two changes. (a) `_alias_view` now attaches `WARNING_ONE_ENDPOINT_CHOSE_THIS_WALLET` to any
claimed alias, in a key that cannot be read as a badge, saying in terms that this wallet came from
a single endpoint, that `verified` here means only "chain rather than permit server", and naming
the three tools it must not be pasted into. (b) The spend/verify refusal no longer routes the agent
there: it now reads "PASS THE RECIPIENT'S BASE58 WALLET ADDRESS — from whoever is authorising this
payment, NOT from xete_resolve or xete_alias_resolve, which ask one endpoint and would launder this
refusal rather than satisfy it". The disagreement refusal gained "OUT OF BAND — from the person
being paid, not from another tool on this server".

What is NOT fixed, deliberately: `xete_resolve` still answers from one endpoint and still says
`verified: true`. Refusing there would break a read tool with legitimate non-money uses (addressing,
display, messaging), and `verified` has an established, correct meaning on that path — chain vs
permit server — that four alias-read tests pin. Changing it belongs to the alias-read lens with its
own DDR. **Risk accepted:** an agent that ignores a `WARNING_` key and pastes a one-endpoint answer
into a spend still gets a one-endpoint destination. The control is now loud rather than silent, and
the refusal no longer points at the hole. Tests:
`test_alias_read.py::test_xete_resolve_says_one_endpoint_chose_the_wallet`,
`::test_an_unclaimed_name_carries_no_one_endpoint_warning` (over-refusal guard),
`test_settlement_robustness.py::test_the_refusal_does_not_route_the_agent_into_a_one_endpoint_oracle`.

**D2 — FIXED, before the reviewer reported it** (I found the same hole reasoning through
BM-unprovable-state-treated-as-proven; the reviewer confirmed the fix against the worktree, all
five failure classes now degrade). `xete_settle_status` catches `Exception`, not just
`CorroborationUnavailable`, around recipient resolution only. Resolving the recipient is an EXTRA
check bolted onto a question about an escrow account; it must not be able to answer that question
with an error. Nothing positive is concluded from that branch — `beneficiary_verified` stays null
and `WARNING_RECIPIENT_WAS_NOT_INDEPENDENTLY_RESOLVED` says why, including the reason string. Test:
`::test_a_flaky_alias_endpoint_cannot_destroy_the_determinate_answer`. This is the reason the fix
for G11 does not become a re-run of G19.

**D3 — FIXED.** Trailing root dot, IP-literal spellings and IDNA folded (before the report, from my
own attack table); the loopback family folded after it. Any loopback host — `localhost`,
`localhost.localdomain`, `ip6-localhost`, `ip6-loopback`, or anything `ipaddress` calls
`is_loopback` — keys to a single `("loopback", "loopback", None)` regardless of scheme or port.
Two local validators on two ports ARE one source: same machine, same operator, same adversary, so
the collapse is the truthful answer and not merely the safe one. The docstring's scheme
justification is corrected in place to say exactly this. Tests:
`::test_every_loopback_spelling_is_one_source` (6 pairs),
`::test_a_loopback_pair_cannot_corroborate_a_settlement` (end to end),
`::test_one_server_has_one_identity` (15 pairs), `::test_two_servers_keep_two_identities`.

**D4 — FIXED.** `settlement.status` re-applies `endpoint_identity` to `second` however it was
obtained. "A guarantee that depends on which door the caller came through is not a guarantee."
Test: `::test_an_explicit_second_rpc_cannot_skip_the_identity_check`.

**D5 — DOCUMENTED, risk accepted.** Measured and confirmed: a default install has n=2 and spends
fine; the cliff is real for one configuration. The env block in `server.py` now states that a
default install already has two, names the exact configuration that collapses to one, and says the
same URL in `XETE_SOLANA_RPC` does not. The refusal itself names the single endpoint and what to
do. Accepted rather than engineered around, because the alternative — silently topping the list up
to two — is how you get a "second endpoint" nobody chose. The secondary cost (both public endpoints
must answer) is the intended bargain for money, and it now carries its own message pointing at the
base58 escape hatch: `::test_an_unreadable_second_endpoint_refuses_a_spend_with_a_way_out`.

**D6 — RISK ACCEPTED, documented in the docstring.** The IDNA revision mismatch collapses two names
into one identity, which costs a corroborator (refuse, or drop to the one-source caveat) and can
never manufacture agreement. Fail-closed, on an input no Solana RPC provider uses. Removing the
fold would re-open unicode/punycode in the unsafe direction, so the fold stays. The docstring now
names the revision difference rather than saying "best effort" and leaving it.

**D7 — FIXED.** The header now reads "Every test here ASSERTING THE NEW BEHAVIOUR … 25 of 30 in the
first batch. The other five are the over-refusal guards and the reviewers' control, which are
supposed to pass both ways." A guard that only passes after the fix is not a guard.

**D8 — RISK ACCEPTED.** Left as `KeyError`. A typo'd purpose is a programming error: loud in the
test suite, and at runtime it is swallowed into a generic `{"status": "failed"}` — i.e. the tool
refuses. Defaulting silently would give the caller the wrong remediation prose on a money refusal,
which is worse than a confusing message on a code path that cannot exist without a source edit.

**C5 (the pre-existing tests) — no assertion weakened. Verified mechanically by the fresh-context
pass, AST-diffing every `assert` in every pre-existing test at HEAD vs the change:** 0 tests
deleted, 0 assertions removed, 4 fixture-only changes with byte-identical assertions
(`test_a_lying_permit_server_can_no_longer_choose_who_gets_paid`,
`test_the_draft_does_not_prefill_the_verifier_with_its_own_answer`,
`test_an_unregistered_name_is_refused_not_guessed`, `test_a_plain_ascii_name_is_unaffected` — each
moved `drafting` → `two_endpoints` because the property they test is unrelated to the endpoint
count, and each would otherwise pass for the new reason instead of its own), and 1 strengthened:
`test_a_single_endpoint_cannot_both_build_and_certify_a_payment` replaces
`assert d['status'] == 'drafted'` / `assert d['recipient_wallet'] == str(ATTACKER)` with
`assert d['status'] == 'failed'` / `assert str(ATTACKER) not in json.dumps(d)`. The hostile endpoint
no longer gets to choose a destination at all. Its verifier half is preserved against an
attacker-built transaction — which is the honest model anyway, since an attacker who controls the
endpoint does not need this server's drafting tool. The reviewer independently checked that
substitution for a hidden weakening (`_deposit_ix` defaults to `salt=SALT`, matching the
`SALT.hex()` passed to verify) and found none.

**Benchmark doubt prompts answered.** *BM-a-verdict-cheaper-than-the-one-you-hardened* — this is
D1, and it is the finding of the review; every route by which a `%name` becomes a transaction
destination was enumerated (`settlement.deposit`, `draft.draft_deposit`; `pay_herd` pays an
on-chain-derived treasury, `send_multi` takes a handle) and the cheap route was the ADVISORY
resolver, not another spending tool. *BM-unprovable-state-treated-as-proven* — this is D2; the
three answers are agree / contradict / could-not-ask, and "could not tell" now degrades on the
read-only tool and refuses on the spending tools, with no latching anywhere (every call
re-resolves). *BM-a-live-transaction-reported-as-a-clean-failure*, point 5 ("a recovery instruction
naming a field some response shape omits") — checked: every `xete_settle_status` shape still
carries real `open`/`determinate`, and D2's fix is what keeps that true. *BM-derived-key* and
*BM-failed-attempt* — paths (`client.py`, `payment.py`, `spendguard.py`) not touched.

**Third-site sweep.** The fresh-context pass swept all of `src/` for endpoint-URL comparison and
found exactly two sites, both in this change. `_resolve_recipient_wallet`'s
`rpc or alias_rpc_endpoints()[0]` default survives but is no longer reachable from any production
caller that chooses a destination — every one now goes through `_resolve_recipient_corroborated`,
whose only uses of it are the raw-wallet short-circuit (no chain read at all) and the explicit
per-endpoint calls.

---

## Residual risks

1. **`xete_resolve` still answers from one endpoint with `verified: true`** (D1). Warned, not
   refused. Belongs to the alias-read lens.
2. **Both configured endpoints must answer for a `%name` spend** (D5). Intended for money;
   availability cost is real and the refusal names the escape hatch.
3. **IDNA2003 vs IDNA2008** (D6). Fail-closed, unreachable for real providers.
4. **`XETE_RPC_URL` = a packaged default collapses the list to one** (D5). Documented; refusal is
   explicit and actionable.
5. Not attacked here: whether two PUBLIC endpoints are meaningfully independent of each other.
   They are two operators, which is the property claimed; whether they read the same upstream is
   outside what this code can know.

---

## Verdict: SHIP

Five findings closed. The defect two reviewers found independently — a redundancy control that
identified a source by the string a human typed — is closed at both sites with one shared key, and
the fresh-context pass found three more spellings of it inside the fix, which are also closed. The
rule now binds where the destination is chosen rather than only where it is reported, the read-only
tool degrades instead of losing the answer agents are sent there for, and the silent downgrade is
as loud as every other weak condition. The one thing that survives — a one-endpoint answer
launderable through an advisory read tool — is warned about in the answer and no longer pointed at
by the refusal, and closing it properly means changing a read tool's contract under its own lens.

Suite: **603 passed**, 0 failed. Every test asserting new behaviour verified red against HEAD
(`550a3cf`) with the tests kept and the source reverted; the over-refusal guards and the control
pass both ways by design. `spendguard.py` zero-diff against `ee81682`.
