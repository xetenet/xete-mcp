# DDR: pointing `TREASURY` at the destination the deployed program accepts keeps payments landing, and a client/program disagreement is refused rather than misdirected

Commit scope: `src/xete_mcp/payment.py`, `pyproject.toml`, `server.json`, `gemini-extension.json`,
`test_payment_treasury_pin.py` (new), `test_payment_spend_release_on_rejection.py` (new)

Branch `treasury-rotation-on-public-main`, cut clean off `origin/main` in a separate worktree. This
matters: the repo's local `main` is 74 commits behind `origin/main` and is not a valid release base —
building there would publish a package reverting three releases. Verified with
`git rev-list --left-right --count origin/main...HEAD` before packaging.

## Claim

`TREASURY` must equal the destination the deployed program accepts, or every payment this package
builds is refused. Changing it is necessary and sufficient on the client side, and the failure mode
of a mismatch is a **rejected transaction that moves no lamports** — never a payment to the wrong
place, because the program pins the destination and the client cannot override it.

## Benchmarks

No `benchmarks/` directory existed in this repo, so there were zero `BM-*.md` cases to match against
this diff. Recorded explicitly rather than passed over.

The first one, `BM-chain-enforced-value-held-privately.md`, was authored for this change because it
hardens a real defect class on a protected path — and it is **deliberately not in this commit**.
`benchmarks/` is listed in this repo's `.gitignore`, so benchmarks are local-only by design. That is
the right call and worth stating rather than silently working around: a benchmark's doubt prompts
describe real defects this codebase has shipped, and this repository is public. Future DDRs on these
paths must still answer those prompts; the file lives alongside the working tree, not in the
published history.

## Assumptions (verified / inherited / assumed)

| # | Assumption | Status | Basis |
|---|---|---|---|
| 1 | The program pins the destination and rejects any other account | **VERIFIED** | program source read directly; guard fired on a validator, identified by its own log line and `InvalidArgument` |
| 2 | The new value is the one the deployed program accepts | **VERIFIED** | decoded the program's raw constant to base58 independently rather than trusting adjacent comments; paid it successfully on a validator with the exact expected lamports landing |
| 3 | A client/program mismatch moves no funds | **VERIFIED** | ran the shipped client against a mismatched program on a validator; both candidate destinations measured, delta 0 lamports |
| 4 | The value cannot be read from the program at runtime | **PARTIALLY FALSIFIED, and corrected** | fresh-context review recovered it from ProgramData by ELF parsing. It is not exposed as *structured account data*, which is why the client holds a constant, but "cannot be read" was too strong and the source comment no longer claims it |
| 5 | Nothing else live still holds the previous value | **VERIFIED for shipped surfaces** | swept the package, the server, and the released tree. Two non-shipped local consumers were found (a loose script and a retrieval corpus doc) and are tracked separately; neither is on `origin/main` |
| 6 | The version bump is complete | **VERIFIED, after failing once** | `pyproject.toml` alone was not enough — the repo's own manifest-consistency test caught `server.json` and `gemini-extension.json` still on the old version. All three now agree |
| 7 | The diff cannot leak repo-internal content into a published package | **VERIFIED** | sdist/wheel include lists cover `src/xete_mcp` + README/LICENSE/pyproject only; no `MANIFEST.in` overrides; `reviews/`, `benchmarks/`, `specs/`, `.claude/` all excluded |
| 8 | Nothing else in the diff changes payment semantics | **VERIFIED** | amount, PDA derivation, account ordering and instruction data untouched; confirmed functionally on a validator |

## Doubts raised

**Fresh-context adversarial review was performed** by a separate agent with no prior context, given
only the claim, the diff and the assumption list, instructed to break the claim and to audit across
five distinct lenses (protocol/correctness, security, supply chain, operational rollout, test
quality). It produced concrete attack attempts per assumption and returned **BLOCK**. This is not
`self-review-only`.

Findings that mattered, all raised by the reviewer and none by the author:

- **D1 (BLOCKER) — a rejected payment permanently consumed spend budget.** The spend release covered
  only the pre-submission span, but a preflight rejection happens inside `send_transaction`. Roughly
  25 rejected attempts exhausted the 24-hour window while moving zero lamports, and upgrading the
  client did not restore it. Reviewer demonstrated it by test.
- **D2 (BLOCKER, compounds D1) — the caller was told to do the one thing that could not work.** The
  program explains a mismatch in its own log, but the message truncated it away and advised
  "fix the cause and retry" — an unfixable retry loop that burned budget per attempt.
- **D3 (MAJOR) — nothing tested the constant.** base58 carries no checksum, so a transposed
  character produces a valid-but-wrong key that ships silently and fails closed for every user. The
  program keeps this invariant on its own side; the payment path had no equivalent.
- **D4 (MAJOR) — assumption 4 was overstated** (see table).
- **D5 (MAJOR) — a runbook outside this repo named a superseded upgrade authority.** An inherited
  belief that chain contradicts, sitting on a deploy step.
- **D6 (MAJOR) — the upgrade this pairs with bundles a second, unrelated change**, so a rollback of
  that change also reverts this pairing and breaks clients on the new version.
- **D7 (MINOR)** — the destination is not independently validated anywhere server-side; the program's
  own check is the only control.

## Reconciliation

- **D1 — FIXED.** A preflight rejection now releases the recorded spend. Justification is
  determinism, not trust: the node simulated this exact transaction and it failed, so it cannot move
  lamports whether or not it was also forwarded — a forwarded copy fails on chain for the same
  reason. This is the standard the pre-submission span already used. `already processed` remains
  explicitly excluded, because that refusal is evidence the payment landed and releasing it would
  under-count a real spend. Covered by `test_payment_spend_release_on_rejection.py`, and
  **mutation-verified**: removing the release turns three of its tests red, with the failure output
  reproducing the lockout exactly (25 transactions, full window consumed, zero lamports moved).
- **D2 — FIXED.** The program's own log lines are extracted and surfaced instead of a truncated RPC
  string, and a mismatch of this specific kind now says the package must be upgraded. An unrelated
  rejection keeps the ordinary advice — asserted in both directions so one case cannot be
  mislabelled as the other. The log extractor's pattern is compiled at import on purpose: the first
  version built it inside a function whose `except Exception` swallowed a missing import and returned
  "no logs" forever, which is the inert-guard failure this repo's gates exist to catch.
- **D3 — FIXED.** `test_payment_treasury_pin.py` pins the destination and the program id together
  (a destination is only correct with respect to a program) and refuses a superseded value.
  Mutation-verified: reverting the constant turns it red.
- **D4 — corrected in the source comment**, which no longer overstates the reason.
- **D5 — FIXED** at the source, outside this repo, with the correct value verified on chain by two
  independent methods.
- **D6 — risk-accepted.** The coupling is real and is inherent to how that change ships; the rollback
  artifact for it is staged and verified byte-identical to what is currently deployed.
- **D7 — risk-accepted**, filed as a doubt prompt in the new benchmark rather than fixed here.

Regression check: the full suite is **847 passed, 0 failed** on the final state.

## Verdict: SHIP
