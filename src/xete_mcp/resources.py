"""Read-only MCP resources for xete-mcp.

SPEC-mcp-prompts-resources-20260817. Resources are context data a client can fetch by
URI without calling a tool. Both are read-only: neither function signs, submits, or
spends anything.

The wheel does not ship README.md (see pyproject.toml's [tool.hatch.build.targets.wheel]
package list), so `SAFETY_MODEL_MARKDOWN` below is a maintained COPY of README.md's
"## The safety model — draft, verify, then sign" section, not a runtime read of the file
— reading it from disk would work in a dev checkout and silently return nothing after a
real `uvx xete-mcp` install. Keep the two in sync by hand; test_resources.py only checks
the copy is non-empty and mentions the same tool names, not byte-identity against a file
that may not exist at runtime.
"""
from __future__ import annotations

SAFETY_MODEL_URI = "xete://safety-model"
SPEND_LIMITS_URI = "xete://spend-limits"

SAFETY_MODEL_MARKDOWN = """\
## The safety model — draft, verify, then sign

Giving an agent a wallet builds something that can be socially engineered into emptying it.
Not giving it one means it can't do the thing you wanted. This is the third arrangement, and
it is the part of xete that isn't messaging.

**The agent drafts; it cannot execute.** `xete_draft_settlement_tx` returns a base64
**unsigned** transaction. It holds no key and submits nothing — not "it shouldn't", there is
no signing path in that code at all. A human signs it, in their own wallet.

**A separate tool checks the draft.** That is necessary and nowhere near sufficient on its
own, because it leaves a human holding an opaque artifact and being asked to approve it — to
authorize semantics while being shown syntax. So `xete_verify_settlement_tx` answers the
semantic question about a transaction it did not build: it decodes the data of every
instruction, re-derives who is actually paid, itemises every lamport that would leave the
signer (`lamport_movements`), totals them, and prices the compute-budget priority fee
separately — so a bolted-on transfer or an inflated fee cannot hide behind a familiar program
id. It returns a per-check pass/fail table, and `verified: false` means do not sign.

**The verifier is deliberately not the drafter.** `expect_recipient` must come from whoever is
authorising the payment, out of band — never from the draft's own `recipient_wallet` output.
Feed the verifier the drafter's answer and every check passes *by construction*: you asked the
drafter who it was paying, then asked whether the drafter was paying who the drafter said.
That is a tautology wearing the costume of a check.

**Two endpoints, or no name.** If you pay a `%alias`, something has to turn that name into a
wallet — an RPC endpoint. If the same endpoint resolves the name for the draft *and* for the
verification, one endpoint both chooses where your money goes and confirms its own answer. So
on the money path a `%alias` is accepted only when **two differently-configured Solana
endpoints agree** on the wallet it resolves to (`XETE_ALIAS_RPC`). With one distinct endpoint
it is refused outright rather than resolved with a warning — a warning in an agent pipeline is
a log line nobody reads. **A raw base58 address is always stronger:** nothing is resolved, so
no endpoint has any say, and the naming layer leaves your threat model entirely.

**Your counterparty is committed, not broadcast.** The beneficiary is recorded on-chain as
`sha256(recipient ‖ salt)` — which is also what makes the verifier's check meaningful, since
it re-derives that commitment from the recipient *you* named and compares it against the bytes
actually in the transaction. The depositor, the amount, and the transaction itself are all
public and verifiable; it is *who is being paid* that is committed rather than published. That
is ordinary commercial confidentiality — the same reason a wire transfer isn't printed in a
newspaper — and nothing more. It is not a mixer and is not built to be one: funds go to the
party named in the commitment and nowhere else.

### What this does not solve

Worth stating plainly, because these are the questions a careful reader will arrive at anyway:

- **A human still has to read the verifier's output.** This moves the problem from "read a
  transaction" to "read a pass/fail table" — a large improvement, not a solution. A
  sufficiently boring table gets rubber-stamped like everything else.
- **Nothing here stops a *legitimate* payment to the wrong person.** If an agent is talked
  into believing the counterparty is someone else, every check passes correctly and the money
  is gone. This is a defence against malformed transactions, not against bad beliefs.
- **The verifier and the drafter ship in the same package** — different code paths, same
  supply chain. A compromised release compromises both. Genuine independence means a verifier
  someone else wrote.
- **The on-chain programs are not in the osec verified-builds registry.** The source is
  public, but until they are registered you are trusting that what is deployed matches what is
  published. Don't take that on faith today.
- **`expect_recipient` is a documentation guarantee, not a structural one.** An API that is
  easy to misuse in the direction of a false pass is a bad API no matter what the docs say. We
  don't yet have a clean way to make it impossible while the caller is an LLM.
"""


def safety_model() -> str:
    """Static resource: the draft-verify-sign safety model, verbatim from README.md."""
    return SAFETY_MODEL_MARKDOWN


def spend_limits() -> str:
    """Dynamic resource: this instance's live client-side spend-guard configuration.

    Reuses server.py's existing redaction (never exposes the ledger's absolute path)
    and spendguard.status() — same data xete_my_identity already reports, exposed here
    as a resource an agent can fetch without a tool call. Imported lazily, after
    server.py has finished loading, the same way xete_my_identity already imports
    spendguard — this module has no top-level dependency on server.py.
    """
    import json

    from . import server as _server
    from .spendguard import status as _spend_status

    try:
        limits = _server._redact_ledger_path(_spend_status())
    except Exception as e:
        limits = {"enforced": True, "error": _server._scrub_paths(str(e))[:200]}
    return json.dumps(limits, indent=2)
