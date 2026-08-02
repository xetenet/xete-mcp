"""No published surface may assert that SENDING A MESSAGE costs, could cost, or is free-for-now.

THIS IS A STANDING PRODUCT DIRECTIVE, not a style preference, and it shipped broken in
0.1.5 to the one file that syndicates to every directory at once.

What went out in `server.json` 0.1.5, and therefore into the canonical registry record:

    XETE_RPC_URL     "...used only if the server requires on-chain payment to send."
    XETE_SOL_KEYPAIR "Used only to pay when the xete server you connect to charges to
                      send; messaging on xete.net is free..."

WHY THE AUDIT THAT RAN BEFORE PUBLISH RETURNED CLEAN. It grepped for the PHRASES that had
triggered the directive: `free alpha|free during|currently free|will start charging`.
Neither offending string contains any of those tokens. A phrase list matches the wording of
the last violation, never the concept, so it goes stale the moment someone paraphrases --
and a clean result from it is indistinguishable from compliance.

Note the second-order failure, which is the one worth remembering: an earlier pass HAD
flagged this exact pair and "fixed" it by RELOCATING the charge to a hypothetical other
server. "Messaging on xete.net is free" implies by contrast that it is not free somewhere,
which is the same future-price hint in a politer coat. Rewording a violation is not
removing it.

So this test sweeps the CONCEPT: any sentence that mentions cost AND mentions sending or
messaging. That over-matches by design -- the allow-list below is explicit, short, and each
entry states why it is true.

Deliberately NOT a violation, and it must not be "fixed":

  * `XETE_SPEND_FLOOR_LAMPORTS` describes a minimum charged against the spend budget for
    any ON-CHAIN ACTION, covering account rent and network fees. It never asserts that
    messaging has a price, and claiming a `%name` genuinely does cost lamports.
  * `xete_settle_create`'s description says a settlement pays a recipient. That is
    agent-to-agent value transfer, and the text says "not a message fee" in as many words.

`mainnet-beta` is Solana's own name for the cluster and is never rewritten.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent

COST = re.compile(r"\b(charg\w*|pay|paying|payment|price[sd]?|pricing|cost\w*|fee|free)\b", re.I)
SEND = re.compile(r"\b(send|sending|sends|message|messages|messaging|relay)\b", re.I)

# Each entry is a substring of an ALLOWED sentence, with the reason it is true. Keeping the
# allow-list explicit rather than loosening the regex means adding an exception is a visible,
# reviewable edit instead of a quiet widening that nobody sees again.
ALLOWED = [
    # on-chain actions generally, not messaging; claiming a name really does cost lamports
    "Minimum charged against the spend budget for any on-chain action",
    "Minimum charged against the budget for any on-chain action",
    # settlement is agent-to-agent value transfer, and says so
    "not a message fee",
    # the spend-cap copy is about what the gate protects, not about a price to send
    "Most a single transaction may cost",
    "Most that may be spent inside the rolling window",
    "the most a single transaction may cost",
    "the most that may be spent in total",
    # idiom, not a price: "free to render whatever the registry holds"
    "free to render",
]

SURFACES = ["server.json", "README.md", "gemini-extension.json", "glama.json",
            "pyproject.toml"]


def _sentences(text: str):
    for chunk in re.split(r"(?<=[.;])\s+|\n", text):
        s = " ".join(chunk.split())
        if s:
            yield s


def _violations(text: str) -> list[str]:
    out = []
    for s in _sentences(text):
        if not (COST.search(s) and SEND.search(s)):
            continue
        if any(a in s for a in ALLOWED):
            continue
        out.append(s[:200])
    return out


@pytest.mark.parametrize("name", SURFACES)
def test_no_published_surface_prices_messaging(name):
    path = REPO / name
    if not path.exists():
        pytest.skip(f"{name} not present in this tree")
    bad = _violations(path.read_text(encoding="utf-8"))
    assert not bad, (
        f"{name} asserts a cost in the same breath as sending/messaging:\n  "
        + "\n  ".join(bad)
        + "\n\nDescribe what the variable IS, without asserting a price. Relocating the "
          "charge to 'some other server' does NOT satisfy this — that was tried, and "
          "'messaging here is free' implies by contrast that it is not free elsewhere.")


def test_the_sweep_is_not_vacuous():
    """THE FLOOR. A concept sweep that matches nothing passes every file trivially.

    The predecessor to this test was a phrase grep that returned clean over two live
    violations; the failure was invisible because a clean result and a broken matcher look
    identical. This proves the matcher still fires on the exact strings that shipped.
    """
    shipped = [
        "Solana RPC URL, used only if the server requires on-chain payment to send.",
        "Used only to pay when the xete server you connect to charges to send; "
        "messaging on xete.net is free, and identity and inbox never need it.",
        "it is used only if the xete server you connect to charges on-chain to send.",
    ]
    for s in shipped:
        assert _violations(s), f"the sweep no longer detects a string that actually shipped: {s!r}"


def test_the_allow_list_entries_are_all_still_reachable():
    """An allow-list entry that matches nothing is dead weight that hides the next one.

    If a description is reworded, its exemption should be re-justified rather than left
    sitting there silently permitting a string nobody has read in months.
    """
    corpus = "\n".join((REPO / n).read_text(encoding="utf-8")
                       for n in SURFACES if (REPO / n).exists())
    # Tool docstrings are swept by their own test, so their exemptions live here too.
    corpus += (REPO / "src" / "xete_mcp" / "server.py").read_text(encoding="utf-8")
    dead = [a for a in ALLOWED if a not in corpus]
    assert not dead, (
        "these allow-list exemptions match nothing in the published surfaces and should be "
        f"removed rather than left as standing permissions: {dead}")


# spendguard.py is FROZEN -- it must stay byte-identical to ee81682, because it is the
# money gate and any edit to it requires deliberate re-verification. Its module docstring
# says "The amount charged for a message is quoted by the server being paid", which the
# sweep below flags correctly. TWO STANDING RULES COLLIDE HERE and it is not this test's
# place to pick one, so the file is excluded and the conflict is escalated in
# next-versions/xete-mcp.md rather than silently resolved in either direction.
FROZEN = {"spendguard.py"}


def test_every_docstring_in_the_package_not_only_the_tool_ones():
    """THE THIRD ROUND OF THE SAME VIOLATION, and the reason the mechanism changed.

    Round 1 fixed the source files (server.json, README). Round 2 fixed the built .mcpb
    and the TOOL docstrings. The MODULE docstrings survived both passes -- including
    payment.py's, which said outright "Sending a message costs SOL (anti-spam)", the most
    direct statement of the thing the directive forbids, sitting in the shipped wheel.

    Each round widened an ENUMERATED LIST of places to look, and each round the list was
    incomplete in a way nobody could see from inside it. "Complete surface list" is not a
    list anyone has ever finished writing. So the mechanism is now an AST walk over every
    docstring in every module -- module, class and function -- which requires no list at
    all and cannot go stale when a file is added.

    Module docstrings do not reach an MCP tool picker, so this is not what a client
    renders. It IS in the published artifact, which doc-ingesting directories read.
    """
    import ast

    src = REPO / "src" / "xete_mcp"
    offenders = {}
    for f in sorted(src.glob("*.py")):
        if f.name in FROZEN:
            continue
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for node in [tree] + [n for n in ast.walk(tree) if isinstance(
                n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]:
            bad = _violations(ast.get_docstring(node) or "")
            if bad:
                where = "MODULE" if node is tree else node.name
                offenders[f"{f.name}::{where}"] = bad
    assert not offenders, (
        "docstrings in the published package assert a price for messaging:\n  "
        + "\n  ".join(f"{k}: {v}" for k, v in offenders.items()))


def test_the_tool_descriptions_an_mcp_client_renders():
    """The TOOL DOCSTRINGS are a published surface: a client renders them in its tool
    picker, and the .mcpb manifest is generated from them at build time. That is how the
    built .mcpb inherited both offending strings without any check noticing.

    Scoped to the docstrings via AST, NOT to the whole module. Sweeping the file text also
    catches internal comments and RUNTIME diagnostics -- notably the message shown when a
    relay actually answers with an invoice, which is a functional error an operator needs
    in order to understand why a send failed, not a claim about what xete charges. Blunting
    that to satisfy a copy rule would trade a real diagnostic for a cosmetic pass. It is
    left alone deliberately; see next-versions if the directive is ever meant to cover it.
    """
    import ast

    tree = ast.parse((REPO / "src" / "xete_mcp" / "server.py").read_text(encoding="utf-8"))
    offenders = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(getattr(d, "attr", getattr(d, "id", None)) == "tool"
                   or getattr(getattr(d, "func", None), "attr", None) == "tool"
                   for d in node.decorator_list):
            continue
        bad = _violations(ast.get_docstring(node) or "")
        if bad:
            offenders[node.name] = bad
    assert not offenders, f"tool descriptions assert a price for messaging: {offenders}"


def test_server_json_env_descriptions_specifically():
    """The one file that syndicates to EVERY directory at once, checked field by field.

    The whole-file sweep above would catch these too; this exists so a failure names the
    variable, because that is what someone fixing it needs.
    """
    data = json.loads((REPO / "server.json").read_text(encoding="utf-8"))
    for pkg in data.get("packages", []):
        for env in pkg.get("environmentVariables", []):
            bad = _violations(env.get("description", ""))
            assert not bad, f"{env.get('name')}: {bad}"
