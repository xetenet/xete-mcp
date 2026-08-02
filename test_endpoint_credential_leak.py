"""A paid RPC credential must not reach the agent's context, on ANY branch.

WHY THIS FILE EXISTS AND WHY IT IS NOT THE TEST IT REPLACES.

`test_primitives_hardening.py` had a guard for this. It searched settlement.py for
`{rpc_url}`, `{second}` and `{url}` and required `redact_url` on the same line. At the
commit it was written it matched six sites. The fix then wrapped those six --
`{redact_url(rpc_url)}` -- WHICH DELETED THE LITERAL TOKENS THE REGEX KEYS ON. From that
commit onward it matched zero sites and passed green over every leak that remained: the
`.format(endpoint=...)` templates, `{rpc_url or '(unnamed)'}`, raw URLs used as dict KEYS,
and the entirety of server.py, which it never opened.

A guard that is SATISFIED BY THE REMOVAL OF THE STRINGS IT SEARCHES FOR is not a guard.
It is worse than no guard, because it retires the finding: the leak is now believed fixed.
That is what happened here, and it was caught by an independent reviewer executing the code
rather than reading it.

So this file replaces it with two checks that fail in the opposite direction:

  1. BEHAVIOURAL (the primary). Feed the real code a canary credential in the two shapes
     that paid providers actually use -- Helius `?api-key=`, QuickNode `/qn-TOKEN/` -- and
     assert the canary appears nowhere in what the tool returns. This cannot be satisfied by
     renaming anything, because it never reads the source.

  2. STRUCTURAL, WITH A FLOOR. An AST sweep that keys on the SHAPE of an emission (f-string,
     .format(), dict key) rather than on any spelling, and that ASSERTS IT FOUND SITES. A
     sweep that examines zero sites now fails. That single assertion is the difference
     between this and the guard it replaces.

Both matter. The behavioural test only covers branches someone thought to construct; the
leak that started all of this was on the SUCCESS path, which no one had constructed.
"""
import ast
import json
import re
from pathlib import Path

import pytest
from solders.pubkey import Pubkey as _P

REPO = Path(__file__).resolve().parent
SRC = REPO / "src" / "xete_mcp"

# The two shapes that are not userinfo and therefore pass `require_secure_url` by design:
# Helius puts its credential in the query, QuickNode in the path. Both are what an operator
# actually pastes into XETE_SOLANA_RPC.
CANARY = "CANARYCREDENTIAL777"
HELIUS = f"https://mainnet.helius-rpc.com/?api-key={CANARY}"
QUICKNODE = f"https://frosty-wild.solana-mainnet.quiknode.pro/{CANARY}/"
ENDPOINTS = pytest.mark.parametrize("endpoint", [HELIUS, QUICKNODE], ids=["helius", "quiknode"])


def _assert_clean(blob, where: str, endpoint: str):
    """The canary must be absent, and the HOST must survive.

    Over-redaction is its own defect: "which endpoint answered" is the entire diagnostic
    these fields owe an operator, and a message naming no endpoint sends them to the wrong
    box. So this asserts both directions rather than only the safe one.
    """
    text = blob if isinstance(blob, str) else json.dumps(blob, default=str)
    assert CANARY not in text, (
        f"{where}: the RPC credential reached the caller.\n"
        f"  endpoint: {endpoint}\n  emitted:  {text[:600]}")
    host = endpoint.split("//", 1)[1].split("/", 1)[0]
    if host in text or "<redacted" in text or "endpoint" in text.lower():
        return
    pytest.fail(f"{where}: neither the host nor a redaction marker survived -> {text[:400]}")


# ── 1. behavioural ─────────────────────────────────────────────────────────────────────


@ENDPOINTS
def test_settle_status_never_returns_the_credential_on_the_single_provider_default(
        endpoint, monkeypatch):
    """THE DEFAULT INSTALL, on the ordinary success path, with no attacker and no error.

    One configured provider is the default -- XETE_RPC_URL_2 is unset -- so `corroborated`
    is False and the one-source caveat fires on EVERY call. The caveat is a `.format()`
    template keyed `{endpoint}`, which the regex guard could not see by construction.
    """
    from xete_mcp import settlement

    monkeypatch.setattr(settlement, "_read_account",
                        lambda url, pda: ((False, None, None), 0))
    out = settlement.status(endpoint, "00" * 32, second_rpc="")
    _assert_clean(out, "settlement.status (account absent, one source)", endpoint)


@ENDPOINTS
def test_settle_status_never_returns_the_credential_when_the_account_is_a_stranger(
        endpoint, monkeypatch):
    """The indeterminate branches carry their own caveat copy and their own interpolations."""
    from xete_mcp import settlement

    monkeypatch.setattr(settlement, "_read_account",
                        lambda url, pda: ((True, "SomeOtherProgram1111111111111111", b"\x00" * 8), 5))
    out = settlement.status(endpoint, "00" * 32, second_rpc="")
    _assert_clean(out, "settlement.status (wrong owner)", endpoint)


def _open_escrow_bytes(commitment: bytes = b"\x07" * 32):
    """A byte-exact STATE_LEN escrow account, so `status` reaches its terminal verdicts.

    The three one-source caveat sites are reached by three DIFFERENT branches, and the
    branch that returns earliest was the only one a test had ever driven -- so two of the
    three fixes were unpinned until this existed.
    """
    import struct

    from solders.pubkey import Pubkey

    from xete_mcp.settlement import STATE_LEN

    data = bytes(Pubkey.default()) + struct.pack("<Q", 5_000_000) + commitment
    return data + b"\x00" * (STATE_LEN - len(data))


@ENDPOINTS
def test_settle_status_never_returns_the_credential_on_an_open_escrow(endpoint, monkeypatch):
    """An OPEN escrow with no commitment supplied -- the `UNVERIFIED_NOTE` verdict."""
    from xete_mcp import settlement

    monkeypatch.setattr(settlement, "program_id", lambda: _P.default())
    monkeypatch.setattr(settlement, "_read_account",
                        lambda url, pda: ((True, str(_P.default()), _open_escrow_bytes()), 9))
    out = settlement.status(endpoint, "00" * 32, second_rpc="")
    assert out["is_escrow"] is True, "the test did not reach the open-escrow branch"
    _assert_clean(out, "settlement.status (open escrow, unverified)", endpoint)


@ENDPOINTS
def test_settle_status_never_returns_the_credential_when_the_beneficiary_matches(
        endpoint, monkeypatch):
    """The BEST possible outcome -- the commitment matches -- on one endpoint.

    A leak on the good-news path is the one least likely to be noticed, because nobody
    reads a verdict that says what they hoped it would.
    """
    from xete_mcp import settlement

    commitment = b"\x07" * 32
    monkeypatch.setattr(settlement, "program_id", lambda: _P.default())
    monkeypatch.setattr(settlement, "_read_account",
                        lambda url, pda: ((True, str(_P.default()),
                                           _open_escrow_bytes(commitment)), 9))
    out = settlement.status(endpoint, "00" * 32, expect_commitment_hex=commitment.hex(),
                            second_rpc="")
    assert out["beneficiary_verified"] is True, "the test did not reach the match branch"
    _assert_clean(out, "settlement.status (beneficiary matches, one source)", endpoint)


@ENDPOINTS
def test_settle_status_never_returns_the_credential_when_two_endpoints_disagree(
        endpoint, monkeypatch):
    """Disagreement puts BOTH endpoint URLs in as dict KEYS.

    A key is not an f-string interpolation, so no amount of tightening the old regex would
    have reached it -- and both providers leak here, not one.
    """
    from xete_mcp import settlement

    other = f"https://second.example/{CANARY}/"
    calls = {}

    def _split(url, pda):
        calls[url] = True
        if url == endpoint:
            return (True, "OwnerA", b"\x01" * 8), 1
        return (False, None, None), 0

    monkeypatch.setattr(settlement, "_read_account", _split)
    out = settlement.status(endpoint, "00" * 32, second_rpc=other)
    _assert_clean(out, "settlement.status (endpoints disagree)", endpoint)
    assert CANARY not in json.dumps(out, default=str), "the SECOND endpoint's credential leaked"


@ENDPOINTS
def test_a_submit_rejection_message_never_carries_the_credential(endpoint, monkeypatch):
    """An ORDINARY rejection -- wrong salt, already claimed, not enough lamports.

    This is the highest-frequency leak of the set: it needs no attacker, no misconfiguration
    and no unusual state, only a transaction the node declines to forward. The message is
    surfaced to the agent as `str(e)` by three separate tools.
    """
    from solana.rpc.core import RPCException
    from solders.hash import Hash
    from solders.keypair import Keypair
    from solders.system_program import TransferParams, transfer

    from xete_mcp import settlement

    payer = Keypair()
    ix = transfer(TransferParams(from_pubkey=payer.pubkey(),
                                 to_pubkey=Keypair().pubkey(), lamports=1))

    class _Value:
        blockhash = Hash.default()

    class _Client:
        # The blockhash read SUCCEEDS. The rejection has to happen at `send_transaction`,
        # after the transaction is built and signed -- a pre-submit failure takes a
        # different branch with a different message, and testing that one would prove
        # nothing about this one.
        def get_latest_blockhash(self):
            return type("R", (), {"value": _Value})()

        def send_transaction(self, tx, opts=None):
            raise RPCException("simulation failed: custom program error 0x1")

    with pytest.raises(Exception) as ei:
        settlement._send(_Client(), [payer], [ix], payer, "claim", rpc_url=endpoint)
    _assert_clean(str(ei.value), "settlement._send rejection", endpoint)


@ENDPOINTS
def test_a_transport_failure_inside_txguard_never_carries_the_credential(endpoint):
    """`txguard._rpc_call` uses `requests`, not safehttp, and re-raises the library's own
    exception text -- which carries the full credentialed URL.

    It reaches the agent through the `reason` field of xete_alias_claim, which is
    DELIBERATELY not truncated (a refusal is the most useful thing that tool can say). The
    triggers are routine operations, not attacks: DNS failure, connect timeout, TLS error,
    connection reset, and a 401 on a rotated key.
    """
    from xete_mcp import txguard

    with pytest.raises(RuntimeError) as ei:
        txguard._rpc_call(endpoint, "getBalance", [], timeout=1)
    _assert_clean(str(ei.value), "txguard._rpc_call transport failure", endpoint)


@ENDPOINTS
def test_the_recipient_resolver_never_returns_the_credential_on_success(endpoint, monkeypatch):
    """A `verified: true` SUCCESS, not an error path.

    The provenance string names both endpoints so the operator can see who agreed -- which
    is the right thing to report and the wrong thing to report RAW.
    """
    from xete_mcp import server

    other = f"https://second-provider.example/?api-key={CANARY}"
    monkeypatch.setattr(server, "alias_rpc_endpoints", lambda: [endpoint, other])
    monkeypatch.setattr(server, "_resolve_recipient_wallet",
                        lambda r, rpc=None: ("So11111111111111111111111111111111111111112", None))
    _wallet, provenance, _handle = server._resolve_recipient_corroborated("%alice", "verify")
    _assert_clean(provenance, "_resolve_recipient_corroborated success provenance", endpoint)


@ENDPOINTS
def test_the_recipient_resolver_never_returns_the_credential_when_endpoints_disagree(
        endpoint, monkeypatch):
    from xete_mcp import server

    other = f"https://second-provider.example/?api-key={CANARY}"
    wallets = {endpoint: "So11111111111111111111111111111111111111112",
               other: "Nat1veM1nt1111111111111111111111111111111111"}
    monkeypatch.setattr(server, "alias_rpc_endpoints", lambda: [endpoint, other])
    monkeypatch.setattr(server, "_resolve_recipient_wallet",
                        lambda r, rpc=None: (wallets[rpc], None))
    with pytest.raises(Exception) as ei:
        server._resolve_recipient_corroborated("%alice", "spend")
    _assert_clean(str(ei.value), "_resolve_recipient_corroborated disagreement", endpoint)


@ENDPOINTS
def test_the_one_endpoint_refusal_never_carries_the_credential(endpoint, monkeypatch):
    from xete_mcp import server

    monkeypatch.setattr(server, "alias_rpc_endpoints", lambda: [endpoint])
    with pytest.raises(Exception) as ei:
        server._resolve_recipient_corroborated("%alice", "spend")
    _assert_clean(str(ei.value), "_resolve_recipient_corroborated one-endpoint refusal", endpoint)


@ENDPOINTS
def test_an_unreadable_endpoint_refusal_never_carries_the_credential(endpoint, monkeypatch):
    from xete_mcp import alias_chain, server

    other = f"https://second-provider.example/?api-key={CANARY}"

    def _boom(r, rpc=None):
        raise alias_chain.AliasChainError("connection to endpoint failed")

    monkeypatch.setattr(server, "alias_rpc_endpoints", lambda: [endpoint, other])
    monkeypatch.setattr(server, "_resolve_recipient_wallet", _boom)
    with pytest.raises(Exception) as ei:
        server._resolve_recipient_corroborated("%alice", "spend")
    _assert_clean(str(ei.value), "_resolve_recipient_corroborated unreadable endpoint", endpoint)


@ENDPOINTS
@pytest.mark.parametrize("branch", ["refused", "failed"])
def test_the_claim_tool_scrubs_an_exception_it_did_not_raise(endpoint, branch, monkeypatch):
    """The BOUNDARY, tested with an exception that was never scrubbed at its source.

    `txguard._rpc_call` now scrubs at the raise, so a test that only drove the real path
    would pass with this handler's `scrub()` removed -- and it did: this fix was the one
    mutation of ten that stayed green, i.e. decoration. That is the whole reason this test
    exists.

    So the exception here is INJECTED unscrubbed. A boundary that is only correct because
    everything upstream is also correct is not a boundary, and `reason` is the widest field
    in this tool: it is deliberately untruncated, because a refusal is the most useful
    thing the tool can say.
    """
    from xete_mcp import server
    from xete_mcp import txguard as txguard_mod

    # The shape `requests` actually produces, with the credentialed URL inside it.
    leaky = (f"getBalance: HTTPSConnectionPool(host='rpc', port=443): Max retries exceeded "
             f"with url: {endpoint} (Caused by NewConnectionError)")
    exc = (txguard_mod.TransactionRejected(leaky) if branch == "refused"
           else RuntimeError(leaky))

    def _boom(*a, **k):
        raise exc

    # Raise from the FIRST thing the tool calls inside its try, so the exception reaches
    # the two handlers under test rather than one of the early typed returns. Which call
    # carries the credential does not matter -- what is under test is whether the handler
    # sanitises text it did not author.
    monkeypatch.setattr(server, "_permit_post", _boom)
    monkeypatch.setattr(server, "_signing_rpc_url", lambda: endpoint)
    monkeypatch.setattr(txguard_mod, "treasury_for_claim", _boom)

    fn = getattr(server.xete_alias_claim, "fn", server.xete_alias_claim)
    out = fn("testname")
    assert CANARY not in out, (
        f"xete_alias_claim {branch} branch leaked the RPC credential:\n  {out[:600]}")


# ── 2. structural, with a floor ────────────────────────────────────────────────────────

# Names that hold an endpoint URL in these modules. Kept explicit rather than inferred:
# an inference that silently matches nothing is the failure this file exists to prevent,
# and the floor assertion below is what catches it if this list goes stale.
ENDPOINT_NAMES = {"rpc_url", "second", "url", "endpoint", "second_rpc",
                  "endpoints", "first_url", "second_url"}

# Calls whose RESULT is safe to emit. `endpoint_identity` normalises for identity decisions
# and drops credentials; `redact_url` and `scrub` exist for exactly this.
REDACTORS = {"redact_url", "scrub", "endpoint_identity", "sanitize_text"}


def _emission_expressions(tree):
    """Yield (node, description) for every expression whose value becomes output text.

    Keyed on NODE TYPE, never on spelling, so renaming a variable or rewriting a template
    cannot make this sweep go quiet.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    yield part.value, "f-string interpolation"
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "format":
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                yield arg, ".format() argument"
        elif isinstance(node, ast.Dict):
            for key in node.keys:
                if key is not None:
                    yield key, "dict key"


def _unprotected_endpoint_names(expr):
    """Endpoint names in `expr` whose VALUE reaches the output without a redactor.

    Two positions mention an endpoint name without emitting the URL, and both are
    excluded by walking into the emitting children only:

      * a SUBSCRIPT INDEX -- `answers[first_url]` emits the wallet that url resolved to,
        not the url. (`endpoints[0]` is the other way round: the endpoint name is the
        container being indexed, so it IS emitted, and that one stays in scope.)
      * an IFEXP TEST -- `redact_url(u) if u else '(unnamed)'` reads `u` for truthiness
        and emits the redacted branch.

    Excluding them is precision, not leniency: a sweep that cries wolf on safe positions
    gets its floor lowered or its names trimmed by the next person under time pressure,
    and that is how the guard it replaced ended up seeing nothing at all.
    """
    found = []

    def walk(node, protected):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", None)
            protected = protected or name in REDACTORS
        if isinstance(node, ast.Name) and node.id in ENDPOINT_NAMES and not protected:
            found.append(node.id)

        if isinstance(node, ast.Subscript):
            children = [node.value]                      # skip the index
        elif isinstance(node, ast.IfExp):
            children = [node.body, node.orelse]          # skip the predicate
        else:
            children = list(ast.iter_child_nodes(node))
        for child in children:
            walk(child, protected)

    walk(expr, False)
    return found


@pytest.mark.parametrize("module,floor", [("settlement.py", 6), ("server.py", 4)])
def test_no_module_emits_an_endpoint_variable_without_redacting_it(module, floor):
    """The replacement for the guard that went hollow.

    THE FLOOR IS THE POINT. `assert examined >= floor` is what makes this un-hollowable by
    the mechanism that killed its predecessor: if the sweep stops finding emission sites --
    because the names changed, because the AST shapes changed, because someone deleted the
    strings it keys on -- it FAILS rather than passing over an empty set.
    """
    tree = ast.parse((SRC / module).read_text())
    examined, bare = 0, []
    for expr, kind in _emission_expressions(tree):
        names = {n for n in ast.walk(expr)
                 if isinstance(n, ast.Name) and n.id in ENDPOINT_NAMES}
        if not names:
            continue
        examined += 1
        unprotected = _unprotected_endpoint_names(expr)
        if unprotected:
            bare.append(f"line {expr.lineno}: {kind} emits {sorted(set(unprotected))} raw")

    assert examined >= floor, (
        f"{module}: the sweep examined only {examined} endpoint emissions, below the floor of "
        f"{floor}. This is the hollow-guard signature: a check that finds nothing passes. "
        f"Either ENDPOINT_NAMES has gone stale or the emission shapes changed -- fix the "
        f"sweep, do not lower the floor.")
    assert not bare, f"{module} emits an endpoint without redaction:\n  " + "\n  ".join(bare)


def test_the_replaced_guard_is_gone_rather_than_left_passing_green():
    """The old regex guard must not survive alongside this file.

    Leaving it in place is worse than deleting it: it is a green check whose name claims
    this exact property, so the next reader sees two guards agreeing when one of them is
    incapable of disagreeing.
    """
    src = (REPO / "test_primitives_hardening.py").read_text()
    assert 'finditer(r"\\{(rpc_url|second|url)\\}"' not in src, (
        "the hollow regex guard is still in test_primitives_hardening.py. It cannot fail: "
        "the tokens it searches for were deleted by the fix it was written to verify.")
