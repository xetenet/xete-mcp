"""s1's INDEPENDENT ORACLE for the F1 endpoint-credential leak. Written by the reviewing
session without reading s2's guard, and deliberately keyed on different things.

Why it exists: the guard that certified F1 as closed searched settlement.py for the literal
`{rpc_url}`. Not one of the seven live leaks was spelled that way -- they were
`{rpc_url or '(unnamed)'}`, `_ONE_SOURCE_CAVEAT.format(endpoint=rpc_url)`, and a raw URL used as
a DICT KEY -- so it matched zero and reported green over all of them. A control that cannot
express the defect it was written for is not a weak control, it is a false report of safety.

s2 replaced that guard with an AST sweep plus a canary. This file is the SECOND opinion: it
drives status()'s return branches with parametrised account fixtures rather than by walking the
AST, so it is blind in different places than s2's guard is. Two independently-authored guards
agreeing is evidence. One guard agreeing with itself is what the old one was.

Run from the repo root:
    PYTHONDONTWRITEBYTECODE=1 python -m pytest -p no:cacheprovider test_s1_independent_oracle.py -q
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO / "src"))

# Distinct from s2's CANARYCREDENTIAL777 on purpose: a guard tuned to one literal is a guard
# that can be satisfied by that literal.
CANARY = "hl-CANARY-DO-NOT-LEAK-8xK2"
CANARY_URL = f"https://mainnet.helius-rpc.com/?api-key={CANARY}"
CANARY2 = "qn-CANARY-SECOND-9pZq"
CANARY_URL2 = f"https://weathered-y.solana-mainnet.quiknode.pro/{CANARY2}/"


def _acct(owner, data):
    """The ((exists, owner, data), lamports) shape _read_account returns."""
    if owner is None and data is None:
        return (False, None, None), None
    return (True, owner, data), 1_454_640


def _escrow_bytes(commitment_byte: int = 0xAA) -> bytes:
    from xete_mcp import settlement as S
    return (bytes(32) + (7_000_000).to_bytes(8, "little")
            + bytes([commitment_byte]) * 32 + bytes(S.STATE_LEN - 72))


# Every return branch of status(), named by the answer an agent would act on.
_BRANCHES = [
    ("absent",             None,   None,       None),
    ("wrong owner",        "SysvarC1ock11111111111111111111111111111111", bytes(81), None),
    ("wrong length",       "PROG", bytes(5),   None),
    ("escrow, no expect",  "PROG", "ESCROW",   None),
    ("escrow, verified",   "PROG", "ESCROW",   None),
    ("escrow, mismatch",   "PROG", "ESCROW",   None),
    ("endpoints disagree", "PROG", "ESCROW",   "DIFFERENT"),
]


@pytest.mark.parametrize("label,owner,data,second_shape", _BRANCHES,
                         ids=[b[0].replace(" ", "_").replace(",", "") for b in _BRANCHES])
@pytest.mark.parametrize("with_second", [False, True], ids=["one_endpoint", "two_endpoints"])
def test_no_status_branch_hands_back_the_rpc_credential(monkeypatch, label, owner, data,
                                                        second_shape, with_second):
    """Drive every answer status() can return and read the JSON, not the source.

    This is the shape the leak actually had: a `verified: true` / "ONE ENDPOINT SAYS" SUCCESS
    return carrying the operator's paid `?api-key=` in the same dictionary the agent prints.
    Nothing here asserts on wording -- only that the secret is absent AND the host survives,
    because over-redaction ("which endpoint answered" going missing) is its own defect and would
    otherwise read as a pass.
    """
    from xete_mcp import settlement as S

    prog = str(S.program_id())
    resolved_owner = prog if owner == "PROG" else owner
    resolved_data = _escrow_bytes() if data == "ESCROW" else data

    def fake_read(rpc, pda):
        if second_shape == "DIFFERENT" and rpc != CANARY_URL:
            return _acct(prog, _escrow_bytes(0xBB))
        return _acct(resolved_owner, resolved_data)

    monkeypatch.setattr(S, "_read_account", fake_read)
    expect = None
    if label == "escrow, verified":
        expect = (bytes([0xAA]) * 32).hex()
    elif label == "escrow, mismatch":
        expect = (bytes([0xCC]) * 32).hex()

    out = S.status(CANARY_URL, "ab" * 32, expect_commitment_hex=expect,
                   second_rpc=CANARY_URL2 if with_second else "")
    blob = json.dumps(out, default=str)

    assert CANARY not in blob, (
        f"[{label}] the paid RPC credential reached a settlement answer:\n{blob[:900]}")
    if with_second:
        assert CANARY2 not in blob, (
            f"[{label}] the SECOND endpoint's credential reached a settlement answer:\n{blob[:900]}")
    assert "helius-rpc.com" in blob, (
        f"[{label}] redaction removed the HOST too -- 'which endpoint answered' is the one "
        f"diagnostic this answer owes anyone:\n{blob[:400]}")


def test_submit_failure_messages_do_not_carry_the_credential():
    """The two SettlementSubmitError raise paths in _send, which the status() sweep cannot reach.

    Both interpolated `{rpc_url or '(unnamed)'}`. An operator hitting a routine simulation
    failure got their paid endpoint credential back inside the exception text, which is exactly
    the string an agent surfaces to whoever it is talking to.
    """
    from solana.rpc.core import RPCException
    from solders.hash import Hash
    from solders.keypair import Keypair
    from solders.system_program import TransferParams, transfer
    from xete_mcp import settlement as S

    payer = Keypair.from_seed(bytes([9] * 32))
    ix = transfer(TransferParams(from_pubkey=payer.pubkey(),
                                 to_pubkey=payer.pubkey(), lamports=1))

    class _Rejecting:
        def get_latest_blockhash(self):
            class R:
                value = type("V", (), {"blockhash": Hash.default(),
                                       "last_valid_block_height": 1})()
            return R()

        # `_send` calls send_transaction, NOT send_raw_transaction. Naming the wrong method
        # sends this down the generic transport branch, which never mentions the endpoint at
        # all -- so the test goes red while proving nothing. Red for the wrong reason reads
        # exactly like a working guard.
        def send_transaction(self, *a, **k):
            raise RPCException("simulation failed")

    with pytest.raises(S.SettlementSubmitError) as ei:
        S._send(_Rejecting(), [payer], [ix], payer, "deposit", rpc_url=CANARY_URL)
    msg = str(ei.value)
    assert "simulated it and refused to forward it" in msg, (
        f"this test did not reach the RPCException branch it exists to cover:\n{msg[:400]}")
    assert CANARY not in msg, (
        f"the submit-rejected message carries the RPC credential:\n{msg[:500]}")
    assert "helius-rpc.com" in msg, (
        "the submit-rejected message lost the HOST as well -- an operator cannot tell WHICH "
        "endpoint refused, which is the whole point of naming it")


def test_signature_mismatch_message_does_not_carry_the_credential():
    """The THIRD raise in _send: an endpoint that answers with someone else's signature.

    Found by mutation-testing this oracle against s2's fix -- reverting the redaction on this
    line alone left every other test green, so the branch had no behavioural coverage at all.
    It is reachable by exactly the endpoint this redaction defends against: a hostile or broken
    one, which is the case where the operator most needs the message and least wants their
    credential in it.
    """
    from solders.hash import Hash
    from solders.keypair import Keypair
    from solders.system_program import TransferParams, transfer
    from xete_mcp import settlement as S

    payer = Keypair.from_seed(bytes([9] * 32))
    ix = transfer(TransferParams(from_pubkey=payer.pubkey(),
                                 to_pubkey=payer.pubkey(), lamports=1))
    OTHER_SIG = "4" * 87  # a signature-shaped string that is not the one we signed

    class _Liar:
        def get_latest_blockhash(self):
            class R:
                value = type("V", (), {"blockhash": Hash.default(),
                                       "last_valid_block_height": 1})()
            return R()

        def send_transaction(self, *a, **k):
            return type("Resp", (), {"value": OTHER_SIG})()

    with pytest.raises(S.SettlementSubmitError) as ei:
        S._send(_Liar(), [payer], [ix], payer, "deposit", rpc_url=CANARY_URL)
    msg = str(ei.value)
    assert "SIGNATURE MISMATCH" in msg, (
        f"this test did not reach the mismatch branch it exists to cover:\n{msg[:400]}")
    assert CANARY not in msg, (
        f"the signature-mismatch message carries the RPC credential:\n{msg[:500]}")
    assert "helius-rpc.com" in msg, (
        "the signature-mismatch message lost the HOST -- naming which endpoint lied is the "
        "entire purpose of that clause")


def test_settlement_cannot_emit_an_unredacted_endpoint_in_any_spelling():
    """Static backstop, broadened to the spellings the deleted guard could not see.

    Keyed on `{rpc_url` rather than `{rpc_url}` (the leaks carried ` or '(unnamed)'` INSIDE the
    braces), on `.format(endpoint=` CALL SITES (not the template, where `{endpoint}` is inert),
    and on an endpoint variable used as a dict KEY. Kept alongside the behavioural sweep because
    a behavioural test only covers the shapes someone thought to construct.
    """
    import re
    src = (REPO / "src" / "xete_mcp" / "settlement.py").read_text(encoding="utf-8")
    patterns = [
        (r"\{(rpc_url|second|url|primary)\b", "f-string interpolation of an endpoint"),
        (r"\.format\(endpoint=", "_ONE_SOURCE_CAVEAT format call"),
        # `\s*:` also matches a PARAMETER ANNOTATION on a wrapped def line, which is not a leak.
        (r"^\s+(rpc_url|second)\s*:(?!\s*(?:str|int|bytes|bool|float|dict|list"
         r"|Pubkey|Keypair|Client))", "endpoint used as a dict KEY"),
    ]
    bare = []
    for pat, why in patterns:
        for m in re.finditer(pat, src, re.MULTILINE):
            start = src.rfind("\n", 0, m.start()) + 1
            line = src[start:src.find("\n", m.end())]
            if "redact_url" not in line:
                bare.append(f"{why}: {line.strip()[:110]}")
    assert not bare, ("settlement.py can emit an endpoint without redact_url:\n  "
                      + "\n  ".join(bare))


def test_this_oracle_can_still_fail():
    """A guard that cannot be made to go red has never been shown to work.

    The whole reason this file exists is that a green guard proved nothing. So prove THIS one
    still has teeth: feed the assertion the un-redacted string and require it to reject.
    """
    leaky = json.dumps({"endpoints_asked": [CANARY_URL], "verified": True})
    assert CANARY in leaky, "the oracle's own canary no longer appears in a deliberately leaky blob"
    over_redacted = json.dumps({"endpoints_asked": ["<redacted>"], "verified": True})
    assert "helius-rpc.com" not in over_redacted, (
        "the oracle's host assertion would pass on a fully over-redacted answer, so it is not "
        "actually checking that the host survives")
